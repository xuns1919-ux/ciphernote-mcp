#!/usr/bin/env python3
"""Encrypted local notebook store with a small JSON-over-stdio interface."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import sqlite3
import secrets
import sys
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def default_db_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return root / "ciphernote-mcp" / "ciphernote.db"


DB_PATH = Path(os.environ.get("CIPHERNOTE_DB", default_db_path()))
MAX_NOTE_BYTES = 100_000
DRAFT_TTL_SECONDS = max(60, min(86_400, int(os.environ.get("CIPHERNOTE_SECURE_CAPTURE_TTL_SECONDS", "900"))))
PRIVACY_MODE = os.environ.get("CIPHERNOTE_PRIVACY_MODE", "standard").strip().lower()
if PRIVACY_MODE not in {"standard", "private", "strict"}:
    raise ValueError("CIPHERNOTE_PRIVACY_MODE must be standard, private, or strict")
KEY_CONTEXT = b"ciphernote-mcp-content-hmac-v1\0"
CREDENTIAL_RE = re.compile(
    r"(?:api[_ -]?key|secret|password|passwd|access[_ -]?token|refresh[_ -]?token|cookie|"
    r"ssh[_ -]?key|authorization\s*:\s*bearer|-----begin [a-z ]*private key-----|"
    r"\bsk-[A-Za-z0-9_-]{12,})",
    re.IGNORECASE,
)


def decode_key(value: str) -> tuple[bytes | None, str]:
    if not value:
        return None, "invalid"
    if value.startswith("base64:"):
        encoded = value[7:]
        try:
            decoded = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError, binascii.Error):
            return None, "invalid"
        canonical = base64.b64encode(decoded).decode("ascii")
        return (decoded, "base64") if len(decoded) == 32 and canonical == encoded else (None, "invalid")
    if value.startswith("hex:"):
        encoded = value[4:]
        if re.fullmatch(r"[0-9a-fA-F]{64}", encoded) is None:
            return None, "invalid"
        decoded = bytes.fromhex(encoded)
        return decoded, "hex"
    return None, "invalid"


KEY, KEY_FORMAT = decode_key(os.environ.get("CIPHERNOTE_KEY", ""))
HMAC_KEY = hashlib.sha256(KEY_CONTEXT + KEY).digest() if KEY else None


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def field_nonce(row_nonce: bytes, field: str) -> bytes:
    return hmac.new(row_nonce, field.encode("ascii"), hashlib.sha256).digest()[:12]


def associated_data(note_id: str, field: str) -> bytes:
    return f"ciphernote:v1:{note_id}:{field}".encode()


def encrypt(note_id: str, field: str, value: str, row_nonce: bytes) -> str:
    encrypted = AESGCM(KEY).encrypt(
        field_nonce(row_nonce, field), value.encode(), associated_data(note_id, field)
    )
    return encode(encrypted)


def decrypt(note_id: str, field: str, value: str, row_nonce: bytes) -> str:
    clear = AESGCM(KEY).decrypt(
        field_nonce(row_nonce, field), decode(value), associated_data(note_id, field)
    )
    return clear.decode()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        if os.name != "nt":
            DB_PATH.parent.chmod(0o700)
    except OSError:
        pass
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA secure_delete=ON")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute(
        """CREATE TABLE IF NOT EXISTS notes (
        id TEXT PRIMARY KEY,
        encrypted_title TEXT NOT NULL,
        encrypted_content TEXT NOT NULL,
        encrypted_tags TEXT NOT NULL,
        nonce BLOB NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        importance INTEGER NOT NULL CHECK (importance BETWEEN 0 AND 5),
        content_hash TEXT NOT NULL
        )"""
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_notes_updated ON notes(updated_at DESC)")
    db.execute("""CREATE TABLE IF NOT EXISTS secure_drafts (
        id TEXT PRIMARY KEY,
        subject_hash TEXT NOT NULL,
        encrypted_title TEXT NOT NULL,
        encrypted_content TEXT NOT NULL,
        encrypted_tags TEXT NOT NULL,
        nonce BLOB NOT NULL UNIQUE,
        importance INTEGER NOT NULL CHECK (importance BETWEEN 0 AND 5),
        created_at TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_secure_drafts_expiry ON secure_drafts(expires_at)")
    db.execute("""CREATE TABLE IF NOT EXISTS draft_commits (draft_id TEXT PRIMARY KEY, note_id TEXT NOT NULL, committed_at TEXT NOT NULL)""")
    db.commit()
    try:
        if os.name != "nt":
            DB_PATH.chmod(0o600)
    except OSError:
        pass
    return db


def canonical(title: str, content: str, tags: list[str]) -> bytes:
    value = {"title": title, "content": content, "tags": tags}
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def write_note(args: dict) -> dict:
    if PRIVACY_MODE != "standard" and not args.get("_secure_capture") and os.environ.get("CIPHERNOTE_DIRECT_WRITE_ENABLED") != "true":
        return {"success": False, "reason": "direct_write_disabled_in_privacy_mode"}
    title = str(args.get("title") or "").strip()
    content = str(args.get("content") or "")
    raw_tags = args.get("tags") or []
    tags = list(dict.fromkeys(str(tag).strip() for tag in raw_tags if str(tag).strip()))
    if not title or not content:
        return {"success": False, "reason": "title_and_content_required"}
    if len(title) > 200 or len(tags) > 20 or any(len(tag) > 80 for tag in tags):
        return {"success": False, "reason": "input_too_large"}
    if len(content.encode()) > MAX_NOTE_BYTES:
        return {"success": False, "reason": "input_too_large"}
    if CREDENTIAL_RE.search("\n".join([title, content, *tags])):
        return {"success": False, "reason": "credential_storage_not_allowed"}
    try:
        importance = max(0, min(5, int(args.get("importance", 0))))
    except (TypeError, ValueError):
        return {"success": False, "reason": "invalid_importance"}
    note_id = "note_" + uuid.uuid4().hex
    row_nonce = os.urandom(32)
    timestamp = now()
    digest = hmac.new(HMAC_KEY, canonical(title, content, tags), hashlib.sha256).hexdigest()
    values = (
        note_id,
        encrypt(note_id, "title", title, row_nonce),
        encrypt(note_id, "content", content, row_nonce),
        encrypt(note_id, "tags", json.dumps(tags, ensure_ascii=False), row_nonce),
        sqlite3.Binary(row_nonce),
        timestamp,
        timestamp,
        importance,
        digest,
    )
    with closing(connect()) as db:
        db.execute("INSERT INTO notes VALUES (?,?,?,?,?,?,?,?,?)", values)
        db.commit()
    return {"success": True, "note_id": note_id}


def unpack(row: sqlite3.Row) -> dict:
    note_id = row[0]
    row_nonce = bytes(row[4])
    title = decrypt(note_id, "title", row[1], row_nonce)
    content = decrypt(note_id, "content", row[2], row_nonce)
    tags = json.loads(decrypt(note_id, "tags", row[3], row_nonce))
    digest = hmac.new(HMAC_KEY, canonical(title, content, tags), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(digest, row[8]):
        raise ValueError("integrity_check_failed")
    return {
        "note_id": note_id,
        "title": title,
        "content": content,
        "tags": tags,
        "created_at": row[5],
        "updated_at": row[6],
        "importance": row[7],
    }


def read_note(args: dict) -> dict:
    if PRIVACY_MODE != "standard" and not args.get("_secure_capture"):
        return {"success": False, "reason": "read_requires_authorization"}
    note_id = str(args.get("note_id") or "")
    with closing(connect()) as db:
        row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    return unpack(row) if row else {"success": False, "reason": "not_found"}


def recent(args: dict) -> dict:
    limit = max(1, min(20, int(args.get("limit", 5))))
    with closing(connect()) as db:
        rows = db.execute("SELECT * FROM notes ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
    if PRIVACY_MODE == "strict":
        return {"success": True, "results": [{"note_id": row[0]} for row in rows]}
    results = []
    for row in rows:
        note = unpack(row)
        if PRIVACY_MODE == "private":
            results.append({key: note[key] for key in ("note_id", "created_at", "updated_at", "importance")})
        else:
            results.append({key: note[key] for key in ("note_id", "title", "tags", "created_at", "updated_at", "importance")})
    return {"success": True, "results": results}


def search(args: dict) -> dict:
    query = str(args.get("query") or "").strip().casefold()
    limit = max(1, min(20, int(args.get("limit", 5))))
    if not query:
        return {"success": False, "reason": "query_required"}
    tokens = query.split()
    matches = []
    with closing(connect()) as db:
        rows = db.execute("SELECT * FROM notes ORDER BY updated_at DESC").fetchall()
    for row in rows:
        note = unpack(row)
        haystack = " ".join([note["title"], note["content"], *note["tags"]]).casefold()
        if not all(token in haystack for token in tokens):
            continue
        score = sum(haystack.count(token) for token in tokens)
        matches.append((score, note["updated_at"], note))
    matches.sort(key=lambda item: (item[0], item[1]), reverse=True)
    if PRIVACY_MODE == "strict":
        return {"success": True, "count": len(matches), "results": []}
    results = []
    for _, _, note in matches[:limit]:
        if PRIVACY_MODE == "private":
            results.append({"note_id": note["note_id"]})
        else:
            results.append({
                "note_id": note["note_id"],
                "title": note["title"],
                "snippet": note["content"][:300],
                "created_at": note["created_at"],
                "tags": note["tags"],
            })
    return {"success": True, "count": len(matches), "results": results}


def delete_note(args: dict) -> dict:
    if PRIVACY_MODE != "standard" and not args.get("_secure_capture"):
        return {"success": False, "reason": "delete_requires_authorization"}
    note_id = str(args.get("note_id") or "")
    with closing(connect()) as db:
        deleted = db.execute("DELETE FROM notes WHERE id = ?", (note_id,)).rowcount == 1
        db.commit()
    return {"success": deleted, "deleted": deleted, **({} if deleted else {"reason": "not_found"})}



def subject_hash(subject: str) -> str:
    return hashlib.sha256((subject or "").encode()).hexdigest()


def create_draft(args: dict) -> dict:
    subject = str(args.get("_subject") or "")
    title = str(args.get("title") or "").strip()
    content = str(args.get("content") or "")
    tags = list(dict.fromkeys(str(tag).strip() for tag in (args.get("tags") or []) if str(tag).strip()))
    if not title or not content:
        return {"success": False, "reason": "title_and_content_required"}
    if len(title) > 200 or len(tags) > 20 or any(len(tag) > 80 for tag in tags) or len(content.encode()) > MAX_NOTE_BYTES:
        return {"success": False, "reason": "input_too_large"}
    if CREDENTIAL_RE.search("\n".join([title, content, *tags])):
        return {"success": False, "reason": "credential_storage_not_allowed"}
    try:
        importance = max(0, min(5, int(args.get("importance", 0))))
    except (TypeError, ValueError):
        return {"success": False, "reason": "invalid_importance"}
    draft_id = "draft_" + secrets.token_urlsafe(32)
    nonce = os.urandom(32)
    created = now()
    expires = int(time.time()) + DRAFT_TTL_SECONDS
    with closing(connect()) as db:
        db.execute(
            "INSERT INTO secure_drafts VALUES (?,?,?,?,?,?,?,?,?)",
            (draft_id, subject_hash(subject), encrypt(draft_id, "title", title, nonce),
             encrypt(draft_id, "content", content, nonce),
             encrypt(draft_id, "tags", json.dumps(tags, ensure_ascii=False), nonce),
             sqlite3.Binary(nonce), importance, created, expires),
        )
        db.commit()
    return {"success": True, "draft_id": draft_id, "expires_in_seconds": DRAFT_TTL_SECONDS}


def commit_draft(args: dict) -> dict:
    draft_id = str(args.get("_draft_id") or args.get("draft_id") or "")
    subject = str(args.get("_subject") or "")
    if not draft_id.startswith("draft_"):
        return {"success": False, "reason": "invalid_draft_id"}
    try:
        with closing(connect()) as db:
            # Serialize consumers and keep note insertion, commit marker, and draft
            # removal in one SQLite transaction. A crash rolls back all three.
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM secure_drafts WHERE expires_at <= ?", (int(time.time()),))
            prior = db.execute("SELECT note_id FROM draft_commits WHERE draft_id=?", (draft_id,)).fetchone()
            if prior is not None:
                db.commit()
                return {"success": True, "note_id": prior[0], "idempotent": True}
            row = db.execute("SELECT * FROM secure_drafts WHERE id=?", (draft_id,)).fetchone()
            if row is None or not hmac.compare_digest(row[1], subject_hash(subject)):
                db.rollback()
                return {"success": False, "reason": "draft_not_found_or_unauthorized"}
            nonce = bytes(row[5])
            try:
                title = decrypt(draft_id, "title", row[2], nonce)
                content = decrypt(draft_id, "content", row[3], nonce)
                tags = json.loads(decrypt(draft_id, "tags", row[4], nonce))
            except Exception:
                db.rollback()
                return {"success": False, "reason": "draft_integrity_failed"}
            note_id = "note_" + uuid.uuid4().hex
            row_nonce = os.urandom(32)
            timestamp = now()
            digest = hmac.new(HMAC_KEY, canonical(title, content, tags), hashlib.sha256).hexdigest()
            db.execute("INSERT INTO notes VALUES (?,?,?,?,?,?,?,?,?)", (
                note_id,
                encrypt(note_id, "title", title, row_nonce),
                encrypt(note_id, "content", content, row_nonce),
                encrypt(note_id, "tags", json.dumps(tags, ensure_ascii=False), row_nonce),
                sqlite3.Binary(row_nonce), timestamp, timestamp, row[6], digest,
            ))
            db.execute("INSERT INTO draft_commits VALUES (?,?,?)", (draft_id, note_id, timestamp))
            db.execute("DELETE FROM secure_drafts WHERE id=?", (draft_id,))
            db.commit()
            return {"success": True, "note_id": note_id}
    except sqlite3.IntegrityError:
        with closing(connect()) as db:
            prior = db.execute("SELECT note_id FROM draft_commits WHERE draft_id=?", (draft_id,)).fetchone()
        if prior is not None:
            return {"success": True, "note_id": prior[0], "idempotent": True}
        return {"success": False, "reason": "draft_commit_conflict"}
    except Exception:
        return {"success": False, "reason": "draft_commit_failed"}
def dispatch(request: dict) -> dict:
    if KEY is None:
        return {"success": False, "reason": "disabled_invalid_or_missing_key"}
    action = request.get("action")
    args = request.get("args") or {}
    operations = {
        "write": write_note,
        "read": read_note,
        "search": search,
        "recent": recent,
        "delete": delete_note,
        "create_draft": create_draft,
        "commit_draft": commit_draft,
    }
    operation = operations.get(action)
    if operation is None:
        return {"success": False, "reason": "unknown_operation"}
    try:
        return operation(args)
    except Exception:
        return {"success": False, "reason": "notebook_operation_failed"}


def main() -> None:
    try:
        request = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        request = {}
    print(json.dumps(dispatch(request), ensure_ascii=False))


if __name__ == "__main__":
    main()

import base64
import importlib.util
import os
import secrets
import tempfile
from concurrent.futures import ThreadPoolExecutor
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_store(database: Path, mode: str):
    os.environ["CIPHERNOTE_KEY"] = "base64:" + base64.b64encode(secrets.token_bytes(32)).decode()
    os.environ["CIPHERNOTE_DB"] = str(database)
    os.environ["CIPHERNOTE_PRIVACY_MODE"] = mode
    spec = importlib.util.spec_from_file_location(f"privacy_store_{secrets.token_hex(4)}", ROOT / "src" / "store.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PrivacyStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp.cleanup()
        os.environ.pop("CIPHERNOTE_PRIVACY_MODE", None)

    def seed(self, store):
        return store.write_note({
            "title": "敏感标题",
            "content": "敏感正文 unique-privacy-marker",
            "tags": ["私人"],
            "importance": 2,
            "_secure_capture": True,
        })

    def test_private_minimizes_search_recent_and_read(self):
        store = load_store(Path(self.temp.name) / "private.db", "private")
        written = self.seed(store)
        self.assertTrue(written["success"])
        self.assertEqual(store.write_note({"title": "x", "content": "y"})["reason"], "direct_write_disabled_in_privacy_mode")
        search = store.search({"query": "unique-privacy-marker"})
        self.assertEqual(search["results"], [{"note_id": written["note_id"]}])
        self.assertNotIn("敏感正文", str(search))
        self.assertEqual(store.read_note({"note_id": written["note_id"]})["reason"], "read_requires_authorization")
        recent = store.recent({"limit": 5})
        self.assertNotIn("敏感标题", str(recent))
        self.assertNotIn("私人", str(recent))

    def test_strict_search_and_recent_are_minimal(self):
        store = load_store(Path(self.temp.name) / "strict.db", "strict")
        written = self.seed(store)
        search = store.search({"query": "unique-privacy-marker"})
        self.assertEqual(search["count"], 1)
        self.assertEqual(search["results"], [])
        self.assertEqual(store.recent({"limit": 5})["results"], [{"note_id": written["note_id"]}])

    def test_secure_draft_is_subject_bound_single_use_and_encrypted(self):
        store = load_store(Path(self.temp.name) / "draft.db", "private")
        draft = store.create_draft({"_subject": "subject-a", "title": "安全标题", "content": "安全正文", "tags": ["tag"]})
        self.assertTrue(draft["draft_id"].startswith("draft_"))
        self.assertEqual(store.commit_draft({"_subject": "subject-b", "draft_id": draft["draft_id"]})["reason"], "draft_not_found_or_unauthorized")
        committed = store.commit_draft({"_subject": "subject-a", "draft_id": draft["draft_id"]})
        self.assertTrue(committed["success"])
        cross_retry = store.commit_draft({"_subject": "subject-b", "draft_id": draft["draft_id"]})
        self.assertEqual(cross_retry["reason"], "draft_replay_not_authorized")
        retry = store.commit_draft({"_subject": "subject-a", "draft_id": draft["draft_id"]})
        self.assertTrue(retry["success"])
        self.assertEqual(retry["note_id"], committed["note_id"])
        self.assertTrue(retry.get("idempotent"))
        legacy_db = store.connect()
        try:
            legacy_db.execute("INSERT INTO draft_commits (draft_id, note_id, committed_at) VALUES (?,?,?)", ("draft_legacy", "note_hidden", "now"))
            legacy_db.commit()
        finally:
            legacy_db.close()
        legacy = store.commit_draft({"_subject": "subject-a", "draft_id": "draft_legacy"})
        self.assertEqual(legacy["reason"], "draft_replay_not_authorized")
        raw = Path(self.temp.name, "draft.db").read_bytes()
        self.assertNotIn("安全正文".encode(), raw)


    def test_concurrent_commit_is_idempotent_and_expired_draft_is_removed(self):
        store = load_store(Path(self.temp.name) / "concurrent.db", "private")
        draft = store.create_draft({"_subject": "subject-a", "title": "并发标题", "content": "并发正文", "tags": []})
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: store.commit_draft({"_subject": "subject-a", "draft_id": draft["draft_id"]}), range(8)))
        self.assertTrue(all(result["success"] for result in results))
        self.assertEqual({result["note_id"] for result in results}, {results[0]["note_id"]})
        self.assertEqual(sum(1 for result in results if result.get("idempotent")), 7)
        expired = store.create_draft({"_subject": "subject-a", "title": "过期标题", "content": "过期正文", "tags": []})
        db = store.connect()
        try:
            db.execute("UPDATE secure_drafts SET expires_at=0 WHERE id=?", (expired["draft_id"],))
            db.commit()
        finally:
            db.close()
        self.assertEqual(store.commit_draft({"_subject": "subject-a", "draft_id": expired["draft_id"]})["reason"], "draft_not_found_or_unauthorized")
if __name__ == "__main__":
    unittest.main()

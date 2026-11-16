import base64
import importlib.util
import os
import secrets
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_store(database: Path):
    key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    os.environ["CIPHERNOTE_KEY"] = "base64:" + key
    os.environ["CIPHERNOTE_DB"] = str(database)
    spec = importlib.util.spec_from_file_location("ciphernote_test_store", ROOT / "src" / "store.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = load_store(Path(self.temp.name) / "notes.db")

    def tearDown(self):
        self.temp.cleanup()

    def test_round_trip_search_and_delete(self):
        written = self.store.write_note({
            "title": "Release checklist",
            "content": "Run tests before publishing.",
            "tags": ["project", "release"],
            "importance": 3,
        })
        self.assertTrue(written["success"])
        note = self.store.read_note({"note_id": written["note_id"]})
        self.assertEqual(note["title"], "Release checklist")
        self.assertEqual(len(self.store.search({"query": "tests publishing"})["results"]), 1)
        self.assertTrue(self.store.delete_note({"note_id": written["note_id"]})["deleted"])

    def test_plaintext_is_not_in_database(self):
        marker = "unique-private-marker-83a1"
        self.store.write_note({"title": "Marker", "content": marker})
        data = self.store.DB_PATH.read_bytes()
        self.assertNotIn(marker.encode(), data)
        self.assertNotIn(b"Marker", data)

    def test_rejects_credentials(self):
        result = self.store.write_note({"title": "Login", "content": "password: example"})
        self.assertEqual(result["reason"], "credential_storage_not_allowed")

    def test_key_parser_requires_explicit_format(self):
        self.assertEqual(self.store.decode_key("A" * 32), (None, "invalid"))
        raw = secrets.token_bytes(32)
        decoded, kind = self.store.decode_key("hex:" + raw.hex())
        self.assertEqual((decoded, kind), (raw, "hex"))


if __name__ == "__main__":
    unittest.main()


import os
import tempfile
import unittest

os.environ.setdefault("LINKEDIN_CLIENT_ID", "test-client")
os.environ.setdefault("LINKEDIN_CLIENT_SECRET", "test-secret")
os.environ.setdefault("APP_API_KEY", "a" * 32)
os.environ.setdefault("SESSION_SECRET", "b" * 32)
os.environ.setdefault("DEFAULT_HASHTAGS", "#NetScout")

import app


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        app.DB_PATH = os.path.join(self.temp.name, "test.db")
        app.init_db()

    def tearDown(self):
        self.temp.cleanup()

    def test_default_hashtag_added_once(self):
        self.assertEqual(app.normalized_text("Packet time"), "Packet time\n\n#NetScout")
        self.assertEqual(app.normalized_text("Packet time #netscout"), "Packet time #netscout")

    def test_queue_post(self):
        post_id = app.queue_post("TCP retransmissions", 1234567890)
        with app.db() as conn:
            row = conn.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
        self.assertEqual(row["status"], "queued")
        self.assertIn("#NetScout", row["text"])

    def test_session_signature(self):
        token = app.signed_session()
        self.assertTrue(app.valid_session(token))
        self.assertFalse(app.valid_session(token + "x"))

    def test_rejects_oversized_post(self):
        with self.assertRaises(ValueError):
            app.normalized_text("x" * 3001)


if __name__ == "__main__":
    unittest.main()

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from central_ops import PiRunner, Store, extract_text_delta


class CentralOpsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "db.sqlite")
        self.thread = self.store.create_thread(
            title="Test",
            project_id="test",
            project_path=self.tmp.name,
            provider="commandcode",
            model="deepseek/deepseek-v4-pro",
        )
        self.fake = str(Path(__file__).with_name("fake_pi.py"))

    def tearDown(self):
        self.tmp.cleanup()

    def wait_status(self, expected, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self.store.get_thread(self.thread["id"])["status"]
            if status == expected:
                return
            time.sleep(0.05)
        self.fail(f"status did not become {expected}: {self.store.get_thread(self.thread['id'])}")

    def test_successful_turn_always_settles_and_persists_reply(self):
        runner = PiRunner(self.store, pi_command=self.fake, timeout_seconds=3)
        runner.start_turn(self.thread["id"], "yo")
        self.wait_status("idle")
        messages = self.store.list_messages(self.thread["id"])
        self.assertEqual([m["role"] for m in messages], ["user", "assistant"])
        self.assertEqual(messages[-1]["content"], "hello from pi")
        events = self.store.list_events_after(self.thread["id"], 0)
        self.assertTrue(any(e["type"] == "pi.reaped" for e in events))
        self.assertTrue(
            any(
                e["type"] == "turn.completed"
                and e["payload"]["status"] == "completed"
                for e in events
            )
        )

    def test_provider_exit_sets_error_instead_of_staying_working(self):
        old = os.environ.get("FAKE_PI_MODE")
        os.environ["FAKE_PI_MODE"] = "fail"
        try:
            runner = PiRunner(self.store, pi_command=self.fake, timeout_seconds=3)
            runner.start_turn(self.thread["id"], "fail")
            self.wait_status("error")
            thread = self.store.get_thread(self.thread["id"])
            self.assertIn("exited before agent_settled", thread["last_error"])
        finally:
            if old is None:
                os.environ.pop("FAKE_PI_MODE", None)
            else:
                os.environ["FAKE_PI_MODE"] = old

    def test_extract_text_delta_variants(self):
        self.assertEqual(extract_text_delta({"type": "text_delta", "text": "a"}), "a")
        self.assertEqual(extract_text_delta({"delta": {"text": "b"}}), "b")
        self.assertEqual(
            extract_text_delta({"content": [{"type": "text", "text": "c"}]}),
            "c",
        )


if __name__ == "__main__":
    unittest.main()

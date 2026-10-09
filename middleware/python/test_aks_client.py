"""Tests for aks_client (stdlib only).

Run from this dir on a capable host:  python3 -m unittest
"""

import json
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aks_client import AksBusyError, AksProtocolError, enter_tool, tool_call


def _reply(obj):
    return (json.dumps(obj) + "\n").encode("utf-8")


class FakeSocket:
    """Stub for socket.socket (AF_UNIX): records sends, replays one reply."""

    def __init__(self, reply_bytes):
        self._chunks = [reply_bytes]
        self.sent = b""
        self.path = None

    def connect(self, path):
        self.path = path

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        return self._chunks.pop(0) if self._chunks else b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class EnterAckTest(unittest.TestCase):
    def test_ack_parsed(self):
        fake = FakeSocket(_reply({"ok": True, "profile": "read_docs",
                                  "epoch": 42}))
        with patch("aks_client.socket.socket", return_value=fake):
            ack = enter_tool("read_docs", "c1")
        self.assertEqual(ack["profile"], "read_docs")
        self.assertEqual(ack["epoch"], 42)
        sent = json.loads(fake.sent.decode("utf-8"))
        self.assertEqual(sent, {"op": "enter_tool", "tool": "read_docs",
                               "call_id": "c1"})
        self.assertEqual(fake.path, "/run/aks/aks.sock")

    def test_busy_raises_busy_error(self):
        fake = FakeSocket(_reply({"ok": False, "error": "busy"}))
        with patch("aks_client.socket.socket", return_value=fake):
            with self.assertRaises(AksBusyError):
                enter_tool("read_docs", "c1")


class FinallyExitTest(unittest.TestCase):
    def test_exit_sent_in_finally_on_exception(self):
        fake_enter = FakeSocket(_reply({"ok": True, "profile": "read_docs",
                                        "epoch": 42}))
        fake_exit = FakeSocket(_reply({"ok": True, "profile": "baseline",
                                       "epoch": 43}))
        with patch("aks_client.socket.socket",
                   side_effect=[fake_enter, fake_exit]):
            with self.assertRaises(RuntimeError):
                with tool_call("read_docs", call_id="c1"):
                    raise RuntimeError("tool blew up")
        exit_sent = json.loads(fake_exit.sent.decode("utf-8"))
        self.assertEqual(exit_sent, {"op": "exit_tool", "call_id": "c1"})


class MalformedReplyTest(unittest.TestCase):
    def test_malformed_reply_raises_clear_error(self):
        fake = FakeSocket(b"not json\n")
        with patch("aks_client.socket.socket", return_value=fake):
            with self.assertRaises(AksProtocolError) as cm:
                enter_tool("read_docs", "c1")
        self.assertIn("malformed", str(cm.exception).lower())

    def test_ack_missing_fields_raises(self):
        fake = FakeSocket(_reply({"ok": True}))
        with patch("aks_client.socket.socket", return_value=fake):
            with self.assertRaises(AksProtocolError):
                enter_tool("read_docs", "c1")


if __name__ == "__main__":
    unittest.main()

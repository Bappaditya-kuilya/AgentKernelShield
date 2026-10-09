"""AKS MCP tool-switch client (SPEC Sec 8.1, 9.2; FR-13).

Wraps MCP tool calls with daemon profile switches over a Unix
socket (JSON-lines). Stdlib only (`socket` + `json`). Python 3.11+.
"""

import contextlib
import json
import socket
import uuid

DEFAULT_SOCKET_PATH = "/run/aks/aks.sock"


class AksError(Exception):
    """Base error: transport failure or negative daemon ack."""


class AksBusyError(AksError):
    """Daemon reported overlapping enter_tool ("busy")."""


class AksProtocolError(AksError):
    """Malformed or unexpected daemon reply."""


def _exchange(payload: dict, socket_path: str = DEFAULT_SOCKET_PATH) -> dict:
    raw = (json.dumps(payload) + "\n").encode("utf-8")
    buf = b""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(socket_path)
        s.sendall(raw)
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    try:
        reply = json.loads(buf.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise AksProtocolError(f"malformed daemon reply: {buf!r}") from e
    if not isinstance(reply, dict) or "ok" not in reply:
        raise AksProtocolError(f"malformed daemon reply: {buf!r}")
    if not reply["ok"]:
        err = reply.get("error", "unknown")
        if err == "busy":
            raise AksBusyError("busy: overlapping enter_tool")
        raise AksError(str(err))
    return reply


def enter_tool(tool: str, call_id: str,
               socket_path: str = DEFAULT_SOCKET_PATH) -> dict:
    """Request a profile switch. Returns ack dict with profile + epoch."""
    reply = _exchange({"op": "enter_tool", "tool": tool,
                       "call_id": call_id}, socket_path)
    if "profile" not in reply or "epoch" not in reply:
        raise AksProtocolError(f"ack missing profile/epoch: {reply!r}")
    return reply


def exit_tool(call_id: str, socket_path: str = DEFAULT_SOCKET_PATH) -> dict:
    """Revert to baseline. Returns ack dict."""
    return _exchange({"op": "exit_tool", "call_id": call_id}, socket_path)


@contextlib.contextmanager
def tool_call(tool: str, call_id: str | None = None,
              socket_path: str = DEFAULT_SOCKET_PATH):
    """Wrap one tool call: enter, yield ack, ALWAYS exit in `finally`.

    Usable as `with tool_call("read_docs"):` or as `@tool_call("t")`
    decorator (contextmanager doubles as ContextDecorator). On connection
    loss the daemon reverts to baseline server-side (FR-7); the error
    here just propagates to the caller.
    """
    cid = call_id or uuid.uuid4().hex
    ack = enter_tool(tool, cid, socket_path)
    try:
        yield ack
    finally:
        exit_tool(cid, socket_path)

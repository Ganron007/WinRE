from __future__ import annotations

from winre import debug_loops


class FakeX64Dbg:
    def __init__(self):
        self.debugging = True
        self.running = False
        self.run_calls = 0
        self.stop_calls = 0

    def get_state(self):
        status = "LOCKED" if self.debugging else "NO_TARGET"
        text = (f"isDebugging: {str(self.debugging).lower()}\n"
                f"isRunning: {str(self.running).lower()}\n"
                f"status: {status}\n"
                "currentAddress: 0x401000\n"
                "currentModule: sample.exe\n"
                "pid: 1234")
        return {"ok": True, "result": {"content": [{"text": text}]}}

    def call(self, name, arguments=None):
        assert name == "DeleteAllBreakpoints"
        return {"ok": True, "result": {}}

    def run(self):
        self.run_calls += 1
        self.running = True
        return {"ok": True}

    def stop_debug(self):
        self.stop_calls += 1
        self.running = False
        self.debugging = False
        return {"ok": True}


def test_bounded_debug_window_stops_target_before_observer_closes(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(debug_loops.time, "monotonic", lambda: now[0])

    def fake_sleep(seconds):
        now[0] += seconds

    monkeypatch.setattr(debug_loops.time, "sleep", fake_sleep)
    client = FakeX64Dbg()

    result = debug_loops.run_debug_window(
        client, seconds=2, poll_s=1)

    assert result["ok"] is True
    assert result["requested_seconds"] == 2
    assert result["observed_seconds"] == 2
    assert result["stopped_after_window"] is True
    assert result["final_state"]["status"] == "NO_TARGET"
    assert client.run_calls == 1
    assert client.stop_calls == 1


def test_bounded_debug_window_requires_a_loaded_target(monkeypatch):
    client = FakeX64Dbg()
    client.debugging = False
    result = debug_loops.run_debug_window(client)
    assert result["ok"] is False
    assert result["reason_code"] == "no_debug_target"
    assert client.run_calls == 0
    assert client.stop_calls == 0

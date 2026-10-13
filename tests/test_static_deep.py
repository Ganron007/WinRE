from __future__ import annotations

from pathlib import Path

from winre import agentic, static_deep


def test_checklist_purpose_is_not_forwarded_as_tool_argument(
        monkeypatch, tmp_path: Path) -> None:
    calls: list[tuple[str, dict]] = []

    class FakeRegistry:
        def __init__(self, *args, **kwargs) -> None:
            self.remote_sample = "C:/samples/sample.exe"

        def call(self, tool: str, args: dict) -> dict:
            calls.append((tool, dict(args)))
            if tool == "ghidra_query":
                sql = args["sql"]
                rows = ([{"name": "entry", "address": "0x401000",
                          "size": 32}]
                        if "FROM funcs" in sql else
                        [{"content": "sample marker", "address": "0x402000"}])
                return {"ok": True, "status": "completed", "rows": rows}
            if tool == "pe_parse":
                return {"ok": True, "status": "completed", "imports": [],
                        "is_dotnet": False}
            if tool == "floss":
                return {"ok": True, "status": "completed",
                        "decoded_strings": []}
            return {"ok": True, "status": "completed"}

    monkeypatch.setattr(agentic, "ToolRegistry", FakeRegistry)
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\0" * 32)

    result = static_deep.run_static_deep_dive(
        sample.name, "a" * 64, mode="remote", sample_path=sample)

    ghidra_calls = [args for tool, args in calls if tool == "ghidra_query"]
    assert len(ghidra_calls) == 2
    assert all("_purpose" not in args for args in ghidra_calls)
    ghidra_history = [event for event in result["history"]
                      if event["tool"] == "ghidra_query"]
    assert [event["purpose"] for event in ghidra_history] == ["functions", "strings"]
    assert all(event["status"] == "completed" for event in ghidra_history)
    assert result["tool_failures"] == []

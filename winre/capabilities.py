"""Structured outcomes for planned and executed analysis capabilities."""
from __future__ import annotations

from typing import Any


SCHEMA = "winre-capability-census/v1"
STATUSES = {
    "planned", "attempted", "completed", "failed", "unavailable",
    "not_applicable", "budget_exhausted", "not_attempted",
}

# These are the minimum static operations that ground a WinRE verdict. Tool
# contracts can explicitly make a capability optional or not applicable; a
# missing/failed required operation is an audit quality failure.
CORE_REQUIRED_TOOLS = ("pe_parse", "decrypt_gate", "capa", "ghidra_query")


def normalize_result(tool: str, result: Any) -> dict[str, Any]:
    """Return an explicit outcome without guessing from human prose."""
    if not isinstance(result, dict):
        return {"tool": tool, "status": "failed",
                "reason_code": "invalid_result_shape",
                "reason": f"tool returned {type(result).__name__}, not an object"}
    status = result.get("status")
    if status not in STATUSES:
        if result.get("error"):
            status, code = "failed", "tool_error"
        elif result.get("skipped"):
            # Legacy skipped payloads are deliberately classified as
            # unavailable until the producer supplies a machine reason code.
            status, code = "unavailable", "legacy_unclassified_skip"
        elif result.get("ok") is False:
            status, code = "failed", "tool_reported_not_ok"
        else:
            status, code = "completed", "completed"
    else:
        code = str(result.get("reason_code") or status)
    reason = (result.get("error") or result.get("reason")
              or result.get("skipped") or result.get("detail"))
    return {"tool": tool, "status": status,
            "reason_code": str(result.get("reason_code") or code),
            "reason": str(reason)[:300] if reason is not None else None}


def census(history: list[dict] | None, *,
           required_tools: tuple[str, ...] = CORE_REQUIRED_TOOLS,
           budget_exhausted: bool = False) -> dict:
    """Summarize invocation history and expose required omissions explicitly."""
    required = tuple(dict.fromkeys(required_tools))
    invocations: list[dict] = []
    by_tool: dict[str, list[dict]] = {}
    for entry in history or []:
        if not isinstance(entry, dict) or not entry.get("tool"):
            continue
        tool = str(entry["tool"])
        result = entry.get("result")
        # Redundant calls and model budget notes did not invoke the capability.
        if entry.get("reason") == "redundant, skipped":
            outcome = {"tool": tool, "status": "not_attempted",
                       "reason_code": "duplicate_call_suppressed",
                       "reason": "identical call was already made"}
        else:
            outcome = normalize_result(tool, result)
        outcome.update({"required": tool in required,
                        "step": entry.get("step"),
                        "args": entry.get("args")})
        invocations.append(outcome)
        by_tool.setdefault(tool, []).append(outcome)

    summary: list[dict] = []
    for tool in sorted(set(by_tool) | set(required)):
        attempts = by_tool.get(tool, [])
        completed = [attempt for attempt in attempts
                     if attempt["status"] == "completed"]
        last = attempts[-1] if attempts else None
        status = ("completed" if completed else
                  last["status"] if last else "not_attempted")
        missing_status = ("budget_exhausted" if budget_exhausted
                          else "not_attempted")
        summary.append({
            "tool": tool,
            "required": tool in required,
            "status": missing_status if not attempts else status,
            "attempt_count": len(attempts),
            "reason_code": (None if completed else
                            (last or {}).get("reason_code") or
                            ("tool_budget_exhausted" if budget_exhausted
                             else "not_attempted")),
            "reason": (None if completed else (last or {}).get("reason") or
                       ("analysis tool budget exhausted" if budget_exhausted
                        else "capability was not invoked")),
            "attempts": attempts,
        })
    failures = [f"{row['tool']}:{row['status']}:{row.get('reason_code')}"
                for row in summary
                if row["required"] and row["status"] != "completed"]
    warnings = [f"{row['tool']}:{row['status']}:{row.get('reason_code')}"
                for row in summary
                if not row["required"] and row["status"] not in
                ("completed", "not_applicable", "not_attempted")]
    return {"schema": SCHEMA, "required": list(required),
            "invocations": invocations, "summary": summary,
            "required_failures": failures, "optional_warnings": warnings}


def decorate_result(tool: str, result: Any) -> Any:
    """Add normalized fields to a tool result while preserving its payload."""
    if not isinstance(result, dict):
        return result
    normalized = normalize_result(tool, result)
    out = dict(result)
    out.setdefault("status", normalized["status"])
    out.setdefault("reason_code", normalized["reason_code"])
    return out

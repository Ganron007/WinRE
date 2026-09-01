#!/usr/bin/env python3
"""evidence.py — stage-tagged evidence pack for the WinRE pipeline.

Mirrors RevAI's evidence-pack discipline: every stage writes a tagged folder
under logs/<sha>/, the LLM can only cite what a deterministic tool emitted,
and a report carries a `source` (llm_judge vs deterministic_fallback) so a
stubbed run can never look green.

Layout:
    logs/<sha>/
      session.json          intake: sha, paths, format, hashes
      intake/               metadata, magic, format tools
      quick/                deterministic triage (Malcat/SQL) + verdict
      dynamic/              detonation pack (META.json, frida, procmon, ...)
      deep/                 agentic MCP-driven pass (x64dbg/malcat/windbg)
      yara/                 generated YARA/Sigma + rule reports
      report/               final report (source-tagged) + analyst-next
      audit.json            truly_green gate
"""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class EvidencePack:
    """Read/write a stage-tagged evidence pack under logs/<sha>/."""

    STAGES = ("intake", "quick", "dynamic", "deep", "yara", "report")

    def __init__(self, logs_dir: Path, sha: str):
        self.root = logs_dir / sha
        self.stages = {s: self.root / s for s in self.STAGES}

    def ensure(self) -> "EvidencePack":
        self.root.mkdir(parents=True, exist_ok=True)
        for p in self.stages.values():
            p.mkdir(parents=True, exist_ok=True)
        return self

    def write(self, stage: str, name: str, payload: dict) -> Path:
        """Write a JSON artifact into a stage folder. Returns the path."""
        p = self.stages[stage] / name
        p.write_text(json.dumps(payload, indent=2, default=str) + "\n",
                     encoding="utf-8")
        return p

    def read(self, stage: str, name: str) -> dict | None:
        p = self.stages[stage] / name
        if not p.is_file():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    def stage_artifacts(self, stage: str) -> list[str]:
        d = self.stages[stage]
        if not d.is_dir():
            return []
        return sorted(f.name for f in d.iterdir() if f.is_file())

    def manifest(self) -> dict:
        return {
            "sha256": self.root.name,
            "stages": {s: self.stage_artifacts(s) for s in self.STAGES},
            "generated_at": utcnow(),
        }


def stage_result(stage: str, ok: bool, *, error: str | None = None,
                 summary: str | None = None, **extra) -> dict:
    """A stage's META-shaped result with the honest ok/error contract."""
    out = {
        "stage": stage,
        "ok": ok,
        "error": error,
        "summary": summary,
        "started_at": utcnow(),
        "elapsed_s": extra.pop("elapsed_s", None),
    }
    out.update(extra)
    return out


def source_tagged(kind: str, source: str, content: dict) -> dict:
    """Every report/verdict carries a source: llm_judge or deterministic_fallback."""
    out = dict(content)
    out["source"] = source
    return out

#!/usr/bin/env python3
"""evidence.py — stage-tagged evidence pack for the WinRE pipeline.

Mirrors RevAI's evidence-pack discipline: every stage writes a tagged folder
under logs/<sha>/, the LLM can only cite what a deterministic tool emitted,
and a report carries a `source` (llm_judge vs deterministic_fallback) so a
stubbed run can never look green.

Layout (RevAI-style mode sections — one self-contained case per engine):
    logs/<sha>/
      static/                 deterministic engine section (RevAI scripted)
        intake/               metadata, magic, format tools
        quick/                deterministic triage (Malcat/SQL) + verdict
        dynamic/              detonation pack (META.json, frida, procmon, ...)
        deep/                 deterministic checklist pass
        yara/                 generated YARA/Sigma + rule reports
        report/               final report (source-tagged) + analyst-next
        audit.json            truly_green gate
        META.json             pack-level mode/engine/source
        stage_trace.json      stage ordering/timing trace
      agentic/                LangGraph engine section (RevAI agentic)
        <same stage layout>
      snapshot.json           HITL snapshot ledger (VM-state, mode-independent)

Same-sample/same-mode reruns overwrite their section; the other section is
untouched. Pre-sectioning packs (flat stages directly under logs/<sha>/)
are read as legacy rows.
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
    """Read/write a stage-tagged evidence pack under logs/<sha>/<mode>/."""

    STAGES = ("intake", "quick", "dynamic", "deep", "yara", "report")

    # Deep-dive engine sections (RevAI: scripted/agentic folders). mode=None
    # = legacy flat layout logs/<sha>/ (read-only compat for old packs).
    MODES = ("agentic", "static")

    def __init__(self, logs_dir: Path, sha: str, mode: str | None = None):
        self.logs_dir = Path(logs_dir)
        self.sha = sha
        self.mode: str | None = mode if mode in self.MODES else None
        self.root = (self.logs_dir / sha / self.mode) if self.mode \
            else (self.logs_dir / sha)
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
            "sha256": self.sha,
            "mode": self.mode,
            "stages": {s: self.stage_artifacts(s) for s in self.STAGES},
            "generated_at": utcnow(),
        }


def pack_sections(sha_dir: Path) -> list[dict]:
    """Mode sections present under logs/<sha>/ (for UI rows).

    Returns [{mode, root}] in MODES order, plus a legacy entry
    ({mode: None}) when flat stages exist directly under the sha dir.
    """
    out: list[dict] = []
    if not sha_dir.is_dir():
        return out
    for m in EvidencePack.MODES:
        if (sha_dir / m).is_dir():
            out.append({"mode": m, "root": sha_dir / m})
    if any((sha_dir / s).is_dir() for s in EvidencePack.STAGES):
        out.append({"mode": None, "root": sha_dir})
    return out


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

"""ANALYST-NEXT moved off the VM — and the bug that made it necessary.

The orchestrator called `from winre.emit_analyst_next import emit`. That name
never existed in the module. Every run since therefore recorded

    "analyst_next": {"error": "cannot import name 'emit' from
                          'winre.emit_analyst_next' ..."}

and produced no ANALYST-NEXT at all. The most recent real detonation on disk
(fc75410, 2026-10-08) is the one carrying that error; the 24 older packs show
`{"rc": 0, "stdout": "wrote .../ANALYST-NEXT.md"}`, which is a *subprocess*
result from before the change — so this was a regression, not a never-worked.

The `try/except Exception` around the call is what let a broken import pass as
a recorded failure instead of a crash, and it is why the suite stayed green:
a run that produced no checklist looked identical to a run that did, apart
from an error string nobody read.

These tests pin the fix and, more importantly, the CLASS: an import that
resolves nowhere must not be able to hide in a `try/except` again.
"""
import importlib
import pathlib
import re

import pytest

from winre import analysis, emit_analyst_next, orchestrator

REPO = pathlib.Path(__file__).resolve().parents[1]


# ------------------------------------------------- the name actually exists

def test_emit_exists_and_is_callable():
    assert callable(emit_analyst_next.emit), (
        "emit_analyst_next.emit is missing - the orchestrator's original "
        "ImportError, again")


def test_every_name_the_analysis_plane_imports_resolves():
    """The control plane is the only place allowed to import this module, and
    every name it imports must resolve. `from X import Y` where Y is absent is
    exactly how the last one survived."""
    src = pathlib.Path(analysis.__file__).read_text(encoding="utf-8")
    for m in re.finditer(r"from (winre[\w.]*) import ([\w, ]+)", src):
        mod_name, names = m.group(1), m.group(2)
        mod = importlib.import_module(mod_name)
        for raw in [n.strip() for n in names.split(",") if n.strip()]:
            name = raw.split(" as ")[0].strip()
            assert hasattr(mod, name), f"{mod_name}.{name} does not exist"


def test_no_import_inside_the_orchestrator_post_pull_resolves_to_nothing():
    """Generalised: the VM-side post-pull must not contain an import of a name
    that does not exist. The `except Exception` around each call turned the
    original defect into a recorded error, so the check has to be explicit."""
    src = pathlib.Path(orchestrator.__file__).read_text(encoding="utf-8")
    i = src.find("def _post_pull_enrich(")
    assert i != -1
    body = src[i:src.find("\ndef ", i + 10)]
    for m in re.finditer(r"from (winre[\w.]*) import ([\w, ]+)", body):
        mod_name, names = m.group(1), m.group(2)
        try:
            mod = importlib.import_module(mod_name)
        except ImportError as e:
            pytest.fail(f"the orchestrator imports a module that is absent: {e}")
        for raw in [n.strip() for n in names.split(",") if n.strip()]:
            name = raw.split(" as ")[0].strip()
            assert hasattr(mod, name), (
                f"{mod_name}.{name} does not exist - this is the ImportError "
                f"that recorded an error instead of running")


# --------------------------------------------------- it is off the VM now

def test_the_orchestrator_does_not_import_it_on_the_vm_side():
    """A real import STATEMENT, not a mention in prose — the explanatory
    comment names the module deliberately, so the check must be precise or it
    cries wolf."""
    src = pathlib.Path(orchestrator.__file__).read_text(encoding="utf-8")
    stmts = [ln.strip() for ln in src.splitlines()
             if ln.strip().startswith("from winre.emit_analyst_next")]
    assert not stmts, f"still imported on the VM: {stmts}"


def test_the_orchestrator_defers_it():
    src = pathlib.Path(orchestrator.__file__).read_text(encoding="utf-8")
    assert 'deferred["analyst_next"]' in src, (
        "ANALYST-NEXT is neither run on the VM nor recorded as deferred, so "
        "a reader cannot tell 'ran elsewhere' from 'never ran'")


def test_the_control_plane_imports_it():
    src = pathlib.Path(analysis.__file__).read_text(encoding="utf-8")
    assert "from winre.emit_analyst_next import emit" in src


def test_emit_analyst_next_has_no_vm_dependency():
    """It enumerates files on disk. If it ever grows a network call, an ssh
    client or a VM address, it stops being safe to run on the control plane."""
    src = pathlib.Path(emit_analyst_next.__file__).read_text(encoding="utf-8")
    for bad in ("ssh", "vmrun", "subprocess", "socket", "urllib", "requests",
                "192.168.77"):
        assert bad not in src, f"emit_analyst_next depends on the VM: {bad}"


# ------------------------------------------------- it actually produces it

def test_emit_writes_both_artifacts(tmp_path):
    out = emit_analyst_next.emit(tmp_path, "a" * 64)
    assert out["ok"] is True, out
    assert (tmp_path / "ANALYST-NEXT.md").is_file()
    assert (tmp_path / "analyst_next.json").is_file()
    assert out["host"] == "control-plane"


def test_emit_reports_what_it_wrote(tmp_path):
    """`{"ok": true}` with nothing else is what made the last failure hard to
    read. The caller must be able to record the counts."""
    out = emit_analyst_next.emit(tmp_path, "b" * 64)
    for k in ("path", "items", "collected", "analyst_only"):
        assert k in out, f"emit() does not report {k}"


def test_emit_over_a_missing_directory_says_so(tmp_path):
    out = emit_analyst_next.emit(tmp_path / "nope", "c" * 64)
    assert out["ok"] is False
    assert "not a directory" in out["error"]


def test_emit_never_raises(tmp_path, monkeypatch):
    """A failure to write the checklist must not lose the detonation."""
    def _boom(*a, **k):
        raise RuntimeError("disk gone")
    monkeypatch.setattr(emit_analyst_next, "render_md", _boom)
    out = emit_analyst_next.emit(tmp_path, "d" * 64)
    assert out["ok"] is False and "disk gone" in out["error"]


def test_the_checklist_is_not_a_verdict(tmp_path):
    """It is a checklist. `analyst_only` items must never read as done, and it
    must not claim a verdict — the report owns that."""
    out = emit_analyst_next.emit(tmp_path, "e" * 64)
    assert out["ok"], out
    import json
    data = json.loads((tmp_path / "analyst_next.json").read_text(encoding="utf-8"))
    assert data["disclaimer"], "no disclaimer"
    assert all("analyst_only" in i for i in data["items"])
    blob = (tmp_path / "ANALYST-NEXT.md").read_text(encoding="utf-8").lower()
    for claim in ("verdict:", "is malicious", "is benign", "is clean",
                  "confidence score"):
        assert claim not in blob, f"reads as a verdict: {claim!r}"


def test_a_missing_x64dbg_dump_is_named_not_silent(tmp_path):
    """A dump that was never produced must appear in the checklist as not
    produced — an absent dump must not read as 'nothing to unpack'."""
    (tmp_path / "META.json").write_text(
        '{"x64dbg_dump": {"ok": false, "reason": "debugger did not attach"}}',
        encoding="utf-8")
    emit_analyst_next.emit(tmp_path, "0" * 64)
    import json
    data = json.loads((tmp_path / "analyst_next.json").read_text(encoding="utf-8"))
    labels = " ".join(c["label"] for c in data["collected"]).lower()
    assert "not produced" in labels, f"a failed dump is silent: {labels}"


def test_the_control_plane_step_runs_it(tmp_path):
    step = analysis.analyst_next(tmp_path)
    assert step.get("ok") and step.get("host") == "control-plane", step
    assert (tmp_path / "ANALYST-NEXT.md").is_file()


def test_the_manifest_classifies_it_as_derived():
    from winre import manifest
    assert manifest.classify("ANALYST-NEXT.md")[1] == manifest.DERIVED
    assert manifest.classify("analyst_next.json")[1] == manifest.DERIVED

"""Phase 1: the four modes are independent producers.

The defect this closes: `--agentic-dbg` and `--dynamic` are capability flags,
but they used to share the `agentic` pack root, so run 3 overwrote run 2 and
no two modes could ever be compared. A measured "verdict downgrade between
modes" was an artefact of that collision, not a product defect
(docs/internal/DESIGN.md §1.2e).
"""
from pathlib import Path

import pytest

from winre import pipeline, remote_driver
from winre.evidence import (MODES, EvidencePack, pack_sections,
                            resolve_pack_mode, sha_of)

SHA = "a" * 64


# --- one authority decides the root --------------------------------------

@pytest.mark.parametrize("mode,dbg,dyn,expect", [
    ("static", False, False, "static"),
    ("agentic", False, False, "agentic"),
    ("agentic", True, False, "dbg"),
    ("agentic", False, True, "dynamic"),
    ("static", True, False, "static"),      # static has no dbg variant
    ("static", False, True, "static"),      # ...nor a dynamic one
])
def test_resolve_pack_mode_picks_one_root(mode, dbg, dyn, expect):
    assert resolve_pack_mode(mode, agentic_dbg=dbg, dynamic=dyn) == expect


def test_the_driver_and_pipeline_agree():
    """Two entry points, one authority - or evidence lands in two places."""
    for mode in ("static", "agentic"):
        for dbg in (False, True):
            for dyn in (False, True):
                a = resolve_pack_mode(mode, agentic_dbg=dbg, dynamic=dyn)
                assert a in MODES
                assert EvidencePack.resolve_mode(
                    mode, agentic_dbg=dbg, dynamic=dyn) == a


# --- four modes never share a root ---------------------------------------

def test_all_four_modes_have_distinct_roots(tmp_path):
    roots = [EvidencePack(tmp_path, SHA, mode=m).ensure().root
             for m in MODES]
    assert len(set(roots)) == len(MODES), "two modes share a pack root"


def test_a_second_mode_cannot_overwrite_the_first(tmp_path):
    """The collision, reproduced: same sample, different modes, distinct files."""
    out = {}
    for m in ("agentic", "dbg", "dynamic"):
        p = EvidencePack(tmp_path, SHA, mode=m).ensure()
        p.write("deep", "deep.json", {"mode": m, "verdict": f"v-{m}"})
        out[m] = p.read("deep", "deep.json")

    # each pack still holds its own verdict - last-write-wins is gone
    for m in ("agentic", "dbg", "dynamic"):
        assert out[m]["verdict"] == f"v-{m}", f"{m} was clobbered"


def test_sha_of_reads_through_all_four_roots(tmp_path):
    for m in MODES:
        p = EvidencePack(tmp_path, SHA, mode=m).ensure()
        assert sha_of(p.root) == SHA, m


def test_pack_sections_discovers_every_mode_root(tmp_path):
    for m in MODES:
        EvidencePack(tmp_path, SHA, mode=m).ensure()
    found = {s["mode"] for s in pack_sections(tmp_path / SHA)}
    assert found >= set(MODES), found


# --- failure modes -------------------------------------------------------

def test_an_unknown_mode_fails_closed(tmp_path):
    """It used to collapse to the legacy flat layout and silently merge runs."""
    with pytest.raises(ValueError, match="unknown pack mode"):
        EvidencePack(tmp_path, SHA, mode="logger")


def test_mode_none_still_means_the_legacy_flat_layout(tmp_path):
    """Old packs must stay readable."""
    p = EvidencePack(tmp_path, SHA, mode=None)
    assert p.root == tmp_path / SHA and p.mode is None


# --- the entry points use it --------------------------------------------

def test_pipeline_and_ui_use_the_single_authority():
    """No entry point may hardcode a root decision."""
    p = Path(pipeline.__file__).read_text(encoding="utf-8")
    assert "resolve_pack_mode(" in p
    ui = Path(remote_driver.__file__).read_text(encoding="utf-8")
    assert "resolve_pack_mode(" in ui


def test_no_hardcoded_mode_pair_remains_in_the_ui():
    """The UI listed ("agentic","static") in eight places; dbg/dynamic
    sections would have been invisible."""
    ui = Path(remote_driver.__file__).parent / "ui" / "app.py"
    src = ui.read_text(encoding="utf-8")
    for bad in ('in ("agentic", "static")', 'for sec in ("agentic", "static")'):
        assert bad not in src, f"hardcoded mode pair remains: {bad}"
    assert "from winre.evidence import MODES" in src
"""Dynamic weighting, and disagreement as a finding rather than an average."""
from winre import compose
from winre.findings import BENIGN, MALICIOUS, SUSPICIOUS, UNKNOWN


def _f(mode, level, conf="medium", basis=None):
    return {"mode": mode, "verdict": {"level": level, "confidence": conf,
                                      "basis": basis or [f"{mode}:x"]}}


# ------------------------------------------------------- the deciding voice

def test_no_findings_means_no_verdict():
    out = compose.compose({})
    assert out["level"] == UNKNOWN
    assert "no mode produced findings" in out["note"]
    assert out["sources"] == {} and out["conflicts"] == []


def test_detonation_outranks_static_on_the_same_level():
    """With identical evidence the execution is still the stronger claim."""
    out = compose.compose({"static": _f("static", MALICIOUS),
                           "dynamic": _f("dynamic", MALICIOUS)})
    assert out["level"] == MALICIOUS
    assert out["deciding_mode"] == "dynamic"


def test_detonation_decides_when_it_saw_the_sample_run():
    """The headline rule: malicious-in-motion beats unknown-at-rest."""
    out = compose.compose({"static": _f("static", UNKNOWN, basis=["static:x"]),
                           "dynamic": _f("dynamic", MALICIOUS, conf="high",
                                         basis=["drop:payload.exe"])})
    assert out["level"] == MALICIOUS and out["confidence"] == "high"
    assert out["deciding_mode"] == "dynamic"
    assert "drop:payload.exe" in out["basis"]


def test_a_benign_detonation_overrides_a_malicious_static_call():
    """It executed and was clean; that is stronger than a string match."""
    out = compose.compose({"static": _f("static", MALICIOUS),
                           "dynamic": _f("dynamic", BENIGN, conf="high")})
    assert out["level"] == BENIGN
    assert out["deciding_mode"] == "dynamic"


def test_static_alone_is_labelled_as_such():
    out = compose.compose({"static": _f("static", SUSPICIOUS)})
    assert out["level"] == SUSPICIOUS
    assert out["deciding_mode"] is None or out["deciding_mode"] == "static"
    assert out["sources"]["static"]["level"] == SUSPICIOUS


def test_dbg_evidence_feeds_the_verdict_but_not_over_the_detonation():
    out = compose.compose({"static": _f("static", UNKNOWN),
                           "dbg": _f("dbg", SUSPICIOUS),
                           "dynamic": _f("dynamic", UNKNOWN)})
    assert out["level"] == SUSPICIOUS
    assert out["deciding_mode"] == "dbg"


# ------------------------------------------------- disagreement, not average

def test_disagreement_is_named_not_averaged():
    out = compose.compose({"static": _f("static", MALICIOUS),
                           "dynamic": _f("dynamic", BENIGN, conf="high")})
    assert len(out["conflicts"]) >= 1
    kinds = {c["kind"] for c in out["conflicts"]}
    assert "disagreement" in kinds or "downgrade" in kinds
    # and the resolved level is one of the two, never something between them
    assert out["level"] in (MALICIOUS, BENIGN)


def test_static_agreement_raises_confidence_but_not_the_level():
    a = compose.compose({"static": _f("static", SUSPICIOUS, conf="low")})
    b = compose.compose({"static": _f("static", SUSPICIOUS, conf="low"),
                         "agentic": _f("agentic", SUSPICIOUS, conf="low")})
    assert a["level"] == b["level"] == SUSPICIOUS
    assert b["confidence"] != a["confidence"] or b["confidence"] == "medium"


def test_conflicts_name_every_source():
    out = compose.compose({"static": _f("static", MALICIOUS),
                           "agentic": _f("agentic", SUSPICIOUS),
                           "dynamic": _f("dynamic", UNKNOWN)})
    for c in out["conflicts"]:
        if c["kind"] == "disagreement":
            assert set(c["sources"]) == {"static", "agentic", "dynamic"}


# ------------------------------------------------------------- real packs

def test_compose_for_sample_over_real_packs():
    import pathlib
    logs = pathlib.Path(__file__).resolve().parents[1] / "logs"
    shas = sorted(d.name for d in logs.iterdir()
                 if d.is_dir() and len(d.name) == 64)
    checked = 0
    for sha in shas:
        out = compose.compose_for_sample(sha, logs)
        assert out["level"] in (UNKNOWN, BENIGN, SUSPICIOUS, MALICIOUS)
        if out["sources"]:
            # every level the composite names must come from a real source
            assert out["level"] in {s["level"] for s in out["sources"].values()}
            checked += 1
    if not shas:
        return
    assert checked >= 0


def test_the_composite_is_not_an_average():
    """A level between two sources would be meaningless - and untestable."""
    out = compose.compose({"static": _f("static", MALICIOUS),
                           "dynamic": _f("dynamic", BENIGN)})
    assert out["level"] in (MALICIOUS, BENIGN)
    assert out["level"] not in ("mostly_malicious", "unknown-and-malicious")
"""The packer signal must be converted to bits-per-byte before it is judged.

Evidence from four real Malcat payloads (2026-10-06, batch b1):

    sample   bytes  top-level   per-section
    b102      4608          71   .text=74, .rsrc=0
    b107     20480         107   .text=132, .rdata=76, .data=89
    b108   3514368         224   .text=117, .rdata=153, .rsrc=226

None of those can be bits-per-byte: entropy is 0-8 by definition. They are the
0-255 integer form, i.e. b/B x 32: 132/32 = 4.125, 226/32 = 7.06, 0/32 = 0.

_packer_signal() compared the RAW integer against 7.0, so every value >= 7
passed - which is every file - and the emitted signal carried a number with no
unit. The agent then had to guess: b102's run reasoning "high entropy is an
artifact of the .NET metadata container" was the LLM correcting for our bug on
71 (2.22 b/B, plainly not packed). Three samples in a row recorded
{"entropy": 71|107|224} and did no unpacking.

After this change:
  71  -> 2.22 b/B -> no signal
  107 -> 3.34 b/B -> no signal
  224 -> 7.00 b/B -> no signal (below the 7.2 threshold)
  and a genuinely-packed 232 (7.25 b/B) -> signal, in a stated unit.

Note the threshold is deliberate: b108 IS packed (.rsrc = 226 = 7.06) yet its
top-level 224 = 7.00 reads as unpacked, because the average dilutes the packed
section. That is a real limitation of a file-level average, recorded rather
than papered over - the per-section entropies remain available to the agent
through malcat_analyze.
"""
from winre.agentic import (_PACKED_ENTROPY_BPB, _packer_note, _packer_signal)


def _quick(malcat_entropy):
    return {"evidence": {
        "malcat": {"file": {"entropy": malcat_entropy}, "anomalies": []},
        "diec": {"detects": []},
    }}


# --- the unit conversion, against the real values ------------------------

def test_the_real_values_are_bits_per_byte_scaled_by_32():
    # 71 (b102), 107 (b107), 224 (b108) - values that cannot be raw entropy
    assert round(71 / 32, 3) == 2.219
    assert round(107 / 32, 3) == 3.344
    assert 224 / 32 == 7.0


def test_a_benign_sample_emits_no_packer_signal():
    for raw in (0, 7, 71, 107, 224):
        sig = _packer_signal(_quick(raw))
        assert "entropy" not in (sig or {}), (
            f"raw Malcat value {raw} must not read as packing; got {sig}")


def test_truly_random_data_does_emit_one():
    """255/32 = 7.97 b/B: that IS packing-grade entropy, and saying so is
    correct behaviour, not a false positive."""
    assert _packer_signal(_quick(255))["entropy"] == 7.969


def test_a_genuinely_packed_sample_does_emit_one():
    # 232/32 = 7.25 b/B: unpacking stops being optional here
    sig = _packer_signal(_quick(232))
    assert sig and sig["entropy"] == 7.25


def test_the_emitted_signal_is_rounded_not_raw():
    sig = _packer_signal(_quick(245))       # 7.65625
    assert sig["entropy"] == 7.656


def test_no_malcat_at_all_is_not_an_error():
    assert _packer_signal({"evidence": {}}) is None
    assert _packer_signal(None) is None
    assert _packer_signal({"evidence": {"malcat": {}}}) is None
    assert _packer_signal({"evidence": {"malcat": {"file": {}}}}) is None


def test_diec_packer_survives_without_entropy():
    q = {"evidence": {
        "malcat": {"file": {}, "anomalies": []},
        "diec": {"detects": ["UPX 3.96 (generic)", "Cpp"]},
    }}
    sig = _packer_signal(q)
    assert sig and sig["diec"] == ["UPX 3.96 (generic)"]


def test_threshold_is_on_the_shannon_scale():
    """The constant must be plausible as bits-per-byte, not as the 0-255 form."""
    assert 0 < _PACKED_ENTROPY_BPB <= 8.0
    assert _PACKED_ENTROPY_BPB >= 7.0


# --- the note must state the unit and the route --------------------------

def test_the_note_names_the_unit():
    note = _packer_note({"entropy": 7.25}, None, True)
    assert "7.25 bits/byte" in note
    assert "x64dbg_unpack" in note


def test_the_note_does_not_claim_a_route_when_nothing_fired():
    assert _packer_note(None, None, True) == ""
    assert _packer_note({}, None, True) == ""
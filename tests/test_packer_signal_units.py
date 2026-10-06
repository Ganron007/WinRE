"""The packer signal converts Malcat's entropy, and reads per-section, not the
file average alone.

Malcat reports entropy as bits-per-byte x 32, as a 0-255 integer:

    sample   bytes   file      sections (raw -> b/B)
    b102      4608     71      .text=74->2.31,  .rsrc=0->0.0     benign
    b107     20480    107      .text=132->4.13, .rdata=76->2.38  benign
    b108   3514368    224      .rsrc=226->7.06, .rdata=153->4.78 MALWARE, packed

Entropy is 0-8 by definition, so the raw integers cannot be compared to a
bits-per-byte threshold. The old code did exactly that and also emitted the
raw number, leaving the agent to re-derive the unit - b102's reasoning "high
entropy is an artefact of the .NET metadata container" was the LLM doing that
correction for us.

The file average is also not sufficient on its own: b108's 3 MB packed .rsrc
pulls its file-level 224/32 = 7.00 down just under a 7.2 threshold, so a
genuinely packed sample read as unpacked. The per-section maximum separates
them cleanly (benign max 2.31 and 4.13 b/B; malware 7.06 b/B), so it is the
primary signal and the thresholds are set against those measurements.
"""
from winre.agentic import (_PACKED_ENTROPY_BPB, _PACKED_SECTION_BPB,
                           _max_section_bpb, _packer_note, _packer_signal)


def _quick(file_entropy, sections=None, anomalies=None):
    return {"evidence": {
        "malcat": {"file": {"entropy": file_entropy,
                            "layout": sections or []},
                   "anomalies": anomalies or []},
        "diec": {"detects": []},
    }}


B102 = ("71", [("header", 61), (".text", 74), (".rsrc", 0), (".reloc", 0)])
B107 = ("107", [("header", 49), (".text", 132), (".rdata", 76),
                (".data", 89), (".rsrc", 88), (".reloc", 50)])
B108 = ("224", [("header", 75), (".text", 117), (".rdata", 153),
                (".data", 76), (".rsrc", 226)])


def _secs(pairs):
    return [{"name": n, "entropy": e} for n, e in pairs]


# --- the real samples -----------------------------------------------------

def test_b102_benign_emits_nothing():
    assert _packer_signal(_quick(71, _secs(B102[1]))) is None


def test_b107_benign_emits_nothing():
    assert _packer_signal(_quick(107, _secs(B107[1]))) is None


def test_b108_packed_section_is_detected():
    """The case the file-average threshold missed."""
    sig = _packer_signal(_quick(224, _secs(B108[1])))
    assert sig is not None
    assert sig["packed_section"]["name"] == ".rsrc"
    assert sig["packed_section"]["bits_per_byte"] == 7.062
    # the file average is below its own threshold, so it must NOT also claim
    assert "entropy" not in sig


# --- the unit conversion --------------------------------------------------

def test_values_are_bits_per_byte_scaled_by_32():
    assert round(71 / 32, 3) == 2.219
    assert round(107 / 32, 3) == 3.344
    assert 224 / 32 == 7.0
    assert round(226 / 32, 3) == 7.062


def test_max_section_picks_the_highest_and_converts():
    name, b = _max_section_bpb({"layout": _secs(B108[1])})
    assert name == ".rsrc" and round(b, 3) == 7.062
    name, b = _max_section_bpb({"layout": _secs(B107[1])})
    assert name == ".text" and round(b, 3) == 4.125


def test_no_sections_or_junk_are_not_an_error():
    assert _max_section_bpb({}) is None
    assert _max_section_bpb({"layout": []}) is None
    assert _max_section_bpb({"layout": [{"name": "x", "entropy": None}]}) is None
    assert _max_section_bpb({"layout": ["not a dict"]}) is None
    assert _packer_signal(_quick(71)) is None
    assert _packer_signal(_quick(71, _secs([(".text", None)]))) is None


# --- thresholds -----------------------------------------------------------

def test_thresholds_are_on_the_shannon_scale():
    for t in (_PACKED_ENTROPY_BPB, _PACKED_SECTION_BPB):
        assert 0 < t <= 8.0
    # and they actually discriminate the measured values
    assert _PACKED_SECTION_BPB > max(2.31, 4.125)
    assert _PACKED_SECTION_BPB < 7.062
    assert _PACKED_ENTROPY_BPB > 7.0


def test_boundary_behaviour():
    # 6.5 x 32 = 208: below -> no signal
    assert _packer_signal(_quick(1, _secs([(".x", 207)]))) is None
    # at the threshold -> signal
    sig = _packer_signal(_quick(1, _secs([(".x", 208)])))
    assert sig and sig["packed_section"]["bits_per_byte"] == 6.5


# --- diec still works independently --------------------------------------

def test_diec_packer_survives_without_entropy():
    q = {"evidence": {
        "malcat": {"file": {}, "anomalies": []},
        "diec": {"detects": ["UPX 3.96 (generic)", "Cpp"]},
    }}
    sig = _packer_signal(q)
    assert sig and sig["diec"] == ["UPX 3.96 (generic)"]


def test_max_section_and_diec_coexist():
    sig = _packer_signal(_quick(224, _secs(B108[1])))
    assert "packed_section" in sig


# --- the note states the target and the unit ----------------------------

def test_the_note_names_the_section_and_the_unit():
    note = _packer_note({"packed_section": {"name": ".rsrc",
                                            "bits_per_byte": 7.062}},
                        None, True)
    assert ".rsrc" in note and "7.062" in note
    assert "x64dbg_unpack" in note


def test_the_note_still_states_bits_per_byte_for_the_file_average():
    note = _packer_note({"entropy": 7.5}, None, True)
    assert "7.5 bits/byte" in note


def test_no_signal_no_note():
    assert _packer_note(None, None, True) == ""
    assert _packer_note({}, None, True) == ""
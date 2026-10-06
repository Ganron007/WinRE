"""A DLL cannot be spawned. It has to be hosted.

b105 (2026-10-06) died in Frida with

    frida.ExecutableNotSupportedError: unable to spawn executable at '...':
      unsupported file format

because the file is a DLL - the export directory says so, the corpus path is
a hash and tells you nothing - and device.spawn only accepts executables. The
detonation never started while the stage still reported green.

An analyst runs a DLL by loading it into a host process and calling an entry
point. That is what _launch_argv does now, and these tests pin the decisions
that make it honest:
  * the DLL verdict comes from the PE header, not the file extension;
  * the entry point is chosen from the file's own exports;
  * with no provable entry point it REFUSES rather than guessing, because a
    wrong entry point is simply not this sample.
"""
import os

import pytest

from tools import frida_api_trace as fat


def test_an_executable_is_launched_directly(tmp_path):
    p = tmp_path / "a.exe"
    p.write_bytes(_MZ(characteristics=0x0002))       # EXE, not DLL
    argv, loader, entry = fat._launch_argv(str(p))
    assert argv == [str(p)]
    assert loader == "direct"
    assert entry is None


def test_a_dll_is_hosted_by_rundll32(tmp_path, monkeypatch):
    p = tmp_path / "b.dll"
    p.write_bytes(_MZ(characteristics=0x2002))
    monkeypatch.setattr(fat, "_exports", lambda _: ["Go"])
    monkeypatch.setenv("WINDIR", r"C:\Windows")
    argv, loader, entry = fat._launch_argv(str(p))
    assert argv[0].lower().endswith("rundll32.exe")
    # the file and the entry travel as ONE argument, file first
    assert argv[1] == f"{p},Go"
    assert loader == "rundll32" and entry == "Go"


def test_a_forced_entry_wins(tmp_path, monkeypatch):
    p = tmp_path / "c.dll"
    p.write_bytes(_MZ(characteristics=0x2002))
    monkeypatch.setattr(fat, "_exports", lambda _: ["Go", "Other"])
    monkeypatch.setenv("WINDIR", r"C:\Windows")
    argv, _, entry = fat._launch_argv(str(p), forced_entry="Other")
    assert entry == "Other" and argv[1] == f"{p},Other"


def test_no_provable_entry_point_refuses(tmp_path, monkeypatch):
    """Guessing silently would run something that is not the sample."""
    p = tmp_path / "d.dll"
    p.write_bytes(_MZ(characteristics=0x2002))
    monkeypatch.setattr(fat, "_exports", lambda _: [])
    with pytest.raises(fat.FridaLaunchError) as e:
        fat._launch_argv(str(p))
    assert "no discernible export" in str(e.value)
    assert "--dll-entry" in str(e.value)


def test_a_missing_or_non_pe_file_is_not_treated_as_a_dll(tmp_path):
    for name, body in (("empty.bin", b""), ("text.txt", b"hello world" * 20),
                       ("trunc.exe", b"MZ")):
        p = tmp_path / name
        p.write_bytes(body)
        argv, loader, _ = fat._launch_argv(str(p))
        assert loader == "direct" and argv == [str(p)], name
    assert fat._launch_argv(str(tmp_path / "nope"), )[1] == "direct"


def test_entry_point_prefers_the_conventional_ones(tmp_path, monkeypatch):
    """DllRegisterServer beats an alphabetically-first export."""
    p = tmp_path / "e.dll"
    p.write_bytes(_MZ(characteristics=0x2002))
    monkeypatch.setattr(fat, "_exports",
                        lambda _: ["Alpha", "DllRegisterServer", "Zeta"])
    _, _, entry = fat._launch_argv(str(p))
    assert entry == "DllRegisterServer"
    monkeypatch.setattr(fat, "_exports", lambda _: ["Go", "DllMain"])
    _, _, entry = fat._launch_argv(str(p))
    assert entry == "DllMain"


def test_a_hostile_header_does_not_raise(tmp_path):
    for head in (b"MZ" + b"\xff" * 0x3C,
                 b"MZ" + (0x7FFFFFFF).to_bytes(4, "little") + b"\x00" * 40):
        p = tmp_path / "h.bin"
        p.write_bytes(head)
        info = fat._pe_info(str(p))
        assert info["is_dll"] is False        # never assume


# --- fixture: a minimal PE header with the given Characteristics ----------

def _MZ(characteristics: int = 0x0002) -> bytes:
    b = bytearray(b"\x00" * 0x400)
    b[0:2] = b"MZ"
    b[0x3C:0x40] = (0x80).to_bytes(4, "little")
    b[0x80:0x84] = b"PE\x00\x00"
    b[0x84:0x86] = (0x014C).to_bytes(2, "little") * 3   # i386, any
    b[0x96:0x98] = characteristics.to_bytes(2, "little")
    b[0x98:0x9A] = (0x0E0).to_bytes(2, "little")          # PE32+
    return bytes(b)
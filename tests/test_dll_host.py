"""A DLL needs the right rundll32 host, by bitness, with a full path.

The first version of the DLL launcher ("rundll32.exe", "<file>", ",entry")
failed on its first real use - b101, which IS a DLL despite its .exe name:

    loader=rundll32 entry=OpenClipFn
    frida.ExecutableNotFoundError: unable to find executable at 'rundll32.exe'

Two defects caught by the very next sample:
  1. a bare image name, which Frida's spawn cannot resolve because an
     SSH-spawned process does not inherit a useful PATH;
  2. wrong bitness - b101 is PE32, so only the SysWOW64 rundll32 can load it.
     A 64-bit host gives "not a valid Win32 application", which is exactly the
     silent-failure class this whole exercise exists to remove.
"""
import os

import pytest

from tools import frida_api_trace as fat


def test_a_32_bit_dll_is_hosted_by_the_wow64_rundll32(tmp_path, monkeypatch):
    monkeypatch.setenv("WINDIR", r"C:\Windows")
    p = tmp_path / "b101.dll"
    p.write_bytes(_MZ(characteristics=0x2002, machine=0x014C))
    monkeypatch.setattr(fat, "_exports", lambda _: ["OpenClipFn"])
    argv, loader, entry = fat._launch_argv(str(p))
    assert argv[0] == r"C:\Windows\SysWOW64\rundll32.exe"
    assert loader == "rundll32" and entry == "OpenClipFn"
    # the file and the entry travel as ONE argument, file first
    assert argv[1].startswith(str(p)) and argv[1].endswith(",OpenClipFn")


def test_a_64_bit_dll_is_hosted_by_the_system32_rundll32(tmp_path, monkeypatch):
    monkeypatch.setenv("WINDIR", r"C:\Windows")
    p = tmp_path / "b.dll"
    p.write_bytes(_MZ(characteristics=0x2002, machine=0x8664))
    monkeypatch.setattr(fat, "_exports", lambda _: ["DllRegisterServer"])
    argv, _, _ = fat._launch_argv(str(p))
    assert argv[0] == r"C:\Windows\System32\rundll32.exe"


def test_an_unknown_machine_defaults_to_the_64_bit_host(tmp_path, monkeypatch):
    monkeypatch.setenv("WINDIR", r"C:\Windows")
    p = tmp_path / "u.dll"
    p.write_bytes(_MZ(characteristics=0x2002, machine=0x01C0))
    monkeypatch.setattr(fat, "_exports", lambda _: ["Go"])
    argv, _, _ = fat._launch_argv(str(p))
    assert argv[0] == r"C:\Windows\System32\rundll32.exe"


def test_a_missing_host_is_a_clear_error_not_a_frida_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("WINDIR", str(tmp_path / "nowhere"))
    p = tmp_path / "h.dll"
    p.write_bytes(_MZ(characteristics=0x2002, machine=0x014C))
    monkeypatch.setattr(fat, "_exports", lambda _: ["Go"])
    with pytest.raises(fat.FridaLaunchError) as e:
        fat._launch_argv(str(p))
    assert "no rundll32 host" in str(e.value)


def test_the_host_path_is_absolute(tmp_path, monkeypatch):
    """This is the ExecutableNotFoundError regression."""
    monkeypatch.setenv("WINDIR", r"C:\Windows")
    p = tmp_path / "a.dll"
    p.write_bytes(_MZ(characteristics=0x2002, machine=0x014C))
    monkeypatch.setattr(fat, "_exports", lambda _: ["Go"])
    argv, _, _ = fat._launch_argv(str(p))
    assert "\\" in argv[0] or ":" in argv[0]
    assert argv[0] != "rundll32.exe"


def test_bits_are_read_from_the_machine_field(tmp_path):
    p32 = tmp_path / "a.dll"
    p32.write_bytes(_MZ(characteristics=0x2002, machine=0x014C))
    assert fat._pe_info(str(p32))["bits"] == 32
    p64 = tmp_path / "b.dll"
    p64.write_bytes(_MZ(characteristics=0x2002, machine=0x8664))
    assert fat._pe_info(str(p64))["bits"] == 64


def test_an_executable_is_still_launched_directly(tmp_path):
    p = tmp_path / "a.exe"
    p.write_bytes(_MZ(characteristics=0x0002, machine=0x014C))
    argv, loader, entry = fat._launch_argv(str(p))
    assert argv == [str(p)] and loader == "direct" and entry is None


def _MZ(characteristics: int = 0x0002, machine: int = 0x014C) -> bytes:
    b = bytearray(b"\x00" * 0x400)
    b[0:2] = b"MZ"
    b[0x3C:0x40] = (0x80).to_bytes(4, "little")
    b[0x80:0x84] = b"PE\x00\x00"
    b[0x84:0x86] = machine.to_bytes(2, "little")
    b[0x96:0x98] = characteristics.to_bytes(2, "little")
    b[0x98:0x9A] = (0x010B if machine == 0x014C else 0x020B).to_bytes(2, "little")
    return bytes(b)
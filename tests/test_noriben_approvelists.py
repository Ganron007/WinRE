"""tests/test_noriben_approvelists.py — Unit tests for Noriben-grade Procmon noise filtering.

Validates path generalization, compiled regex approvelists, guest summarization,
post-detonation correlation, and CSV encoding resilience.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

from winre.procmon_approvelists import (
    generalize_path,
    is_global_noise,
    is_cmd_noise,
    is_file_noise,
    is_reg_noise,
    is_dll_noise,
    iter_procmon_csv,
)
from winre.summarize_dynamic import summarize_procmon
from winre.procmon_post import build_procmon_report


def test_path_generalization():
    # User / system folders generalized
    assert generalize_path(r"C:\Users\Admin\AppData\Local\Temp\malware.bin") == r"%TEMP%\malware.bin"
    assert generalize_path(r"C:\Windows\Temp\payload.dll") == r"%TEMP%\payload.dll"
    assert generalize_path(r"C:\Users\JohnDoe\AppData\Local\evil.exe") == r"%LOCALAPPDATA%\evil.exe"
    assert generalize_path(r"C:\Users\Alice\AppData\Roaming\bot.exe") == r"%APPDATA%\bot.exe"
    assert generalize_path(r"C:\Users\Bob\malware.exe") == r"%USERPROFILE%\malware.exe"
    assert generalize_path(r"C:\ProgramData\payload.exe") == r"%PROGRAMDATA%\payload.exe"
    assert generalize_path(r"C:\Program Files (x86)\Common\drop.dll") == r"%PROGRAMFILES(X86)%\Common\drop.dll"
    assert generalize_path(r"C:\Program Files\App\drop.dll") == r"%PROGRAMFILES%\App\drop.dll"
    assert generalize_path(r"C:\Windows\System32\cmd.exe") in (r"%WINDIR%\System32\cmd.exe", r"%SYSTEMROOT%\System32\cmd.exe")

    # Edge cases
    assert generalize_path("") == ""
    assert generalize_path(None) == ""


def test_noise_filtering_predicates():
    # 1. Global noise processes
    assert is_global_noise("SearchIndexer.exe") is True
    assert is_global_noise("Procmon64.exe") is True
    assert is_global_noise("consent.exe") is True
    assert is_global_noise("VMwareUser.exe") is True
    assert is_global_noise("hollows_hunter64.exe") is True
    assert is_global_noise("malware.exe") is False
    assert is_global_noise("svchost_fake.exe") is False

    # 2. Command line noise
    assert is_cmd_noise(r"C:\Windows\system32\conhost.exe 0xffffffff -ForceV1") is True
    assert is_cmd_noise(r"C:\Windows\System32\RuntimeBroker.exe -Embedding") is True
    assert is_cmd_noise(r"powershell.exe -enc aQB3AHIA...") is False
    assert is_cmd_noise(r"cmd.exe /c whoami") is False

    # 3. File noise
    assert is_file_noise(r"C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\foo.tmp") is True
    assert is_file_noise(r"C:\Users\Admin\AppData\Local\GDIPFONTCACHEV1.DAT") is True
    assert is_file_noise(r"C:\Users\Admin\AppData\Local\Microsoft\Windows\Explorer\thumbcache_32.db") is True
    assert is_file_noise(r"C:\Users\Admin\Desktop\desktop.ini") is True
    assert is_file_noise(r"C:\Windows\System32\catroot2\edb.log") is True
    # True negative: malicious drops
    assert is_file_noise(r"C:\Users\Admin\AppData\Local\Temp\dropped.exe") is False
    assert is_file_noise(r"C:\Windows\System32\wlogon.dll") is False
    assert is_file_noise(r"C:\ProgramData\malware.dat") is False

    # 4. Registry noise
    assert is_reg_noise(r"HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-123") is True
    assert is_reg_noise(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") is True
    assert is_reg_noise(r"HKCU\Software\Microsoft\Windows\Shell\BagMRU\1") is True
    assert is_reg_noise(r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Prefetcher") is True
    # True negative: persistence and tampering
    assert is_reg_noise(r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\EvilBackdoor") is False
    assert is_reg_noise(r"HKLM\System\CurrentControlSet\Services\EvilService\ImagePath") is False
    assert is_reg_noise(r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\Payload") is False

    # 5. DLL load noise
    assert is_dll_noise(r"C:\Windows\System32\kernel32.dll") is True
    assert is_dll_noise(r"C:\Windows\SysWOW64\ntdll.dll") is True
    assert is_dll_noise(r"C:\Windows\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.1110_none_60b5254171f9507e\comctl32.dll") is True
    assert is_dll_noise(r"C:\Python313\python313.dll") is True
    assert is_dll_noise(r"C:\Program Files\Common Files\System\oleo.dll") is True
    # True negative: sideloaded or dropped DLLs
    assert is_dll_noise(r"C:\Users\Admin\AppData\Local\Temp\hook.dll") is False
    assert is_dll_noise(r"C:\malware\inject.dll") is False


def test_summarize_procmon_with_noise_and_signal(tmp_path: Path):
    csv_file = tmp_path / "procmon.csv"
    rows = [
        "Time of Day,Process Name,PID,Operation,Path,Result,Detail",
        # 1. Global noise process
        "12:00:01,SearchIndexer.exe,1000,QueryOpen,C:\\Windows\\System32,SUCCESS,",
        # 2. Benign file noise from sample
        "12:00:02,sample.exe,2000,CreateFile,C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp\\ns.tmp,SUCCESS,Desired Access: Read Attributes",
        # 3. Benign registry noise from sample
        "12:00:03,sample.exe,2000,RegQueryValue,HKCU\\Software\\Microsoft\\Windows\\Shell\\BagMRU,SUCCESS,",
        # 4. Benign system DLL load from sample
        "12:00:04,sample.exe,2000,Load Image,C:\\Windows\\System32\\kernel32.dll,SUCCESS,",
        # 5. Malicious file drop from sample
        "12:00:05,sample.exe,2000,CreateFile,C:\\Users\\Admin\\AppData\\Local\\Temp\\dropped.bin,SUCCESS,Access: Generic Write",
        # 6. Malicious registry persistence from sample
        "12:00:06,sample.exe,2000,RegSetValue,HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater,SUCCESS,Data: evil.exe",
        # 7. Malicious process execution
        "12:00:07,sample.exe,2000,Process Create,C:\\Windows\\System32\\cmd.exe,SUCCESS,cmd.exe /c whoami",
    ]
    csv_file.write_text("\n".join(rows) + "\n", encoding="utf-8")

    res = summarize_procmon(csv_file, sample_name="sample.exe")

    # Contract assertions
    assert res["status"] == "ok"
    assert res["rows_total"] == 7
    assert res["rows_sample"] == 6

    # Noriben noise filtering assertions
    assert res["filtered_events_count"] == 4
    assert res["filtered_by_category"]["global_process"] == 1
    assert res["filtered_by_category"]["file"] == 1
    assert res["filtered_by_category"]["registry"] == 1
    assert res["filtered_by_category"]["dll"] == 1

    # Notable signal captured with generalized paths
    assert len(res["notable_files"]) == 1
    assert res["notable_files"][0]["path"] == r"C:\Users\Admin\AppData\Local\Temp\dropped.bin"
    assert res["notable_files"][0]["generalized_path"] == r"%TEMP%\dropped.bin"

    assert len(res["notable_registry"]) == 1
    assert res["notable_registry"][0]["path"] == r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater"

    assert len(res["notable_processes"]) == 1
    assert res["notable_processes"][0]["process"] == "sample.exe"
    assert "whoami" in res["notable_processes"][0]["cmdline"]


def test_procmon_post_filtering_and_merge(tmp_path: Path):
    csv_file = tmp_path / "procmon.csv"
    rows = [
        "Time of Day,Process Name,PID,Operation,Path,Result,Detail",
        # False drop (NetworkService temp) -> must be filtered
        "13:00:01,sample.exe,3000,CreateFile,C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp\\ns.tmp,SUCCESS,",
        # False DLL sideload (Python runtime) -> must be filtered
        "13:00:02,sample.exe,3000,Load Image,C:\\Python313\\python313.dll,SUCCESS,",
        # False service creation (BAM state) -> must be filtered
        "13:00:03,sample.exe,3000,RegSetValue,HKLM\\System\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21,SUCCESS,",
        # True payload drop -> must be kept
        "13:00:04,sample.exe,3000,CreateFile,C:\\Users\\Admin\\AppData\\Local\\Temp\\payload.exe,SUCCESS,",
        # True DLL sideload -> must be kept
        "13:00:05,sample.exe,3000,Load Image,C:\\Users\\Admin\\AppData\\Local\\Temp\\sideload.dll,SUCCESS,",
        # True service persistence -> must be kept
        "13:00:06,sample.exe,3000,RegSetValue,HKLM\\System\\CurrentControlSet\\Services\\MalService\\ImagePath,SUCCESS,mal.exe",
    ]
    csv_file.write_text("\n".join(rows) + "\n", encoding="utf-8")

    # Simulate existing guest summary in dyn_dir
    guest_summary = {
        "status": "ok",
        "rows_total": 6,
        "rows_sample": 6,
        "filtered_events_count": 3,
        "top_operations": [["CreateFile", 2], ["Load Image", 2]],
    }
    (tmp_path / "procmon_summary.json").write_text(json.dumps(guest_summary), encoding="utf-8")

    report = build_procmon_report(tmp_path)

    assert report["status"] == "ok"
    assert report["ok"] is True
    # Merged guest keys preserved
    assert report["rows_total"] == 6
    assert report["filtered_events_count"] == 3
    assert report["top_operations"] == [["CreateFile", 2], ["Load Image", 2]]

    # Persistence correctly filtered
    persistence = report["persistence"]
    # Drop file family only has the real drop
    assert persistence["drop_file"]["count"] == 1
    assert r"payload.exe" in persistence["drop_file"]["samples"][0]

    # DLL sideload only has the real sideload
    assert persistence["dll_sideload"]["count"] == 1
    assert r"sideload.dll" in persistence["dll_sideload"]["samples"][0]

    # Service only has MalService, not BAM
    assert persistence["service"]["count"] == 1
    assert "MalService" in persistence["service"]["samples"][0]

    # Dropped files list in AppData only contains payload.exe
    assert len(report["dropped_files_appdata"]) == 1
    assert "payload.exe" in report["dropped_files_appdata"][0]


def test_resilient_csv_reader_encoding_recovery(tmp_path: Path):
    csv_file = tmp_path / "procmon_latin1.csv"
    # Write latin-1 bytes with non-UTF-8 character (e.g. byte 0xe9 = é in latin-1)
    content = b"Time of Day,Process Name,PID,Operation,Path,Result,Detail\r\n14:00:00,t\xe9st.exe,4000,CreateFile,C:\\test.txt,SUCCESS,\r\n"
    csv_file.write_bytes(content)

    rows = list(iter_procmon_csv(csv_file))
    assert len(rows) == 1
    assert rows[0]["Operation"] == "CreateFile"
    assert rows[0]["Path"] == "C:\\test.txt"

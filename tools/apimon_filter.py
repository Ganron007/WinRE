r"""
apimon_filter.py — Generate API Monitor / procmon filter for a target binary.

For API Monitor: outputs an .api filter file that selects a curated set
of API categories (file, registry, process, network, etc.) scoped to a
specific process name.

For procmon: outputs a ProcMon Filter (PMC) XML that filters events to
just the target process + a curated event class set.

Both are static filter files; the analyst loads them in the GUI and runs
the target.

Usage (PowerShell on Flare-VM):
    # API Monitor filter
    PS> python C:\tools\flarevm-deploy\dynamic\apimon_filter.py --tool apimon --process foo.exe --categories file,registry,process,network --out C:\samples\foo.apimon.api

    # procmon filter
    PS> python C:\tools\flarevm-deploy\dynamic\apimon_filter.py --tool procmon --process foo.exe --categories file,registry,process,network --out C:\samples\foo.procmon.pmc
"""
import argparse
from pathlib import Path


# API Monitor category GUIDs (from API Monitor v2r12)
APIMON_CATEGORIES = {
    "process":     "{00000000-0000-0000-0000-000000000000}",  # default
    "file":        "{8FC8E228-B4F0-4f50-BB0E-68BAB26FD7B5}",
    "registry":    "{9CB87D3F-2D4A-4f97-AE89-2ABDBA84FAE5}",
    "network":     "{5A2B96F0-DA84-4f6c-A40C-3B6A6A0C8D9C}",
    "memory":      "{2BF9A5B9-3B5A-4f4c-91F0-3FA4B6C3E1A1}",
    "crypto":      "{B9D9EB5C-3E2D-4f4c-BF1F-1B6E5F8E2DAB}",
    "synchronization": "{D63D9C7A-3B7A-4f1c-A5B6-9E5D7A2B6C8F}",
}


def apimon_filter(process: str, categories: list, out: Path):
    """Generate API Monitor .api filter file."""
    lines = [
        f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        f"<ApiMonitorFilter Version=\"2\" Category=\"{categories[0]}\">",
        f"  <Process Name=\"{process}\" />",
        "  <Include>",
    ]
    for cat in categories:
        guid = APIMON_CATEGORIES.get(cat, "")
        if guid:
            lines.append(f"    <Category Name=\"{cat}\" GUID=\"{guid}\" />")
    lines += [
        "  </Include>",
        "</ApiMonitorFilter>",
    ]
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote API Monitor filter: {out} ({len(lines)} lines)")


def procmon_filter(process: str, categories: list, out: Path):
    """Generate ProcMon .pmc filter file."""
    # ProcMon filter XML format
    event_classes = {
        "file":    "File",
        "registry": "Registry",
        "process": "Process",
        "network": "Network",
        "memory":  "Memory",
    }
    events = [event_classes[c] for c in categories if c in event_classes]
    lines = [
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<ProcMonFilter Version=\"1.0\">",
        f"  <Filter>",
        f"    <ProcessNameFilter Match=\"Include\">{process}</ProcessNameFilter>",
        f"    <EventClassFilter Match=\"Include\">",
    ]
    for e in events:
        lines.append(f"      <EventClass>{e}</EventClass>")
    lines += [
        "    </EventClassFilter>",
        "  </Filter>",
        "</ProcMonFilter>",
    ]
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote ProcMon filter: {out} ({len(lines)} lines)")


def main():
    ap = argparse.ArgumentParser(description="Generate API Monitor / procmon filter")
    ap.add_argument("--tool", choices=["apimon", "procmon"], required=True)
    ap.add_argument("--process", required=True, help="process name to filter on (e.g. foo.exe)")
    ap.add_argument("--categories", required=True,
                    help="comma-separated categories: file,registry,process,network,memory,crypto,synchronization")
    ap.add_argument("--out", required=True, help="output filter file")
    args = ap.parse_args()

    cats = [c.strip() for c in args.categories.split(",") if c.strip()]
    if not cats:
        print("FATAL: --categories is empty")
        return 1

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    if args.tool == "apimon":
        apimon_filter(args.process, cats, out)
    else:
        procmon_filter(args.process, cats, out)


if __name__ == "__main__":
    main()

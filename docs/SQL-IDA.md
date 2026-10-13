# SQL-IDA — Windows (FlareVM)

> **Integration:** WinRE uses the free `idasql` engine against an `.i64`
> database through `tools/ida_sql_client.py`. `idasql` is not a substitute
> for IDA licensing: WinRE's headless database workflow requires a compatible,
> activated IDA Professional installation. Verify the pairing on the deployed
> revision.
> **Audience:** integrators querying IDA over SQL.

```
tools/ida_sql_client.py  (IdaSqlClient)
  -> POST http://127.0.0.1:19300/query        (SQL as text/plain; persistent reads)
  -> idasql -s <file>.i64 -w -q "<SQL>"       (persisting writes)
      -> idat -A -c -o<file>.i64              (creates the .i64 on first use)
```

Port: HTTP `:19300` bound to `127.0.0.1`.

## Install (free release, auto-provisioned)

| Component | Location | How |
|---|---|---|
| idasql CLI | `<IDA>\idasql.exe` next to `idat.exe` | staged by `ops/provision_tools.ps1` (downloads `idasql-v0.0.18.1-ida93.zip` from GitHub releases) → installed by `install/setup-flarevm.ps1` |
| IDA plugin (optional, GUI) | `<IDA>\plugins\{idasql.dll,ida-plugin.json}` | same archive (`windows-x86_64/plugin/`) |

Version matrix: select an archive matching the installed IDA version. The
recorded IDA 9.3 verification used `idasql v0.0.18.1`; rerun the health and
query checks below after changing either component.

## Verification (no stubs)

```powershell
C:\Python313\python.exe C:\WinRE\tools\ida_sql_client.py health
C:\Python313\python.exe C:\WinRE\tools\ida_sql_client.py query `
  "SELECT addr FROM funcs WHERE size > 150 ORDER BY size DESC LIMIT 3" `
  --file C:\samples\calc.exe
```

`install\verify-flarevm.ps1` runs the same live query and warns on failure.

Client API: `ida_query(sample, sql, max_rows=200)` — read-only policy enforced
(`validate_readonly_sql`); `ida_write(sample, sql)` for persisting updates via
`-w`; `.i64` auto-created with `idat -A -c`. Audit trail:
`C:\WinRE\logs\ida-sql-audit.jsonl`.

Notes:
- `tools/flarevm_ida_query.py` remains as the one-shot CLI (also real SQL via
  `idasql -s … -q …`) used by older helpers; new code should prefer the client
  (persistent server, ~ms per query after first load).
- Writes invalidate a running HTTP server (it caches the database): the client
  closes the server after `ida_write`.

# SQL-Ghidra — Windows (FlareVM) — REAL ENGINE

> **Status: REAL (2026-09-15).** SQL-first Ghidra access, mirroring RevAI's
> architecture. There is **no fallback stub** — without the engine, queries
> fail loudly.

```
tools/flare_ghidra_sql.py  (canonical queries)
  -> tools/ghidra_sql_client.py  (GhidraSqlClient: lazy start, read-only gate)
      -> POST http://127.0.0.1:18080/query          (SQL as text/plain)
          -> ghidrasql --http  (SQLite-backed SQL engine, ghidrasql 0.0.6)
              -> LibGhidraHost extension  (RPC host inside Ghidra headless)
                  -> Ghidra project per sample (analyzeHeadless import+analysis)
```

Ports: HTTP `:18080`, LibGhidraHost RPC `:18090` (both `127.0.0.1`).
One Ghidra project per sample, cached under `C:\WinRE\cache\ghidra\<sha16>\`.

## Installed artifacts

| Component | Location | Notes |
|---|---|---|
| LibGhidraHost extension | `<Ghidra>\Ghidra\Extensions\LibGhidraHost` | built from `0xeb/libghidra` (`gradle installExtension`) |
| ghidrasql engine | `C:\Tools\ghidrasql\ghidrasql.exe` | built v0.0.6 from `0xeb/ghidrasql` + `0xeb/libxsql` |
| JDK pin | `<Ghidra>\support\launch.properties` | `JAVA_HOME_OVERRIDE=<temurin21>` (Ghidra 12 hangs on JDK 25) |
| Ownership pin | `<Ghidra>\support\launch.properties` | `VMARGS=-Duser.name=flare-vm` (project ownership; SSH vs Task Scheduler case mismatch aborts with `NotOwnerException`) |

Staged offline copies live in `internal\reapply\sql\` (`LibGhidraHost.zip`,
`ghidrasql.exe`) and are installed by `install\setup-flarevm.ps1`
(also staged to `C:\Tools-staged\sql\` by `ops\reapply_after_revert.ps1` /
`ops\provision_tools.ps1`).

## Build from source (air-gapped recipe, verified 2026-09-15)

1. Fetch: `libghidra` (main), `ghidrasql` (main, VERSION 0.0.6), `libxsql`
   (main), `cpp-httplib` v0.16.3, `protobuf` v29.3 + its vendored
   `third_party/abseil-cpp` `4a2c6336` (protobuf 29.3 is built as a
   subproject, gencode 5.29.3).
2. Normalize source mtimes to a fixed date (avoids CMake `generate.stamp`
   re-run loops on Windows), apply libghidra's
   `cpp/cmake/PatchProtobufCMake.cmake` manually (FetchContent override
   skips `PATCH_COMMAND`).
3. Extension: patch the staged `ghidra-extension/build.gradle`
   (`mavenCentral()` → a file:// maven repo holding `protobuf-java-4.29.3`
   with a minimal standalone POM), then
   `gradle --offline installExtension -PGHIDRA_INSTALL_DIR=<ghidra>`.
4. SDK: `cmake -G "Visual Studio 17 2022" -A x64` on `libghidra/cpp` with
   `-DFETCHCONTENT_SOURCE_DIR_CPP_HTTPLIB=<httplib>` and
   `-DFETCHCONTENT_SOURCE_DIR_PROTOBUF=<protobuf>`;
   `--build --config Release --target install` → `C:\Tools\libghidra-sdk`.
5. ghidrasql: patch its `CMakeLists.txt` httplib block to
   `add_subdirectory(<cpp-httplib>)` (or pre-create the target) and the
   `cpp_httplib` declare to `SOURCE_DIR <cpp-httplib>`. A stale-RevEng
   snapshot fails to compile (expects `HeadlessOptions`); ghidrasql **main**
   is required. Configure with `-DGHIDRASQL_LIBXSQL_DIR=<libxsql main>`
   `-DGHIDRASQL_LIBGHIDRA_DIR=<libghidra/cpp>` `-DGHIDRASQL_WITH_MCP=OFF`
   (fastmcpp fetch is not needed for HTTP SQL). Build → `bin\Release\ghidrasql.exe`.
6. Run long builds detached with **Task Scheduler** — Win32-OpenSSH kills the
   session's process tree on disconnect.

## Verification (no stubs)

```powershell
C:\Python313\python.exe C:\WinRE\tools\ghidra_sql_client.py health
C:\Python313\python.exe C:\WinRE\tools\flare_ghidra_sql.py query `
  "SELECT name, size FROM funcs WHERE size > 150 ORDER BY size DESC LIMIT 5" `
  --file C:\samples\calc.exe
```

`install\verify-flarevm.ps1` runs the same WHERE/ORDER semantics gate and
FAILs if the engine is missing or ordering/filtering is wrong.

Failure signatures and fixes:

| Symptom | Cause | Fix |
|---|---|---|
| `NotOwnerException: Project is owned by <user>` | `java user.name` differs between project creation and host start (case) | pin `VMARGS=-Duser.name=flare-vm`; delete `*.lock*` in the project dir |
| launcher sits 420s then timeout | JDK 25 or batch `pause` on error | pin `JAVA_HOME_OVERRIDE` to JDK 21; helper closes stdin (`DEVNULL`) |
| `generate.stamp is out-of-date` loop | source mtimes newer than build stamps | normalize source mtimes, wipe build dir |
| httplib fetched during configure | `FETCHCONTENT_SOURCE_DIR_*` cleared by declare | `add_subdirectory` the local tree / `SOURCE_DIR` in the declare |

Client API: `ghidra_query(sample, sql, max_rows=200)` returns
`{columns, rows:[dict], row_count, total_row_count, truncated, source,
session_id, audit_path}`; read-only SQL policy (single SELECT / WITH…SELECT)
is enforced in `ghidra_sql_client.validate_readonly_sql`. Audit trail:
`C:\WinRE\logs\ghidra-sql-audit.jsonl`.

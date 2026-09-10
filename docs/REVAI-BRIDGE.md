# RevAI ↔ WinRE remote-driver bridge

> **Audience:** operators and integrators running RevAI (Remnux/Linux) or any
> other control plane that drives WinRE (FlareVM) remotely. This document is
> the contract for **where the LLM configuration lives and how it reaches the
> remote driver**. WinRE is model-agnostic: any OpenAI-compatible endpoint
> works; only the variable names below are contractual.

## 1. Topology

| Machine | Runs | Needs |
|---|---|---|
| **Driver box** (e.g. RevAI on Remnux, or the operator host) | `winre.remote_driver` / `winre.pipeline --driver remote` — the pipeline process, the LangGraph agent, **every LLM call** | WinRE code + Python deps, the 4 LLM variables, internet to the LLM endpoint, SSH to the VM |
| **FlareVM** (Windows, air-gapped) | Tools only: Ghidra/IDA/Malcat/x64dbg SQL+HTTP MCP, detonation job, snapshot gate | WinRE repo at `C:\WinRE`, tools, MCP servers, clean-snapshot marker. **No LLM keys. No internet.** |

```
Driver box (agent loop + LLM + internet)          FlareVM (air-gapped, tools only)
  winre.remote_driver ── SSH-exec ────────────────► C:\Python313 tools
                      ── SCP (sample/packs) ──────► C:\samples, C:\WinRE\logs
                      ── HTTP MCP :9094/:9009/:9097 ► x64dbg / Malcat / WinDbg
                      LLM calls go to the provider — never to the VM.
```

**Invariant:** LLM calls execute inside the process that runs the WinRE
driver. The VM never receives, stores, or needs LLM configuration. This is
what allows the FlareVM to stay permanently air-gapped, including during
detonation.

## 2. What the driver box must have

1. The **WinRE package** (repo clone or at minimum `winre/` + its deps:
   `langchain-openai`, `langgraph`, `langchain-core`, `pydantic`).
   The remote driver is WinRE code — whoever drives must run it.
2. The **4 LLM variables** (§3) in the driver process environment.
3. **Network** to the LLM endpoint and SSH access to the FlareVM
   (`FLARE_HOST`, `FLARE_USER`, `FLARE_SSH_KEY`, `FLARE_SSH_PORT`).

The FlareVM side needs none of the LLM variables. If a `C:\WinRE\.env`
exists there from a previous NAT/testing phase, delete it.

## 3. The 4 variables

```
WINRE_LLM_BASE_URL=https://<your-provider>/v1
WINRE_LLM_MODEL=<model-name-your-provider-exposes>
WINRE_LLM_API_KEY=<key>
WINRE_LLM_REASONING=high          # low|medium|high|max — optional
```

Resolution order (highest first):

1. **Real process environment variables** — the `.env` file never
   overwrites an exported value. Best for secrets (nothing on disk).
2. `$WINRE_ENV` file (any path), if set.
3. `<repo>/.env` next to the WinRE package on the driver box.
4. Built-in fallback: `http://127.0.0.1:8000/v1`, model `local`
   (for a local unauthenticated server; non-localhost endpoints require
   `WINRE_LLM_API_KEY`).

### 3.1 Where the WinRE key lives (per runner)

The variable names are always `WINRE_LLM_*`; only the **surface** changes with
the machine that runs the driver process:

| Driver process runs on | WinRE key surface |
|---|---|
| Operator/Windows box — WinRE UI, `--driver local`, or a local `remote_driver` | `<WinRE repo>\.env` next to the package (gitignored, loaded automatically) |
| RevAI VM / any Linux control plane driving the FlareVM | a WinRE-owned env file on that box via `WINRE_ENV` (e.g. `/opt/winre/.env`), or process exports — **not** inside RevAI's own `llm.env` |
| FlareVM | none — the VM never holds LLM config; delete leftover `C:\WinRE\.env` |

**Same key or different keys — both are first-class.** Same model/endpoint on
both sides is expected; whether the API key is shared is the operator's choice:

- **Same key** (simplest): put the same value in both surfaces, or map it at
  the spawn site (§5).
- **Different keys** (independent quotas/rotation): keep each key in its own
  surface; WinRE traffic uses the WinRE key only.

Switching between the two is a one-line value change in the WinRE key
surface — no code change, no rewiring, and nothing moves into the other
project's config.

## 4. Wiring options on the driver box

Any of these is sufficient — pick one per deployment:

**A. Exports in the launcher/service (recommended; keys never on disk)**

```bash
export WINRE_LLM_BASE_URL="https://<your-provider>/v1"
export WINRE_LLM_MODEL="<model>"
export WINRE_LLM_API_KEY="<key>"
export WINRE_LLM_REASONING="high"
cd /opt/winre          # parent directory of the winre/ package
python3 -m winre.pipeline <sample> --driver remote --mode agentic
```

Invoke WinRE as a module (`python3 -m winre.pipeline`) from the directory
that contains the `winre/` package (or with `PYTHONPATH` pointing there).
Direct script paths (`python3 winre/pipeline.py`) fail: WinRE uses
package-relative imports and ships no `__init__.py` entry script.

**B. `.env` next to the WinRE copy on the driver box**

```
/opt/winre/.env        # same 4 lines as §3; gitignored by WinRE
```

**C. Central keys file via `WINRE_ENV`**

```bash
export WINRE_ENV=/etc/winre.env     # file holding the 4 lines
```

## 5. If the driver box also has RevAI config

When the box that runs the WinRE driver already resolves an LLM configuration
(e.g. a RevAI install), WinRE still imports nothing implicitly: map the values
into `WINRE_LLM_*` at the **spawn site** — the process that launches the
driver. Substitute your own variable names on the right-hand side.

**Same key for both projects** (simplest):

```bash
export WINRE_LLM_BASE_URL="$REVAI_LLM_BASE_URL"
export WINRE_LLM_MODEL="$REVAI_LLM_MODEL"
export WINRE_LLM_API_KEY="$REVAI_LLM_API_KEY"
export WINRE_LLM_REASONING="$REVAI_LLM_REASONING"
cd /opt/winre
python3 -m winre.pipeline <sample> --driver remote --mode agentic
```

**Different keys per project** (independent rotation/quotas): reuse the
endpoint/model mapping, but source the key from WinRE's own surface (§3.1):

```bash
export WINRE_LLM_BASE_URL="$REVAI_LLM_BASE_URL"
export WINRE_LLM_MODEL="$REVAI_LLM_MODEL"
export WINRE_LLM_REASONING="$REVAI_LLM_REASONING"
export WINRE_LLM_API_KEY="$WINRE_KEY"   # the WinRE key - not RevAI's
cd /opt/winre
python3 -m winre.pipeline <sample> --driver remote --mode agentic
```

Warning: never map `$REVAI_LLM_API_KEY` into `WINRE_LLM_API_KEY` when the
projects use separate keys — that silently routes WinRE traffic onto the
RevAI key.

Notes:

- The mapping happens wherever the driver process is spawned. Today that is
  typically the operator host with a local WinRE checkout; installing the
  WinRE package on the RevAI VM (any Linux host with SSH to the FlareVM)
  works the same way — package + the 4 variables (or a `WINRE_ENV` file),
  nothing else.
- WinRE's side of the contract is only: *the 4 variables must be present in
  the driver process*. There is no implicit import of RevAI config.

## 6. What each mode needs (driver box / VM)

| Mode | LLM variables on driver box | Internet on driver box | Internet/keys on VM |
|---|---|---|---|
| `--mode static` | not needed (zero LLM calls) | not needed | no |
| `--mode agentic` | **required** | **required** (to the endpoint) | no |
| `--mode agentic --agentic-dbg` | **required** | **required** | no (debug tools run on VM) |
| `--dynamic` (detonation, any engine) | not needed (deterministic job) | not needed | no (air-gap enforced) |

A detonation with `--mode agentic --dynamic` therefore needs the LLM only
for the deep stage; the detonation itself never calls it.

## 7. Verify the wiring (on the driver box)

```bash
cd /opt/winre   # parent directory of the winre/ package
python3 -c "from winre.llm_client import available; print('LLM reachable:', available())"
```

Then a full run without touching the VM:

```bash
python3 -m winre.pipeline <local-sample-path> --driver remote --mode agentic --dry-llm
# dry-llm proves the remote path; drop --dry-llm to use the LLM
```

## 8. Troubleshooting

| Symptom (driver box) | Cause | Fix |
|---|---|---|
| `WINRE_LLM_API_KEY not set for remote endpoint` in deep META | variables not in the driver process env | wire §4/§5; re-check the spawn environment |
| `agent error: Connection error` | driver box cannot reach the endpoint | DNS/NAT/internet on the **driver box** (never the VM) |
| Deep source `deterministic_fallback` with a key configured | endpoint returned an error or timed out | test §7; check provider status |
| RevAI works, WinRE agentic falls back | RevAI config not translated | apply §5 at the spawn site |
| Keys present on the VM | leftover from testing phase | delete `C:\WinRE\.env` (and from the snapshot, then re-snapshot) |

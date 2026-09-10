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

## 4. Wiring options on the driver box

Any of these is sufficient — pick one per deployment:

**A. Exports in the launcher/service (recommended; keys never on disk)**

```bash
export WINRE_LLM_BASE_URL="https://<your-provider>/v1"
export WINRE_LLM_MODEL="<model>"
export WINRE_LLM_API_KEY="<key>"
export WINRE_LLM_REASONING="high"
python3 /opt/winre/winre/pipeline.py <sample> --driver remote --mode agentic
```

**B. `.env` next to the WinRE copy on the driver box**

```
/opt/winre/.env        # same 4 lines as §3; gitignored by WinRE
```

**C. Central keys file via `WINRE_ENV`**

```bash
export WINRE_ENV=/etc/winre.env     # file holding the 4 lines
```

## 5. If RevAI owns the config: the adapter snippet

RevAI already resolves its own LLM configuration. To make "the LLM configured
in RevAI" drive WinRE, map RevAI's values into `WINRE_LLM_*` in the
environment of the process that launches the WinRE driver — a few lines at
the spawn site, nothing more:

```bash
WINRE_LLM_BASE_URL="$REVAI_LLM_BASE_URL" \
WINRE_LLM_MODEL="$REVAI_LLM_MODEL" \
WINRE_LLM_API_KEY="$REVAI_LLM_API_KEY" \
WINRE_LLM_REASONING="$REVAI_LLM_REASONING" \
python3 /opt/winre/winre/pipeline.py <sample> --driver remote --mode agentic
```

Notes:

- Substitute your RevAI variable names on the right-hand side of the mapping.
- This bridge currently lives on the **RevAI side** (it owns the user's LLM
  settings). WinRE's side of the contract is only: *the 4 variables must be
  present in the driver process*.
- There is no implicit import of RevAI config by WinRE — export/translate
  explicitly at spawn time.

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

# PYRACLAW · CYBERSECURITY DIVISION
## Evidence-OS MCP — wiring runbook

Goal: make `pyraclaw-evidence-mcp-server` reachable from working sessions so the
ledger seal for `EC_RSFAPP_FT03_20260902` (and every capsule after it) stops
being PENDING. Nothing here is simulated: until preflight passes, the honest
status stays PENDING.

**Two values only the operator holds** (per the Trinity Spine runbook, the
bearer travels in a header — never in the URL or argv). The scheme is not a
value: `https://` is baked into the config and the preflight, so a cleartext
endpoint is unrepresentable.

```
export PYRA_EVIDENCE_HOST="<host[:port] of your Evidence-OS endpoint>"
export PYRA_EVIDENCE_PATH="/mcp"        # optional; default /mcp
export PYRA_EVIDENCE_BEARER="<bearer>"
```

If the server is not yet deployed over HTTPS (estate status 2026-09-01:
PENDING), deploy it first — every step below is wiring, not deployment.

### 0 · Preflight (read-only, always first)

```
python3 PYRACLAW_EVIDENCE/preflight_evidence_mcp.py
```

PASS = the endpoint answers MCP `initialize` (the negotiated protocol version
is validated and carried on every subsequent request) and lists all five
doctrine tools (`pyraclaw_verify_ledger`, `pyraclaw_seal_evidence`,
`pyraclaw_generate_verdict`, `pyraclaw_trace_lineage`, `pyraclaw_list_entries`).
The script never calls a tool — listing is not sealing — and it refuses HTTP
redirects outright, so the bearer is never re-sent toward a Location header.

### 1 · Local Claude Code (WSL / DD7Ai)

`.mcp.json` at the repo root already declares the server, with host, path and
bearer expanded from the environment — the bearer never lands in a file, and
the `https://` scheme is fixed in the config so no environment value can
downgrade the transport (the `.invalid` default host is IETF-reserved and can
never resolve, so an unset host fails closed at connect):

```json
{ "mcpServers": { "pyraclaw_evidence": {
    "type": "http",
    "url": "https://${PYRA_EVIDENCE_HOST:-evidence-os.invalid}${PYRA_EVIDENCE_PATH:-/mcp}",
    "headers": { "Authorization": "Bearer ${PYRA_EVIDENCE_BEARER}" } } } }
```

Put the exports in `~/.bashrc` (or a secrets manager), start a **new**
`claude` session in this repo, approve the project server when prompted, and
confirm with `/mcp`. MCP servers load at session start — an already-running
session cannot hot-mount one.

### 2 · Remote / web sessions (claude.ai)

Remote sessions receive MCP servers as claude.ai connectors:
Settings → Connectors → **Add custom connector** → name `pyraclaw_evidence`,
URL = the HTTPS endpoint. Use the server's OAuth if it offers it; a static
bearer belongs in the connector's auth configuration, never pasted into chat.
Then enable the connector for the session. (Checked 2026-09-02: no such
connector exists in the org yet.)

### 3 · Hermes gateways (the trinity estate)

Per `TRINITY_SPINE.md` §4 — order matters, trust before tools: preflight,
approve Pairing on 02/03, then `/mcp` → Add Server → Streamable-HTTP →
`pyraclaw_evidence` with the bearer from `PYRA_EVIDENCE_BEARER`; on 01:
`nemoclaw mcp add pyraclaw_evidence --http <HTTPS> --bearer-env PYRA_EVIDENCE_BEARER`.
Every OAuth grant is performed by the operator in the gateway's own browser flow.

### 4 · Seal the capsule (first session where preflight passes)

Doctrine order, no step skipped:

1. `pyraclaw_verify_ledger` — never seal onto an unverified chain.
2. `pyraclaw_seal_evidence` with the prepared args from
   `EC_RSFAPP_FT03_20260902/CAPSULE.json` → `seal_when_connected`
   (actor `byron/DD7`, tags `rsfapp · ip-disclosure · to-patent · fT_03`,
   `store_preview: false`, content hash
   `6df9545559dbbe10f175df93096a4510322b6585e394225e414c8fcb781f2364`).
3. `pyraclaw_verify_ledger` again → publish the returned `head_hash`
   externally (a commit in this directory is the established anchor path),
   and update `CAPSULE.json` → `pipeline_status.ledger_seal` from PENDING to
   the entry hash. PENDING is deleted only by a real seal.

*The ledger proves integrity and sequence, not content truth. A capsule is not
a patent filing; priority comes only from filing through counsel.*

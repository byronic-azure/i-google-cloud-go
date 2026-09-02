#!/usr/bin/env python3
# PYRACLAW · CYBERSECURITY DIVISION
# preflight_evidence_mcp — READ-ONLY liveness gate for the Evidence-OS MCP.
#
# Checks, in order, and fails closed:
#   1. PYRA_EVIDENCE_URL and PYRA_EVIDENCE_BEARER are set (bearer never in URL/argv).
#   2. The endpoint answers an MCP Streamable-HTTP `initialize` over HTTPS.
#   3. `tools/list` exposes the five doctrine tools:
#      pyraclaw_verify_ledger, pyraclaw_seal_evidence, pyraclaw_generate_verdict,
#      pyraclaw_trace_lineage, pyraclaw_list_entries.
#
# This script NEVER calls a tool. Listing is not sealing; a preflight that
# mutates the ledger would be a contradiction in terms. stdlib only.

import json
import os
import sys
import urllib.request

def die(msg: str) -> None:
    print(f"FAIL  {msg}")
    sys.exit(1)

def rpc(url: str, bearer: str, payload: dict, session: str | None) -> tuple[dict | None, str | None]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {bearer}",
        "MCP-Protocol-Version": "2025-06-18",
    }
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, json.dumps(payload).encode(), headers)
    with urllib.request.urlopen(req, timeout=20) as resp:
        sid = resp.headers.get("Mcp-Session-Id") or session
        body = resp.read().decode("utf-8", "replace")
        ctype = resp.headers.get("Content-Type", "")
    if "text/event-stream" in ctype:
        for line in body.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip()), sid
        return None, sid
    return (json.loads(body) if body.strip() else None), sid

def main() -> None:
    url = os.environ.get("PYRA_EVIDENCE_URL", "").strip()
    bearer = os.environ.get("PYRA_EVIDENCE_BEARER", "").strip()
    if not url:
        die("PYRA_EVIDENCE_URL is not set")
    if not url.lower().startswith("https://"):
        die("PYRA_EVIDENCE_URL must be HTTPS — the integrity boundary rides on transport")
    if not bearer:
        die("PYRA_EVIDENCE_BEARER is not set (export it; never place it in the URL or argv)")

    init = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "clientInfo": {"name": "pyraclaw-preflight", "version": "1.0.0"},
            "capabilities": {},
        },
    }
    try:
        reply, sid = rpc(url, bearer, init, None)
    except Exception as exc:
        die(f"initialize unreachable: {exc}")
    if not reply or "result" not in reply:
        die(f"initialize returned no result: {reply!r}")
    server = reply["result"].get("serverInfo", {})
    print(f"ok    initialize — {server.get('name', '?')} {server.get('version', '')}".rstrip())

    try:
        rpc(url, bearer, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
    except Exception:
        pass  # some servers return 202/empty here; tools/list is the real check

    try:
        reply, _ = rpc(url, bearer, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid)
    except Exception as exc:
        die(f"tools/list unreachable: {exc}")
    tools = {t.get("name") for t in (reply or {}).get("result", {}).get("tools", [])}
    required = {
        "pyraclaw_verify_ledger", "pyraclaw_seal_evidence", "pyraclaw_generate_verdict",
        "pyraclaw_trace_lineage", "pyraclaw_list_entries",
    }
    missing = sorted(required - tools)
    for name in sorted(required & tools):
        print(f"ok    tool — {name}")
    if missing:
        die(f"missing tools: {', '.join(missing)}")
    print("PASS  Evidence-OS MCP reachable and complete — wire it into a session and seal.")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# PYRACLAW · CYBERSECURITY DIVISION
# preflight_evidence_mcp — READ-ONLY liveness gate for the Evidence-OS MCP.
#
# Checks, in order, and fails closed:
#   1. PYRA_EVIDENCE_HOST (bare host[:port]) and PYRA_EVIDENCE_BEARER are set;
#      the URL is composed as https://HOST + PYRA_EVIDENCE_PATH (default /mcp),
#      so a cleartext http:// endpoint is unrepresentable and the bearer never
#      rides an unencrypted transport. Bearer never in URL/argv.
#   2. The endpoint answers an MCP Streamable-HTTP `initialize`; the server's
#      negotiated protocolVersion is validated and propagated to every
#      subsequent request. Redirects are refused outright — a bearer must
#      never follow a Location header to another origin.
#   3. `tools/list` exposes the five doctrine tools:
#      pyraclaw_verify_ledger, pyraclaw_seal_evidence, pyraclaw_generate_verdict,
#      pyraclaw_trace_lineage, pyraclaw_list_entries.
#
# This script NEVER calls a tool. Listing is not sealing; a preflight that
# mutates the ledger would be a contradiction in terms. stdlib only.

import json
import os
import sys
import urllib.error
import urllib.request

REQUESTED_PROTOCOL = "2025-06-18"


def die(msg: str) -> None:
    """Print a FAIL line and exit non-zero — the fail-closed exit path."""
    print(f"FAIL  {msg}")
    sys.exit(1)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every HTTP redirect: urllib would forward the Authorization
    header to the new location, so a redirect could hand the bearer to another
    origin or an http:// URL. Returning None turns 3xx into an HTTPError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return None so urllib raises instead of following the redirect."""
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def _sse_match(stream, want):
    """Parse an SSE byte stream incrementally and return the first JSON-RPC
    message whose "id" equals `want`, skipping interim notifications and
    responses to other requests (MCP servers may send those before the real
    response). Returns None if the stream ends without a match."""
    data_lines: list[str] = []
    for raw in stream:
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
        elif line == "" and data_lines:
            try:
                msg = json.loads("\n".join(data_lines))
            except ValueError:
                msg = None
            data_lines = []
            if isinstance(msg, dict) and msg.get("id") == want:
                return msg
    return None


def rpc(url: str, bearer: str, payload: dict, session, protocol: str):
    """POST one JSON-RPC payload to the MCP endpoint and return
    (reply, session_id). Sends the negotiated MCP-Protocol-Version, accepts
    plain-JSON or SSE responses (SSE parsed incrementally, matched on the
    request id), and converts any redirect into a hard failure so the bearer
    is never re-sent toward an unvetted destination."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {bearer}",
        "MCP-Protocol-Version": protocol,
    }
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, json.dumps(payload).encode(), headers)
    try:
        resp = _OPENER.open(req, timeout=20)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise RuntimeError(
                f"endpoint redirected (HTTP {exc.code}) — refusing to forward "
                "the bearer; point PYRA_EVIDENCE_HOST/PATH at the final URL"
            ) from exc
        raise
    with resp:
        sid = resp.headers.get("Mcp-Session-Id") or session
        ctype = resp.headers.get("Content-Type", "")
        if "text/event-stream" in ctype:
            want = payload.get("id")
            if want is None:
                return None, sid
            return _sse_match(resp, want), sid
        body = resp.read().decode("utf-8", "replace")
        return (json.loads(body) if body.strip() else None), sid


def _endpoint() -> str:
    """Compose the HTTPS endpoint from PYRA_EVIDENCE_HOST and
    PYRA_EVIDENCE_PATH, rejecting anything that could smuggle a scheme,
    userinfo, or path into the host. HTTPS is fixed by construction."""
    host = os.environ.get("PYRA_EVIDENCE_HOST", "").strip()
    if not host:
        die("PYRA_EVIDENCE_HOST is not set (bare host[:port]; scheme is fixed to https://)")
    if "://" in host or "/" in host or "@" in host or any(c.isspace() for c in host):
        die("PYRA_EVIDENCE_HOST must be a bare host[:port] — no scheme, path, userinfo, or whitespace")
    path = os.environ.get("PYRA_EVIDENCE_PATH", "/mcp").strip() or "/mcp"
    if not path.startswith("/") or any(c.isspace() for c in path):
        die("PYRA_EVIDENCE_PATH must start with '/' and contain no whitespace")
    return f"https://{host}{path}"


def main() -> None:
    """Run the three fail-closed checks and report PASS only when the
    Evidence-OS MCP is reachable, version-negotiated, and complete."""
    url = _endpoint()
    bearer = os.environ.get("PYRA_EVIDENCE_BEARER", "").strip()
    if not bearer:
        die("PYRA_EVIDENCE_BEARER is not set (export it; never place it in the URL or argv)")

    init = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": REQUESTED_PROTOCOL,
            "clientInfo": {"name": "pyraclaw-preflight", "version": "1.1.0"},
            "capabilities": {},
        },
    }
    try:
        reply, sid = rpc(url, bearer, init, None, REQUESTED_PROTOCOL)
    except Exception as exc:
        die(f"initialize unreachable: {exc}")
    if not reply or "result" not in reply:
        die(f"initialize returned no result: {reply!r}")
    negotiated = reply["result"].get("protocolVersion")
    if not isinstance(negotiated, str) or not negotiated:
        die("server returned no protocolVersion — refusing to guess the dialect")
    server = reply["result"].get("serverInfo", {})
    print(f"ok    initialize — {server.get('name', '?')} {server.get('version', '')} "
          f"· protocol {negotiated}".rstrip())

    try:
        rpc(url, bearer, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid, negotiated)
    except Exception:
        pass  # some servers return 202/empty here; tools/list is the real check

    try:
        reply, _ = rpc(url, bearer, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid, negotiated)
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

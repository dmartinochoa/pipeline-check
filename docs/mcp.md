# MCP server (`--serve`)

Pipeline-check ships a [Model Context Protocol](https://modelcontextprotocol.io/) server that lets MCP-aware AI clients (Claude Desktop, Claude Code, Cursor, Continue, Zed) drive scans and introspect the rule catalog directly. The server runs **locally on stdio**. It never reaches the network on its own, never sends telemetry, and exits when the client disconnects.

## Install

The server depends on the `mcp` Python SDK, which is shipped as an optional extra so the default install stays slim:

```bash
pip install 'pipeline-check[mcp]'
```

## Run

```bash
pipeline_check --serve
```

The process blocks until stdin closes. No scan flags are honored in this mode; each scan is an MCP `tools/call` request.

## Tools

The server exposes the following tools. Schemas are advertised through `tools/list` and validated on every call.

| Tool | What it does |
|------|---------------|
| `list_providers` | Every supported provider plus its path-argument requirement. |
| `list_checks` | Every registered security check, optionally scoped to one provider. |
| `explain_check` | Full reference for one check id (severity, OWASP/CWE/ESF, recommendation, docs note, known false-positive modes). |
| `list_chains` | Every registered attack chain. |
| `explain_chain` | Full reference for one attack chain id (MITRE ATT&CK techniques, kill-chain phase, references). |
| `list_standards` | Every registered compliance standard with control counts. |
| `scan` | Run a scan and return findings + score + chains. STRIDE codes attached to each finding. Honors `diff_base` for branch-scoped file filtering. |
| `inventory` | Component inventory for a provider + path. |
| `threat_model` | Run a scan and return the STRIDE-mapped Markdown threat-model document. See [threatmodel.md](threatmodel.md) for what's in the document. |
| `scan_markdown` | Run a scan and return the GitHub-Flavored Markdown summary (PR-comment shape). |
| `scan_pr_diff` | Compute the introduced / resolved / preserved finding delta between a git base ref and HEAD. Mirrors `--pr-diff`. Returns the structured delta plus the rendered Markdown PR comment. Not supported for `aws` or `scm` (no local BASE ref). |

Every tool returns JSON-serializable data. Errors come back as `{"error": "..."}` payloads, never as raw stack traces.

### Providers

The catalog covers every provider pipeline-check ships, including the
supply-chain providers (`npm`, `pypi`, `maven`), `argocd`, and the live
remote-SCM provider (`scm`, scanned via `scm_platform` + `scm_repo`
instead of a local path). `list_providers` is the source of truth.

## Claude Desktop config

Edit `claude_desktop_config.json` (Settings → Developer → Edit Config) and add:

```json
{
  "mcpServers": {
    "pipeline-check": {
      "command": "pipeline_check",
      "args": ["--serve"]
    }
  }
}
```

Restart Claude Desktop. The server's tools appear in the tool picker. Ask for things like:

- "Run pipeline-check against `.github/workflows/release.yml` and tell me which findings are CRITICAL."
- "What does `GHA-037` mean? What's the recommended fix?"
- "Generate a STRIDE threat model for the GitLab CI config in this repo."

## Claude Code

Add to `.mcp.json` in the repo root:

```json
{
  "mcpServers": {
    "pipeline-check": {
      "command": "pipeline_check",
      "args": ["--serve"]
    }
  }
}
```

The agent picks it up on the next session.

## Other clients

The server speaks standard MCP, so any client that talks the protocol works the same way. The pattern is always: launch `pipeline_check --serve` as a subprocess, communicate over its stdin/stdout.

## Architecture

The server is split across two files:

- `pipeline_check/mcp_server/tools.py` — pure functions that wrap the existing `Scanner` and registries. No `mcp` SDK import; can be called programmatically without the protocol layer.
- `pipeline_check/mcp_server/server.py` — binds the tool functions to MCP request types and runs the asyncio stdio loop.

The split means tool logic is unit-testable without spinning up an MCP loop, and the protocol layer can grow new transports (HTTP+SSE, websockets) without touching tool code.

## Limitations

- **Stdio only** for v1. HTTP+SSE / streamable-http transports are an additive change for a later release.
- **No persistent state** between calls. Each tool call is independent; the agent is responsible for threading context (e.g. running `list_checks` then `explain_check` for each interesting one).
- **Long scans block the call**. Tool functions run on the asyncio default executor, so other tool calls can interleave, but each individual scan synchronously waits for the scanner to finish.

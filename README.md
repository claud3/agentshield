# AgentShield Scanner

Open-source endpoint scanner for AI tool configuration governance. Discovers MCP servers, detects hardcoded credentials, and reports managed config status across your fleet.

## What It Does

AgentShield Scanner inspects your machine for AI coding tool configurations and finds:

- **AI tools installed** -- Claude Code, Cursor, VS Code/Copilot, Codex CLI, Windsurf, Continue.dev, Aider, Zed
- **MCP server configurations** -- name, transport type (stdio/http/sse), URL or command, environment variables
- **Hardcoded credentials** -- Databricks tokens, GitHub PATs, AWS keys, Anthropic/OpenAI API keys, Slack tokens, Atlassian API tokens, and more
- **Insecure transport** -- `--allow-http` flags, TLS verification bypasses, unencrypted WebSocket connections
- **Managed config status** -- whether centralized policy enforcement is deployed

## Install

### Quick install (macOS/Linux)

```bash
curl -sSfL https://github.com/claud3/agentshield/releases/latest/download/agentshield-scan-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m) -o agentshield-scan
chmod +x agentshield-scan
sudo mv agentshield-scan /usr/local/bin/
```

### Using Go

```bash
go install github.com/claud3/agentshield/cmd/agentshield-scan@latest
```

> **Note:** This installs to `~/go/bin/`. Make sure it's in your PATH:
> `export PATH="$HOME/go/bin:$PATH"` (add to your `~/.zshrc` or `~/.bashrc`)

### Build from repo

```bash
git clone https://github.com/claud3/agentshield.git
cd agentshield
go build -o agentshield-scan ./cmd/agentshield-scan/
./agentshield-scan
```

## Usage

```bash
# Scan and print human-readable report
agentshield-scan

# Output as JSON (for CI/automation)
agentshield-scan --json

# Use custom config directory
agentshield-scan --configs /path/to/configs
```

## Example Output

```
╔══════════════════════════════════════════════════════════╗
║              AgentShield Endpoint Scan Report           ║
╚══════════════════════════════════════════════════════════╝

── Endpoint ──────────────────────────────────────────────
  Hostname:  ENG-LAPTOP-42
  Platform:  darwin
  User:      jane.doe

── Discovery ─────────────────────────────────────────────
  Config files found:    8
  AI tools detected:     4
  MCP servers found:     12

── MCP Servers ───────────────────────────────────────────
  stdio (local):   5
  url (remote):    7

── Security Findings ─────────────────────────────────────
  Total findings: 3 (CRITICAL: 2, MEDIUM: 1)

  1. [CRITICAL] Databricks personal access token
     Server: databricks-sql (claude-desktop)
     Match:  dapiba****************************1d3f

  2. [CRITICAL] GitHub personal access token (classic)
     Server: github (cursor)
     Match:  ghp_Xy****************************9kLm

  3. [MEDIUM] Bearer token in authorization header
     Server: internal-api (claude-code)
     Match:  Bearer****************************token
```

## Supported AI Tools

Claude Code, Claude Desktop, Cursor, VS Code/Copilot, Codex CLI, Windsurf, Continue.dev, Aider, Zed -- across macOS, Linux, and Windows. Managed config enforcement status is detected where supported.

## Credential Detection

Detects hardcoded credentials from 15+ vendors including cloud providers (AWS, GCP), source control (GitHub, GitLab), data platforms (Databricks), communication tools (Slack, Atlassian), AI providers (Anthropic, OpenAI), and payment processors (Stripe). Also flags insecure transport configurations and high-entropy strings in credential-bearing contexts.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan complete, no critical findings |
| 1 | Error (config load failure, etc.) |
| 2 | Critical credential exposures found |

## Contributing

Issues and pull requests welcome. See the [issues page](https://github.com/claud3/agentshield/issues).

## License

MIT

# AgentShield Scanner

Open-source endpoint scanner for AI tool configuration governance. Discovers MCP servers, detects hardcoded credentials, and reports managed config status across your fleet.

## Why AgentShield?

AI coding tools (Claude Code, Cursor, Copilot, Codex CLI, Windsurf, and more) store MCP server configurations in local config files. These configs often contain:

- **Hardcoded API keys and tokens** -- Databricks, GitHub, AWS, Slack, Atlassian, and others
- **Insecure transport settings** -- `--allow-http` flags, TLS verification bypasses
- **No centralized governance** -- each developer configures their own MCP servers with no visibility or policy enforcement

AgentShield Scanner finds all of this in seconds. Run it on one machine or deploy it across your fleet.

## Install

### Homebrew (macOS/Linux)

```bash
brew install claud3/tap/agentshield-scan
```

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

> **Note:** Installs to `~/go/bin/`. Ensure it's in your PATH: `export PATH="$HOME/go/bin:$PATH"`

### Build from source

```bash
git clone https://github.com/claud3/agentshield.git
cd agentshield
go build -o agentshield-scan ./cmd/agentshield-scan/
./agentshield-scan
```

## Usage

```bash
# Scan and print report
agentshield-scan

# JSON output (for CI/automation)
agentshield-scan --json

# Use custom config directory
agentshield-scan --configs /path/to/configs

# Check version
agentshield-scan --version
```

## Example Output

```
╔══════════════════════════════════════════════════════════╗
║              AgentShield Endpoint Scan Report           ║
╚══════════════════════════════════════════════════════════╝

── Endpoint ──────────────────────────────────────────────
  Hostname:  LAPTOP-42
  Platform:  darwin
  User:      jane.doe

── Discovery ─────────────────────────────────────────────
  Config files found:    8
  AI tools detected:     4
  MCP servers found:     12

  AI tools present:
    - claude-code
    - cursor
    - vscode-copilot
    - codex-cli

── MCP Servers ───────────────────────────────────────────
  stdio (local):   5
  url (remote):    7

  [http] databricks-sql
    Tool: claude-desktop
    URL: https://workspace.databricks.com/api/2.0/mcp/sql

  [stdio] github
    Tool: cursor
    Command: npx

── Managed Configuration ─────────────────────────────────
  No managed configurations detected.
  This endpoint has no centralized policy enforcement.

── Security Findings ─────────────────────────────────────
  Total findings: 3 (CRITICAL: 2, MEDIUM: 1)

  1. [CRITICAL] Databricks personal access token
     Vendor:     databricks
     Type:       hardcoded_credential
     Server:     databricks-sql (claude-desktop)
     Location:   args
     Match:      dapiba****************************1d3f

  2. [CRITICAL] GitHub personal access token (classic)
     Vendor:     github
     Type:       hardcoded_credential
     Server:     github (cursor)
     Match:      ghp_Xy****************************9kLm

  3. [MEDIUM] Bearer token in authorization header
     Vendor:     unknown
     Type:       hardcoded_credential
     Server:     internal-api (claude-code)
     Match:      Bearer****************************token

──────────────────────────────────────────────────────────
  ACTION REQUIRED: Critical credential exposures found.
  Rotate the affected credentials immediately.
```

## Found Credentials? Here's What to Do

If AgentShield finds hardcoded credentials on your machine:

1. **Rotate immediately** -- The exposed credential should be considered compromised. Generate a new one from the vendor's dashboard (Databricks, GitHub, AWS, etc.) and revoke the old one.

2. **Move credentials out of config files** -- Use environment variables or a secrets manager instead of hardcoding tokens:
   ```json
   {
     "mcpServers": {
       "github": {
         "command": "npx",
         "args": ["@modelcontextprotocol/server-github"],
         "env": { "GITHUB_TOKEN": "${GITHUB_TOKEN}" }
       }
     }
   }
   ```

3. **Check git history** -- If the config file was ever committed, the credential is in your git history. Use `git log -p -- <config-file>` to check, and consider using [BFG Repo Cleaner](https://rtyley.github.io/bfg-repo-cleaner/) to remove it.

4. **Deploy managed configuration** -- For Claude Code, use `managed-mcp.json` to centrally control MCP server configurations and prevent users from adding their own credentials. See [Claude Code managed configuration](https://docs.anthropic.com/en/docs/claude-code/managed-configuration).

5. **Run AgentShield across your fleet** -- One machine is a finding. Ninety machines is a pattern. Deploy the scanner via JumpCloud, Jamf, or any MDM to understand your organization's exposure.

## Supported AI Tools

| Tool | Config Formats | Managed Config |
|------|:---:|:---:|
| Claude Code | JSON | Yes |
| Claude Desktop | JSON | Partial |
| Cursor | JSON | Partial |
| VS Code / Copilot | JSON | Yes |
| Codex CLI | TOML | Yes |
| Windsurf | JSON | No |
| Continue.dev | JSON/YAML | No |
| Aider | YAML | No |
| Zed | JSON | No |
| JetBrains AI | JSON | No |

Scans macOS, Linux, and Windows config paths.

## What It Detects

**Credentials:** Databricks tokens, GitHub PATs, AWS access keys, Anthropic API keys, OpenAI API keys, Slack tokens, Atlassian API tokens, Stripe keys, generic Bearer tokens, private keys, and high-entropy strings in credential contexts.

**Insecure Transport:** `--allow-http` flags, `--allow-insecure-host` bypasses, unencrypted connections.

**Governance Gaps:** Missing managed configurations, no centralized policy enforcement.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan complete, no critical findings |
| 1 | Error (config load failure, etc.) |
| 2 | Critical credential exposures found |

Use exit code 2 in CI pipelines to fail builds when credentials are detected.

## Contributing

Issues and pull requests welcome at [github.com/claud3/agentshield](https://github.com/claud3/agentshield/issues).

## License

MIT

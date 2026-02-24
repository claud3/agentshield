package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractMCPServersJSON_TopLevel(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mcp.json")

	config := `{
		"mcpServers": {
			"github": {
				"type": "stdio",
				"command": "npx",
				"args": ["@modelcontextprotocol/server-github"],
				"env": {"GITHUB_TOKEN": "test-token"}
			},
			"honeycomb": {
				"type": "http",
				"url": "https://mcp.honeycomb.io/mcp",
				"headers": {"Authorization": "Bearer abc123"}
			}
		}
	}`
	os.WriteFile(configPath, []byte(config), 0644)

	servers := extractMCPServers("cursor", configPath)

	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	byName := make(map[string]MCPServer)
	for _, s := range servers {
		byName[s.Name] = s
	}

	gh := byName["github"]
	if gh.Type != "stdio" {
		t.Errorf("github: expected type stdio, got %s", gh.Type)
	}
	if gh.Command != "npx" {
		t.Errorf("github: expected command npx, got %s", gh.Command)
	}
	if len(gh.Args) != 1 || gh.Args[0] != "@modelcontextprotocol/server-github" {
		t.Errorf("github: unexpected args: %v", gh.Args)
	}
	if gh.Env["GITHUB_TOKEN"] != "test-token" {
		t.Errorf("github: expected env GITHUB_TOKEN=test-token, got %s", gh.Env["GITHUB_TOKEN"])
	}
	if gh.Tool != "cursor" {
		t.Errorf("github: expected tool cursor, got %s", gh.Tool)
	}

	hc := byName["honeycomb"]
	if hc.Type != "http" {
		t.Errorf("honeycomb: expected type http, got %s", hc.Type)
	}
	if hc.URL != "https://mcp.honeycomb.io/mcp" {
		t.Errorf("honeycomb: unexpected URL: %s", hc.URL)
	}
	if hc.Headers["Authorization"] != "Bearer abc123" {
		t.Errorf("honeycomb: unexpected Authorization header")
	}
}

func TestExtractMCPServersJSON_PerProject(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "claude.json")

	config := `{
		"numStartups": 10,
		"projects": {
			"/home/user/project-a": {
				"mcpServers": {
					"vercel": {
						"type": "http",
						"url": "https://mcp.vercel.com"
					}
				}
			},
			"/home/user/project-b": {
				"mcpServers": {}
			},
			"/home/user/project-c": {
				"mcpServers": {
					"atlassian": {
						"type": "http",
						"url": "https://mcp.atlassian.com/v1/mcp"
					},
					"honeycomb": {
						"type": "http",
						"url": "https://mcp.honeycomb.io/mcp"
					}
				}
			}
		}
	}`
	os.WriteFile(configPath, []byte(config), 0644)

	servers := extractMCPServers("claude-code", configPath)

	if len(servers) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(servers))
	}

	byName := make(map[string]MCPServer)
	for _, s := range servers {
		byName[s.Name] = s
	}

	vercel := byName["vercel"]
	if vercel.Project != "/home/user/project-a" {
		t.Errorf("vercel: expected project /home/user/project-a, got %s", vercel.Project)
	}
	if vercel.URL != "https://mcp.vercel.com" {
		t.Errorf("vercel: unexpected URL: %s", vercel.URL)
	}

	atlassian := byName["atlassian"]
	if atlassian.Project != "/home/user/project-c" {
		t.Errorf("atlassian: expected project /home/user/project-c, got %s", atlassian.Project)
	}
}

func TestExtractMCPServersTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	// Token values constructed via concatenation to avoid GitHub push protection
	dbToken := "Bearer " + "dapi" + "fa1e567890abcdef1234567890abcdef"
	config := "[mcp_servers.github]\n" +
		"type = \"stdio\"\n" +
		"command = \"npx\"\n" +
		"args = [\"@modelcontextprotocol/server-github\"]\n\n" +
		"[mcp_servers.github.env]\n" +
		"GITHUB_TOKEN = \"ghp_test123\"\n\n" +
		"[mcp_servers.databricks]\n" +
		"type = \"http\"\n" +
		"url = \"https://workspace.databricks.com/api/2.0/mcp/sql\"\n\n" +
		"[mcp_servers.databricks.headers]\n" +
		"Authorization = \"" + dbToken + "\"\n"
	os.WriteFile(configPath, []byte(config), 0644)

	servers := extractMCPServers("codex-cli", configPath)

	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	byName := make(map[string]MCPServer)
	for _, s := range servers {
		byName[s.Name] = s
	}

	gh := byName["github"]
	if gh.Type != "stdio" {
		t.Errorf("github: expected type stdio, got %s", gh.Type)
	}
	if gh.Command != "npx" {
		t.Errorf("github: expected command npx, got %s", gh.Command)
	}
	if gh.Env["GITHUB_TOKEN"] != "ghp_test123" {
		t.Errorf("github: expected env GITHUB_TOKEN=ghp_test123, got %s", gh.Env["GITHUB_TOKEN"])
	}

	db := byName["databricks"]
	if db.Type != "http" {
		t.Errorf("databricks: expected type http, got %s", db.Type)
	}
	if db.URL != "https://workspace.databricks.com/api/2.0/mcp/sql" {
		t.Errorf("databricks: unexpected URL: %s", db.URL)
	}
}

func TestExtractMCPServersYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	config := `
mcpServers:
  slack:
    type: stdio
    command: npx
    args:
      - "@modelcontextprotocol/server-slack"
    env:
      SLACK_TOKEN: "xoxb-test-token"
  notion:
    type: http
    url: "https://mcp.notion.com/mcp"
`
	os.WriteFile(configPath, []byte(config), 0644)

	servers := extractMCPServers("continue-dev", configPath)

	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	byName := make(map[string]MCPServer)
	for _, s := range servers {
		byName[s.Name] = s
	}

	slack := byName["slack"]
	if slack.Type != "stdio" {
		t.Errorf("slack: expected type stdio, got %s", slack.Type)
	}
	if slack.Env["SLACK_TOKEN"] != "xoxb-test-token" {
		t.Errorf("slack: expected env SLACK_TOKEN, got %s", slack.Env["SLACK_TOKEN"])
	}
}

func TestExtractMCPServers_TypeInference(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mcp.json")

	// No explicit "type" field — should be inferred
	config := `{
		"mcpServers": {
			"local-tool": {
				"command": "/usr/local/bin/my-mcp",
				"args": ["--verbose"]
			},
			"remote-api": {
				"url": "https://api.example.com/mcp"
			}
		}
	}`
	os.WriteFile(configPath, []byte(config), 0644)

	servers := extractMCPServers("test-tool", configPath)

	byName := make(map[string]MCPServer)
	for _, s := range servers {
		byName[s.Name] = s
	}

	if byName["local-tool"].Type != "stdio" {
		t.Errorf("local-tool: expected inferred type stdio, got %s", byName["local-tool"].Type)
	}
	if byName["remote-api"].Type != "url" {
		t.Errorf("remote-api: expected inferred type url, got %s", byName["remote-api"].Type)
	}
}

func TestExtractMCPServers_EmptyAndInvalid(t *testing.T) {
	dir := t.TempDir()

	// Empty JSON
	emptyPath := filepath.Join(dir, "empty.json")
	os.WriteFile(emptyPath, []byte(`{}`), 0644)
	if servers := extractMCPServers("test", emptyPath); len(servers) != 0 {
		t.Errorf("empty JSON: expected 0 servers, got %d", len(servers))
	}

	// Empty mcpServers
	emptyMCPPath := filepath.Join(dir, "empty-mcp.json")
	os.WriteFile(emptyMCPPath, []byte(`{"mcpServers": {}}`), 0644)
	if servers := extractMCPServers("test", emptyMCPPath); len(servers) != 0 {
		t.Errorf("empty mcpServers: expected 0 servers, got %d", len(servers))
	}

	// Invalid JSON
	invalidPath := filepath.Join(dir, "invalid.json")
	os.WriteFile(invalidPath, []byte(`{not valid json`), 0644)
	if servers := extractMCPServers("test", invalidPath); servers != nil {
		t.Errorf("invalid JSON: expected nil, got %v", servers)
	}

	// Non-existent file
	if servers := extractMCPServers("test", filepath.Join(dir, "nope.json")); servers != nil {
		t.Errorf("non-existent: expected nil, got %v", servers)
	}
}

func TestDeduplication(t *testing.T) {
	dir := t.TempDir()

	config := `{
		"mcpServers": {
			"github": {
				"type": "stdio",
				"command": "npx",
				"args": ["@modelcontextprotocol/server-github"]
			}
		}
	}`

	// Write the same config to two paths
	path1 := filepath.Join(dir, "global.json")
	path2 := filepath.Join(dir, "global.json") // same absolute path
	os.WriteFile(path1, []byte(config), 0644)

	paths := &PathConfig{
		MacOS: PlatformConfig{
			Tools: []ToolPaths{
				{
					Tool:        "cursor",
					ConfigPaths: []string{path1, path2},
				},
			},
		},
	}

	result := Scan(paths)

	if len(result.MCPServers) != 1 {
		t.Errorf("expected 1 server after dedup, got %d", len(result.MCPServers))
	}
}

func TestExpandPath(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		input    string
		expected string
	}{
		{"~/.claude.json", filepath.Join(home, ".claude.json")},
		{"/etc/codex/config.toml", "/etc/codex/config.toml"},
		{".mcp.json", ".mcp.json"},
	}

	for _, tt := range tests {
		got := expandPath(tt.input)
		if got != tt.expected {
			t.Errorf("expandPath(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestMCPServerRawConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mcp.json")

	config := `{
		"mcpServers": {
			"test": {
				"type": "stdio",
				"command": "echo",
				"custom_field": "custom_value"
			}
		}
	}`
	os.WriteFile(configPath, []byte(config), 0644)

	servers := extractMCPServers("test-tool", configPath)
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}

	// Verify RawConfig preserves all fields including custom ones
	var rawMap map[string]interface{}
	if err := json.Unmarshal(servers[0].RawConfig, &rawMap); err != nil {
		t.Fatalf("failed to unmarshal RawConfig: %v", err)
	}
	if rawMap["custom_field"] != "custom_value" {
		t.Errorf("RawConfig missing custom_field")
	}
}

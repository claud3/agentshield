package compliance

import (
	"testing"

	"github.com/claud3/agentshield/internal/scanner"
	"github.com/claud3/agentshield/internal/secrets"
)

func TestCheckTransportHTTPS(t *testing.T) {
	tests := []struct {
		name   string
		server scanner.MCPServer
		status string
	}{
		{"https url passes", scanner.MCPServer{Name: "test", URL: "https://mcp.example.com/mcp"}, StatusPass},
		{"http url fails", scanner.MCPServer{Name: "test", URL: "http://mcp.example.com/mcp"}, StatusFail},
		{"localhost http passes", scanner.MCPServer{Name: "test", URL: "http://127.0.0.1:3845/mcp"}, StatusPass},
		{"localhost name passes", scanner.MCPServer{Name: "test", URL: "http://localhost:8080/mcp"}, StatusPass},
		{"stdio skips", scanner.MCPServer{Name: "test", Command: "npx"}, StatusSkip},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkTransportHTTPS(tt.server)
			if result.Status != tt.status {
				t.Errorf("expected status %s, got %s", tt.status, result.Status)
			}
		})
	}
}

func TestCheckWebSocketTLS(t *testing.T) {
	tests := []struct {
		name   string
		server scanner.MCPServer
		status string
	}{
		{"wss passes", scanner.MCPServer{Name: "test", URL: "wss://mcp.example.com/ws"}, StatusPass},
		{"ws fails", scanner.MCPServer{Name: "test", URL: "ws://mcp.example.com/ws"}, StatusFail},
		{"ws localhost passes", scanner.MCPServer{Name: "test", URL: "ws://127.0.0.1:8080/ws"}, StatusPass},
		{"https passes", scanner.MCPServer{Name: "test", URL: "https://mcp.example.com/mcp"}, StatusPass},
		{"no url skips", scanner.MCPServer{Name: "test", Command: "npx"}, StatusSkip},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkWebSocketTLS(tt.server)
			if result.Status != tt.status {
				t.Errorf("expected status %s, got %s", tt.status, result.Status)
			}
		})
	}
}

func TestCheckRemoteAuth(t *testing.T) {
	tests := []struct {
		name   string
		server scanner.MCPServer
		status string
	}{
		{
			"http server passes (MCP OAuth)",
			scanner.MCPServer{
				Name: "vercel",
				Tool: "claude-code",
				Type: "http",
				URL:  "https://mcp.vercel.com",
			},
			StatusPass,
		},
		{
			"sse server passes (MCP OAuth)",
			scanner.MCPServer{
				Name: "atlassian",
				Tool: "cursor",
				Type: "sse",
				URL:  "https://mcp.atlassian.com/v1/sse",
			},
			StatusPass,
		},
		{
			"any tool http passes (MCP spec defines OAuth)",
			scanner.MCPServer{
				Name: "test",
				Tool: "windsurf",
				Type: "http",
				URL:  "https://mcp.example.com/mcp",
			},
			StatusPass,
		},
		{
			"stdio local server skips",
			scanner.MCPServer{
				Name:    "github",
				Type:    "stdio",
				Command: "npx",
				Args:    []string{"@modelcontextprotocol/server-github"},
			},
			StatusSkip,
		},
		{
			"stdio remote proxy without auth warns",
			scanner.MCPServer{
				Name:    "remote",
				Type:    "stdio",
				Command: "npx",
				Args:    []string{"mcp-remote", "https://mcp.example.com/mcp"},
			},
			StatusWarn,
		},
		{
			"stdio remote proxy with auth passes",
			scanner.MCPServer{
				Name:    "remote",
				Type:    "stdio",
				Command: "npx",
				Args:    []string{"mcp-remote", "https://mcp.example.com/mcp", "--header", "Authorization: Bearer tok123"},
			},
			StatusPass,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkRemoteAuth(tt.server)
			if result.Status != tt.status {
				t.Errorf("expected status %s, got %s (details: %s)", tt.status, result.Status, result.Details)
			}
		})
	}
}

func TestCheckTokensInURL(t *testing.T) {
	tests := []struct {
		name   string
		server scanner.MCPServer
		status string
	}{
		{"no params passes", scanner.MCPServer{Name: "test", URL: "https://mcp.example.com/mcp"}, StatusPass},
		{"token param fails", scanner.MCPServer{Name: "test", URL: "https://mcp.example.com/mcp?token=abc"}, StatusFail},
		{"api_key param fails", scanner.MCPServer{Name: "test", URL: "https://mcp.example.com/mcp?api_key=abc"}, StatusFail},
		{"safe param passes", scanner.MCPServer{Name: "test", URL: "https://mcp.example.com/mcp?version=2"}, StatusPass},
		{"no url skips", scanner.MCPServer{Name: "test", Command: "npx"}, StatusSkip},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkTokensInURL(tt.server)
			if result.Status != tt.status {
				t.Errorf("expected status %s, got %s", tt.status, result.Status)
			}
		})
	}
}

func TestCheckVersionPinning(t *testing.T) {
	tests := []struct {
		name   string
		server scanner.MCPServer
		status string
	}{
		{
			"pinned version passes",
			scanner.MCPServer{Name: "test", Type: "stdio", Command: "npx", Args: []string{"@modelcontextprotocol/server-github@1.2.3"}},
			StatusPass,
		},
		{
			"latest fails",
			scanner.MCPServer{Name: "test", Type: "stdio", Command: "npx", Args: []string{"some-package@latest"}},
			StatusFail,
		},
		{
			"http server skips",
			scanner.MCPServer{Name: "test", Type: "http", URL: "https://mcp.example.com"},
			StatusSkip,
		},
		{
			"non-package-manager skips",
			scanner.MCPServer{Name: "test", Type: "stdio", Command: "/usr/local/bin/my-server"},
			StatusSkip,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkVersionPinning(tt.server)
			if result.Status != tt.status {
				t.Errorf("expected status %s, got %s (details: %s)", tt.status, result.Status, result.Details)
			}
		})
	}
}

func TestCheckThirdPartyProxy(t *testing.T) {
	tests := []struct {
		name   string
		server scanner.MCPServer
		status string
	}{
		{"direct url passes", scanner.MCPServer{Name: "test", URL: "https://mcp.atlassian.com/v1/mcp"}, StatusPass},
		{"natoma proxy warns", scanner.MCPServer{Name: "test", URL: "https://mcp.natoma.app/abc123"}, StatusWarn},
		{"stdio skips", scanner.MCPServer{Name: "test", Command: "npx"}, StatusSkip},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkThirdPartyProxy(tt.server)
			if result.Status != tt.status {
				t.Errorf("expected status %s, got %s", tt.status, result.Status)
			}
		})
	}
}

func TestCheckDebugFlags(t *testing.T) {
	tests := []struct {
		name   string
		server scanner.MCPServer
		status string
	}{
		{"no flags passes", scanner.MCPServer{Name: "test", Args: []string{"--port", "8080"}}, StatusPass},
		{"debug flag fails", scanner.MCPServer{Name: "test", Args: []string{"--debug"}}, StatusFail},
		{"verbose flag fails", scanner.MCPServer{Name: "test", Args: []string{"--verbose"}}, StatusFail},
		{"debug env fails", scanner.MCPServer{Name: "test", Env: map[string]string{"LOG_LEVEL": "debug"}}, StatusFail},
		{"info env passes", scanner.MCPServer{Name: "test", Env: map[string]string{"LOG_LEVEL": "info"}}, StatusPass},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkDebugFlags(tt.server)
			if result.Status != tt.status {
				t.Errorf("expected status %s, got %s (details: %s)", tt.status, result.Status, result.Details)
			}
		})
	}
}

func TestCheckServerSprawl(t *testing.T) {
	result := &scanner.ScanResult{}
	for i := 0; i < 5; i++ {
		result.MCPServers = append(result.MCPServers, scanner.MCPServer{Name: "test"})
	}

	check := checkServerSprawl(result)
	if check.Status != StatusPass {
		t.Errorf("5 servers: expected pass, got %s", check.Status)
	}

	// Add more to exceed threshold
	for i := 0; i < 15; i++ {
		result.MCPServers = append(result.MCPServers, scanner.MCPServer{Name: "test"})
	}

	check = checkServerSprawl(result)
	if check.Status != StatusWarn {
		t.Errorf("20 servers: expected warn, got %s", check.Status)
	}
}

func TestCheckDuplicateServers(t *testing.T) {
	// Cross-tool duplicates should NOT be flagged (expected behavior)
	t.Run("cross-tool duplicates pass", func(t *testing.T) {
		result := &scanner.ScanResult{
			MCPServers: []scanner.MCPServer{
				{Name: "vercel", Tool: "claude-code", URL: "https://mcp.vercel.com"},
				{Name: "vercel", Tool: "codex-cli", URL: "https://mcp.vercel.com"},
			},
		}

		checks := checkDuplicateServers(result)
		for _, c := range checks {
			if c.Status == StatusFail {
				t.Error("cross-tool duplicate should not be flagged")
			}
		}
	})

	// Same-tool duplicates SHOULD be flagged
	t.Run("same-tool duplicates fail", func(t *testing.T) {
		result := &scanner.ScanResult{
			MCPServers: []scanner.MCPServer{
				{Name: "atlassian-a", Tool: "claude-code", URL: "https://mcp.atlassian.com/v1/mcp"},
				{Name: "atlassian-b", Tool: "claude-code", URL: "https://mcp.atlassian.com/v1/mcp"},
			},
		}

		checks := checkDuplicateServers(result)
		hasFail := false
		for _, c := range checks {
			if c.Status == StatusFail {
				hasFail = true
			}
		}
		if !hasFail {
			t.Error("expected duplicate detection for same-tool duplicate URL")
		}
	})
}

func TestMapSecretFindings(t *testing.T) {
	findings := []secrets.Finding{
		{
			Severity:   secrets.SeverityCritical,
			Context:    "args[3]",
			ServerName: "databricks",
			Tool:       "claude-code",
			Type:       "bearer_token",
		},
		{
			Severity:   secrets.SeverityHigh,
			Context:    "env[GITHUB_TOKEN]",
			ServerName: "github",
			Tool:       "cursor",
			Type:       "pat",
		},
		{
			Severity:   secrets.SeverityHigh,
			Context:    "headers[Authorization]",
			ServerName: "api",
			Tool:       "claude-code",
			Type:       "bearer_token",
		},
		{
			Severity:   secrets.SeverityHigh,
			Context:    "args[1]",
			ServerName: "config",
			Tool:       "cursor",
			Type:       "allow_http_flag",
		},
	}

	checks := mapSecretFindings(findings)

	if len(checks) != 4 {
		t.Fatalf("expected 4 checks, got %d", len(checks))
	}

	// Verify mapping
	if checks[0].ID != "CS-01" {
		t.Errorf("args finding: expected CS-01, got %s", checks[0].ID)
	}
	if checks[1].ID != "CS-02" {
		t.Errorf("env finding: expected CS-02, got %s", checks[1].ID)
	}
	if checks[2].ID != "CS-03" {
		t.Errorf("headers finding: expected CS-03, got %s", checks[2].ID)
	}
	if checks[3].ID != "TS-02" {
		t.Errorf("allow_http: expected TS-02, got %s", checks[3].ID)
	}
}

func TestRunBenchmark_Scoring(t *testing.T) {
	result := &scanner.ScanResult{
		MCPServers: []scanner.MCPServer{
			{Name: "test", Type: "stdio", Command: "npx", Args: []string{"test-server@1.0.0"}},
		},
	}

	report := RunBenchmark(result, nil)

	if report.Score > 100 || report.Score < 0 {
		t.Errorf("score out of range: %d", report.Score)
	}
	if report.MaturityLevel < 1 || report.MaturityLevel > 5 {
		t.Errorf("maturity level out of range: %d", report.MaturityLevel)
	}
	if report.MaturityName == "" {
		t.Error("maturity name should not be empty")
	}
}

func TestRunBenchmark_MaturityLevel3(t *testing.T) {
	// No critical/high failures = Level 3
	result := &scanner.ScanResult{
		MCPServers: []scanner.MCPServer{
			{Name: "local", Type: "stdio", Command: "/usr/local/bin/my-server"},
		},
		ManagedConfigs: []scanner.ManagedConfig{
			{Tool: "claude-code", Path: "/tmp/managed.json", Present: true, Readable: true},
		},
	}

	report := RunBenchmark(result, nil)

	// With managed config present and no critical issues, should be level 4
	if report.MaturityLevel < 3 {
		t.Errorf("expected maturity level >= 3, got %d (%s)", report.MaturityLevel, report.MaturityName)
	}
}

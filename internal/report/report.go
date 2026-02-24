package report

import (
	"fmt"
	"strings"

	"github.com/claud3/agentshield/internal/scanner"
	"github.com/claud3/agentshield/internal/secrets"
)

// Result combines scan results and security findings.
type Result struct {
	ScanResult *scanner.ScanResult `json:"scan_result"`
	Findings   []secrets.Finding   `json:"findings"`
}

// HasCriticalFindings returns true if any finding is critical severity.
func (r Result) HasCriticalFindings() bool {
	for _, f := range r.Findings {
		if f.Severity == secrets.SeverityCritical {
			return true
		}
	}
	return false
}

// PrintTerminal outputs a human-readable report to stdout.
func PrintTerminal(r Result) {
	printHeader()
	printScanSummary(r.ScanResult)
	printMCPServers(r.ScanResult)
	printManagedConfigs(r.ScanResult)
	printFindings(r.Findings)
	printFooter(r)
}

func printHeader() {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║              AgentShield Endpoint Scan Report           ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func printScanSummary(result *scanner.ScanResult) {
	fmt.Println("── Endpoint ──────────────────────────────────────────────")
	fmt.Printf("  Hostname:  %s\n", result.Hostname)
	fmt.Printf("  Platform:  %s\n", result.Platform)
	fmt.Printf("  User:      %s\n", result.Username)
	fmt.Println()

	configsFound := 0
	toolsWithConfigs := make(map[string]bool)
	for _, tc := range result.ToolConfigs {
		if tc.Exists {
			configsFound++
			toolsWithConfigs[tc.Tool] = true
		}
	}

	fmt.Println("── Discovery ─────────────────────────────────────────────")
	fmt.Printf("  Config files found:    %d\n", configsFound)
	fmt.Printf("  AI tools detected:     %d\n", len(toolsWithConfigs))
	fmt.Printf("  MCP servers found:     %d\n", len(result.MCPServers))
	fmt.Println()

	if len(toolsWithConfigs) > 0 {
		fmt.Println("  AI tools present:")
		for tool := range toolsWithConfigs {
			fmt.Printf("    - %s\n", tool)
		}
		fmt.Println()
	}
}

func printMCPServers(result *scanner.ScanResult) {
	if len(result.MCPServers) == 0 {
		return
	}

	fmt.Println("── MCP Servers ───────────────────────────────────────────")

	stdioCount := 0
	urlCount := 0
	for _, s := range result.MCPServers {
		if s.Type == "stdio" {
			stdioCount++
		} else {
			urlCount++
		}
	}

	fmt.Printf("  stdio (local):   %d\n", stdioCount)
	fmt.Printf("  url (remote):    %d\n", urlCount)
	fmt.Println()

	for _, s := range result.MCPServers {
		fmt.Printf("  [%s] %s\n", s.Type, s.Name)
		fmt.Printf("    Tool: %s\n", s.Tool)
		if s.Project != "" {
			fmt.Printf("    Project: %s\n", s.Project)
		}
		if s.Command != "" {
			fmt.Printf("    Command: %s\n", s.Command)
		}
		if s.URL != "" {
			fmt.Printf("    URL: %s\n", s.URL)
		}
		fmt.Println()
	}
}

func printManagedConfigs(result *scanner.ScanResult) {
	hasManaged := false
	for _, mc := range result.ManagedConfigs {
		if mc.Present {
			hasManaged = true
			break
		}
	}

	fmt.Println("── Managed Configuration ─────────────────────────────────")
	if !hasManaged {
		fmt.Println("  No managed configurations detected.")
		fmt.Println("  This endpoint has no centralized policy enforcement.")
	} else {
		for _, mc := range result.ManagedConfigs {
			if mc.Present {
				fmt.Printf("  [PRESENT] %s: %s\n", mc.Tool, mc.Path)
			}
		}
	}
	fmt.Println()
}

func printFindings(findings []secrets.Finding) {
	fmt.Println("── Security Findings ─────────────────────────────────────")

	if len(findings) == 0 {
		fmt.Println("  No credential exposures detected.")
		fmt.Println()
		return
	}

	critical := 0
	high := 0
	medium := 0
	low := 0
	for _, f := range findings {
		switch f.Severity {
		case secrets.SeverityCritical:
			critical++
		case secrets.SeverityHigh:
			high++
		case secrets.SeverityMedium:
			medium++
		case secrets.SeverityLow:
			low++
		}
	}

	fmt.Printf("  Total findings: %d", len(findings))
	parts := []string{}
	if critical > 0 {
		parts = append(parts, fmt.Sprintf("CRITICAL: %d", critical))
	}
	if high > 0 {
		parts = append(parts, fmt.Sprintf("HIGH: %d", high))
	}
	if medium > 0 {
		parts = append(parts, fmt.Sprintf("MEDIUM: %d", medium))
	}
	if low > 0 {
		parts = append(parts, fmt.Sprintf("LOW: %d", low))
	}
	if len(parts) > 0 {
		fmt.Printf(" (%s)", strings.Join(parts, ", "))
	}
	fmt.Println()
	fmt.Println()

	for i, f := range findings {
		severityTag := strings.ToUpper(f.Severity)
		fmt.Printf("  %d. [%s] %s\n", i+1, severityTag, f.Description)
		fmt.Printf("     Vendor:     %s\n", f.Vendor)
		fmt.Printf("     Type:       %s\n", f.Type)
		fmt.Printf("     Server:     %s (%s)\n", f.ServerName, f.Tool)
		fmt.Printf("     Location:   %s\n", f.Location)
		fmt.Printf("     Context:    %s\n", f.Context)
		fmt.Printf("     Match:      %s\n", f.Match)
		fmt.Println()
	}
}

func printFooter(r Result) {
	fmt.Println("──────────────────────────────────────────────────────────")
	if r.HasCriticalFindings() {
		fmt.Println("  ACTION REQUIRED: Critical credential exposures found.")
		fmt.Println("  Rotate the affected credentials immediately.")
	} else if len(r.Findings) > 0 {
		fmt.Println("  Review the findings above and address as needed.")
	} else {
		fmt.Println("  Scan complete. No immediate issues found.")
	}
	fmt.Println()
	fmt.Println("  Learn more: https://github.com/claud3/agentshield")
	fmt.Println()
}

package report

import (
	"fmt"
	"os"
	"strings"

	"github.com/claud3/agentshield/internal/scanner"
	"github.com/claud3/agentshield/internal/secrets"
	"golang.org/x/term"
)

// ANSI color codes
var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

func init() {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		colorReset = ""
		colorRed = ""
		colorGreen = ""
		colorYellow = ""
		colorBlue = ""
		colorCyan = ""
		colorBold = ""
		colorDim = ""
	}
}

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
	fmt.Printf("%s╔══════════════════════════════════════════════════════════╗%s\n", colorCyan, colorReset)
	fmt.Printf("%s║%s%s              AgentShield Endpoint Scan Report           %s%s║%s\n", colorCyan, colorReset, colorBold, colorReset, colorCyan, colorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════╝%s\n", colorCyan, colorReset)
	fmt.Println()
}

func printScanSummary(result *scanner.ScanResult) {
	fmt.Printf("%s── Endpoint ──────────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Printf("  Hostname:  %s%s%s\n", colorBold, result.Hostname, colorReset)
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

	fmt.Printf("%s── Discovery ─────────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Printf("  Config files found:    %s%d%s\n", colorBold, configsFound, colorReset)
	fmt.Printf("  AI tools detected:     %s%d%s\n", colorBold, len(toolsWithConfigs), colorReset)
	fmt.Printf("  MCP servers found:     %s%d%s\n", colorBold, len(result.MCPServers), colorReset)
	fmt.Println()

	if len(toolsWithConfigs) > 0 {
		fmt.Println("  AI tools present:")
		for tool := range toolsWithConfigs {
			fmt.Printf("    %s- %s%s\n", colorCyan, tool, colorReset)
		}
		fmt.Println()
	}
}

func printMCPServers(result *scanner.ScanResult) {
	if len(result.MCPServers) == 0 {
		return
	}

	fmt.Printf("%s── MCP Servers ───────────────────────────────────────────%s\n", colorDim, colorReset)

	stdioCount := 0
	httpCount := 0
	sseCount := 0
	for _, s := range result.MCPServers {
		switch s.Type {
		case "stdio":
			stdioCount++
		case "sse":
			sseCount++
		default:
			httpCount++
		}
	}

	fmt.Printf("  stdio (local):   %s%d%s\n", colorBold, stdioCount, colorReset)
	fmt.Printf("  http (remote):   %s%d%s\n", colorBold, httpCount, colorReset)
	if sseCount > 0 {
		fmt.Printf("  sse (remote):    %s%d%s\n", colorBold, sseCount, colorReset)
	}
	fmt.Println()

	for _, s := range result.MCPServers {
		typeColor := colorBlue
		switch s.Type {
		case "stdio":
			typeColor = colorCyan
		case "sse":
			typeColor = colorYellow
		}
		fmt.Printf("  %s[%s]%s %s%s%s\n", typeColor, s.Type, colorReset, colorBold, s.Name, colorReset)
		fmt.Printf("    %sTool:%s %s\n", colorDim, colorReset, s.Tool)
		if s.Project != "" {
			fmt.Printf("    %sProject:%s %s\n", colorDim, colorReset, s.Project)
		}
		if s.Command != "" {
			fmt.Printf("    %sCommand:%s %s\n", colorDim, colorReset, s.Command)
		}
		if s.URL != "" {
			fmt.Printf("    %sURL:%s %s\n", colorDim, colorReset, s.URL)
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

	fmt.Printf("%s── Managed Configuration ─────────────────────────────────%s\n", colorDim, colorReset)
	if !hasManaged {
		fmt.Printf("  %sNo managed configurations detected.%s\n", colorYellow, colorReset)
		fmt.Printf("  %sThis endpoint has no centralized policy enforcement.%s\n", colorDim, colorReset)
	} else {
		for _, mc := range result.ManagedConfigs {
			if mc.Present {
				fmt.Printf("  %s[PRESENT]%s %s: %s\n", colorGreen, colorReset, mc.Tool, mc.Path)
			}
		}
	}
	fmt.Println()
}

func printFindings(findings []secrets.Finding) {
	fmt.Printf("%s── Security Findings ─────────────────────────────────────%s\n", colorDim, colorReset)

	if len(findings) == 0 {
		fmt.Printf("  %sNo credential exposures detected.%s\n", colorGreen, colorReset)
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

	fmt.Printf("  Total findings: %s%d%s", colorBold, len(findings), colorReset)
	parts := []string{}
	if critical > 0 {
		parts = append(parts, fmt.Sprintf("%sCRITICAL: %d%s", colorRed, critical, colorReset))
	}
	if high > 0 {
		parts = append(parts, fmt.Sprintf("%sHIGH: %d%s", colorRed, high, colorReset))
	}
	if medium > 0 {
		parts = append(parts, fmt.Sprintf("%sMEDIUM: %d%s", colorYellow, medium, colorReset))
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
		tagColor := colorYellow
		switch f.Severity {
		case secrets.SeverityCritical:
			tagColor = colorRed
		case secrets.SeverityHigh:
			tagColor = colorRed
		case secrets.SeverityLow:
			tagColor = colorDim
		}
		fmt.Printf("  %d. %s[%s]%s %s\n", i+1, tagColor, severityTag, colorReset, f.Description)
		fmt.Printf("     %sVendor:%s     %s\n", colorDim, colorReset, f.Vendor)
		fmt.Printf("     %sType:%s       %s\n", colorDim, colorReset, f.Type)
		fmt.Printf("     %sServer:%s     %s (%s)\n", colorDim, colorReset, f.ServerName, f.Tool)
		fmt.Printf("     %sLocation:%s   %s\n", colorDim, colorReset, f.Location)
		fmt.Printf("     %sContext:%s    %s\n", colorDim, colorReset, f.Context)
		fmt.Printf("     %sMatch:%s      %s\n", colorDim, colorReset, f.Match)
		fmt.Println()
	}
}

func printFooter(r Result) {
	fmt.Printf("%s──────────────────────────────────────────────────────────%s\n", colorDim, colorReset)
	if r.HasCriticalFindings() {
		fmt.Printf("  %s%sACTION REQUIRED:%s Critical credential exposures found.\n", colorBold, colorRed, colorReset)
		fmt.Printf("  Rotate the affected credentials immediately.\n")
	} else if len(r.Findings) > 0 {
		fmt.Printf("  %sReview the findings above and address as needed.%s\n", colorYellow, colorReset)
	} else {
		fmt.Printf("  %sScan complete. No immediate issues found.%s\n", colorGreen, colorReset)
	}
	fmt.Println()
	fmt.Printf("  Learn more: %shttps://github.com/claud3/agentshield%s\n", colorDim, colorReset)
	fmt.Println()
}

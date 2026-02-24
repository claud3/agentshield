package compliance

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/claud3/agentshield/internal/scanner"
	"github.com/claud3/agentshield/internal/secrets"
)

// Check severity constants.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
	SevInfo     = "info"
)

// Check status constants.
const (
	StatusPass = "pass"
	StatusFail = "fail"
	StatusWarn = "warn"
	StatusSkip = "skip"
)

// CheckResult represents the outcome of a single benchmark check.
type CheckResult struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Details     string `json:"details,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
	Tool        string `json:"tool,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// BenchmarkReport contains all check results and the computed maturity level.
type BenchmarkReport struct {
	Checks        []CheckResult    `json:"checks"`
	Score         int              `json:"score"`
	MaturityLevel int              `json:"maturity_level"`
	MaturityName  string           `json:"maturity_name"`
	Summary       CategorySummary  `json:"summary"`
}

// CategorySummary counts pass/fail per category.
type CategorySummary struct {
	CredentialSecurity CategoryCount `json:"credential_security"`
	TransportSecurity  CategoryCount `json:"transport_security"`
	Authentication     CategoryCount `json:"authentication"`
	SupplyChain        CategoryCount `json:"supply_chain"`
	Governance         CategoryCount `json:"governance"`
	OperationalHygiene CategoryCount `json:"operational_hygiene"`
}

// CategoryCount tracks pass/fail/warn counts.
type CategoryCount struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Warn int `json:"warn"`
	Skip int `json:"skip"`
}

// Known third-party proxy domains.
var knownProxyDomains = []string{
	"mcp.natoma.app",
	"natoma.app",
}

// Patterns that indicate debug/verbose flags.
var debugPatterns = []string{
	"--debug", "--verbose", "-vvv", "--log-level=debug",
	"--log-level=trace", "-v",
}

var debugEnvPatterns = []string{
	"DEBUG", "LOG_LEVEL",
}

// unpinnedVersionPattern matches @latest or bare package names without version.
var unpinnedLatest = regexp.MustCompile(`@latest\b`)

// RunBenchmark executes all L1 benchmark checks and returns the report.
func RunBenchmark(result *scanner.ScanResult, findings []secrets.Finding) *BenchmarkReport {
	report := &BenchmarkReport{
		Score: 100,
	}

	// Map existing secrets findings to CS/TS benchmark checks
	report.Checks = append(report.Checks, mapSecretFindings(findings)...)

	// Run additional checks per MCP server
	for _, server := range result.MCPServers {
		report.Checks = append(report.Checks, checkTransportHTTPS(server))
		report.Checks = append(report.Checks, checkWebSocketTLS(server))
		report.Checks = append(report.Checks, checkRemoteAuth(server))
		report.Checks = append(report.Checks, checkTokensInURL(server))
		report.Checks = append(report.Checks, checkVersionPinning(server))
		report.Checks = append(report.Checks, checkThirdPartyProxy(server))
		report.Checks = append(report.Checks, checkDebugFlags(server))
	}

	// Run endpoint-level checks
	report.Checks = append(report.Checks, checkManagedConfig(result)...)
	report.Checks = append(report.Checks, checkFilePermissions(result)...)
	report.Checks = append(report.Checks, checkDuplicateServers(result)...)
	report.Checks = append(report.Checks, checkServerSprawl(result))

	// Compute score and maturity
	report.computeScore()
	report.computeMaturity(result)
	report.computeSummary()

	return report
}

// mapSecretFindings maps existing secrets.Finding entries to benchmark check IDs.
func mapSecretFindings(findings []secrets.Finding) []CheckResult {
	var checks []CheckResult
	for _, f := range findings {
		check := CheckResult{
			Severity:   f.Severity,
			Status:     StatusFail,
			ServerName: f.ServerName,
			Tool:       f.Tool,
			Details:    f.Description,
		}

		// Map by context (where the credential was found)
		switch {
		case strings.HasPrefix(f.Context, "args"):
			check.ID = "CS-01"
			check.Name = "No credentials in args"
			check.Category = "Credential Security"
			check.Remediation = "Move credentials to environment variables or a secrets manager"
		case strings.HasPrefix(f.Context, "env"):
			check.ID = "CS-02"
			check.Name = "No credentials in env values"
			check.Category = "Credential Security"
			check.Remediation = "Use environment variable references (${VAR_NAME}) instead of inline values"
		case strings.HasPrefix(f.Context, "headers"):
			check.ID = "CS-03"
			check.Name = "No credentials in headers"
			check.Category = "Credential Security"
			check.Remediation = "Use a credential broker that injects headers at runtime"
		case strings.HasPrefix(f.Context, "url"):
			check.ID = "AA-02"
			check.Name = "No tokens in URL parameters"
			check.Category = "Authentication"
			check.Remediation = "Move tokens to Authorization headers"
		default:
			check.ID = "CS-06"
			check.Name = "No high-entropy strings in credential contexts"
			check.Category = "Credential Security"
			check.Remediation = "Review flagged values and move actual credentials to a secrets manager"
		}

		// Override for specific finding types
		switch f.Type {
		case "private_key_header":
			check.ID = "CS-04"
			check.Name = "No private keys in configs"
			check.Category = "Credential Security"
			check.Remediation = "Store private keys in the OS keychain or hardware security module"
		case "allow_http_flag":
			check.ID = "TS-02"
			check.Name = "No --allow-http flags"
			check.Category = "Transport Security"
			check.Remediation = "Remove the flag and ensure the MCP server URL uses HTTPS"
		case "allow_insecure_host":
			check.ID = "TS-03"
			check.Name = "No TLS verification bypass"
			check.Category = "Transport Security"
			check.Remediation = "Install proper TLS certificates instead of disabling verification"
		}

		checks = append(checks, check)
	}
	return checks
}

// --- Transport Security Checks ---

// checkTransportHTTPS verifies remote MCP servers use HTTPS (TS-01).
func checkTransportHTTPS(server scanner.MCPServer) CheckResult {
	check := CheckResult{
		ID:         "TS-01",
		Name:       "Remote servers use HTTPS",
		Category:   "Transport Security",
		Severity:   SevHigh,
		ServerName: server.Name,
		Tool:       server.Tool,
	}

	if server.URL == "" {
		check.Status = StatusSkip
		return check
	}

	parsed, err := url.Parse(server.URL)
	if err != nil {
		check.Status = StatusSkip
		return check
	}

	// Localhost HTTP is acceptable
	host := parsed.Hostname()
	if host == "127.0.0.1" || host == "localhost" || host == "::1" {
		check.Status = StatusPass
		return check
	}

	if parsed.Scheme == "http" {
		check.Status = StatusFail
		check.Details = fmt.Sprintf("Server uses HTTP: %s", server.URL)
		check.Remediation = "Change URL to https://"
		return check
	}

	check.Status = StatusPass
	return check
}

// checkWebSocketTLS checks for unencrypted WebSocket connections (TS-04).
func checkWebSocketTLS(server scanner.MCPServer) CheckResult {
	check := CheckResult{
		ID:         "TS-04",
		Name:       "No unencrypted WebSocket",
		Category:   "Transport Security",
		Severity:   SevMedium,
		ServerName: server.Name,
		Tool:       server.Tool,
	}

	if server.URL == "" {
		check.Status = StatusSkip
		return check
	}

	parsed, err := url.Parse(server.URL)
	if err != nil {
		check.Status = StatusSkip
		return check
	}

	host := parsed.Hostname()
	if host == "127.0.0.1" || host == "localhost" || host == "::1" {
		check.Status = StatusPass
		return check
	}

	if parsed.Scheme == "ws" {
		check.Status = StatusFail
		check.Details = fmt.Sprintf("Server uses unencrypted WebSocket: %s", server.URL)
		check.Remediation = "Change ws:// to wss://"
		return check
	}

	check.Status = StatusPass
	return check
}

// --- Authentication Checks ---

// checkRemoteAuth checks MCP servers for authentication posture (AA-01).
//
// The MCP spec defines OAuth as the standard auth mechanism for HTTP/SSE transport.
// Tools implementing MCP properly (Claude Code, Claude Desktop, Codex CLI, Cursor, etc.)
// handle authentication at the application level and store tokens in the OS credential
// store (e.g. macOS Keychain). The ABSENCE of credentials in config files is the correct,
// secure state for HTTP/SSE servers.
//
// This check focuses on stdio servers that proxy to remote endpoints (e.g. npx mcp-remote),
// where auth credentials may need to be provided via config since the tool can't handle
// OAuth for stdio transport.
func checkRemoteAuth(server scanner.MCPServer) CheckResult {
	check := CheckResult{
		ID:         "AA-01",
		Name:       "Remote servers have authentication",
		Category:   "Authentication",
		Severity:   SevHigh,
		ServerName: server.Name,
		Tool:       server.Tool,
	}

	// HTTP/SSE servers: the MCP spec defines OAuth authentication at the transport
	// level. Tools handle auth via browser OAuth flow and store tokens in the OS
	// keychain (e.g. "Claude Code-credentials", "Codex MCP Credentials" in Keychain
	// Access). No config-level credentials is the expected, secure state.
	if server.Type == "http" || server.Type == "sse" {
		check.Status = StatusPass
		check.Details = "Auth handled via MCP OAuth + OS credential store"
		return check
	}

	// stdio servers: check if this is a remote proxy (e.g. npx mcp-remote https://...)
	// These bridge local stdio to a remote URL and may need explicit credentials.
	if server.Type == "stdio" {
		remoteURL := ""
		for _, arg := range server.Args {
			if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
				remoteURL = arg
				break
			}
		}

		// Not proxying to a remote endpoint — pure local stdio, skip
		if remoteURL == "" {
			check.Status = StatusSkip
			return check
		}

		// Proxying to remote — check for auth in args/env/headers
		if hasConfigLevelAuth(server) {
			check.Status = StatusPass
			return check
		}

		check.Status = StatusWarn
		check.Details = fmt.Sprintf("stdio server proxying to remote URL without explicit auth: %s", remoteURL)
		check.Remediation = "Verify authentication is handled by the remote endpoint or add credentials"
		return check
	}

	check.Status = StatusSkip
	return check
}

// hasConfigLevelAuth checks if a server has any authentication configured in its
// config file (headers, env vars, or auth-related args).
func hasConfigLevelAuth(server scanner.MCPServer) bool {
	for k := range server.Headers {
		lower := strings.ToLower(k)
		if lower == "authorization" || lower == "x-api-key" || lower == "api-key" {
			return true
		}
	}
	for k := range server.Env {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "token") || strings.Contains(lower, "key") ||
			strings.Contains(lower, "secret") || strings.Contains(lower, "password") ||
			strings.Contains(lower, "auth") {
			return true
		}
	}
	for _, arg := range server.Args {
		lower := strings.ToLower(arg)
		if strings.Contains(lower, "bearer") || strings.HasPrefix(lower, "--header") ||
			strings.HasPrefix(lower, "--auth") || strings.HasPrefix(lower, "--token") {
			return true
		}
	}
	return false
}

// checkTokensInURL flags authentication tokens in URL query parameters (AA-02).
func checkTokensInURL(server scanner.MCPServer) CheckResult {
	check := CheckResult{
		ID:         "AA-02",
		Name:       "No tokens in URL parameters",
		Category:   "Authentication",
		Severity:   SevMedium,
		ServerName: server.Name,
		Tool:       server.Tool,
	}

	if server.URL == "" {
		check.Status = StatusSkip
		return check
	}

	parsed, err := url.Parse(server.URL)
	if err != nil || parsed.RawQuery == "" {
		check.Status = StatusPass
		return check
	}

	suspiciousParams := []string{"token", "api_key", "apikey", "key", "access_token", "secret", "password", "auth"}
	q := parsed.Query()
	for param := range q {
		lower := strings.ToLower(param)
		for _, suspicious := range suspiciousParams {
			if strings.Contains(lower, suspicious) {
				check.Status = StatusFail
				check.Details = fmt.Sprintf("Token in URL parameter: ?%s=...", param)
				check.Remediation = "Move tokens to Authorization headers"
				return check
			}
		}
	}

	check.Status = StatusPass
	return check
}

// --- Supply Chain Checks ---

// checkVersionPinning checks for unpinned package versions (SC-01).
func checkVersionPinning(server scanner.MCPServer) CheckResult {
	check := CheckResult{
		ID:         "SC-01",
		Name:       "Package versions pinned",
		Category:   "Supply Chain",
		Severity:   SevMedium,
		ServerName: server.Name,
		Tool:       server.Tool,
	}

	// Only applies to stdio servers using package managers
	if server.Type != "stdio" {
		check.Status = StatusSkip
		return check
	}

	// Check if using npx, uvx, or go run
	cmd := strings.ToLower(server.Command)
	isPackageManager := cmd == "npx" || cmd == "uvx" || cmd == "go" || cmd == "pip" || cmd == "pipx"
	if !isPackageManager {
		check.Status = StatusSkip
		return check
	}

	// Check args for @latest
	allArgs := strings.Join(server.Args, " ")
	if unpinnedLatest.MatchString(allArgs) {
		check.Status = StatusFail
		check.Details = fmt.Sprintf("Unpinned @latest version in: %s %s", server.Command, allArgs)
		check.Remediation = "Pin to a specific version (e.g., @1.2.3)"
		return check
	}

	// Check for npx -y with no version in package name
	if cmd == "npx" {
		for _, arg := range server.Args {
			if arg == "-y" || arg == "--yes" {
				continue
			}
			if strings.HasPrefix(arg, "-") {
				continue
			}
			// Package name without @ version
			if !strings.Contains(arg, "@") || strings.HasSuffix(arg, "@latest") {
				// Could be a scope like @modelcontextprotocol/server-github (no version)
				if strings.Contains(arg, "/") && !strings.Contains(arg[strings.LastIndex(arg, "/"):], "@") {
					check.Status = StatusWarn
					check.Details = fmt.Sprintf("No version pinned for package: %s", arg)
					check.Remediation = "Pin to a specific version (e.g., %s@1.2.3)"
					return check
				}
			}
		}
	}

	check.Status = StatusPass
	return check
}

// checkThirdPartyProxy detects MCP servers routing through known proxy services (SC-04).
func checkThirdPartyProxy(server scanner.MCPServer) CheckResult {
	check := CheckResult{
		ID:         "SC-04",
		Name:       "Third-party proxy awareness",
		Category:   "Supply Chain",
		Severity:   SevInfo,
		ServerName: server.Name,
		Tool:       server.Tool,
	}

	if server.URL == "" {
		check.Status = StatusSkip
		return check
	}

	parsed, err := url.Parse(server.URL)
	if err != nil {
		check.Status = StatusSkip
		return check
	}

	host := strings.ToLower(parsed.Hostname())
	for _, proxy := range knownProxyDomains {
		if host == proxy || strings.HasSuffix(host, "."+proxy) {
			check.Status = StatusWarn
			check.Details = fmt.Sprintf("Traffic routes through third-party proxy: %s", host)
			check.Remediation = "Assess the proxy vendor's security posture. Consider direct connections for sensitive services"
			return check
		}
	}

	check.Status = StatusPass
	return check
}

// --- Governance Checks ---

// checkManagedConfig verifies managed organization policy is deployed (GP-01).
// Produces a single consolidated result rather than per-path results.
func checkManagedConfig(result *scanner.ScanResult) []CheckResult {
	check := CheckResult{
		ID:       "GP-01",
		Name:     "Managed organization policy deployed",
		Category: "Governance",
		Severity: SevHigh,
	}

	if len(result.ManagedConfigs) == 0 {
		check.Status = StatusFail
		check.Details = "No managed MCP server organization policy detected"
		check.Remediation = "Deploy a managed configuration policy via MDM (JumpCloud, Jamf, Intune)"
		return []CheckResult{check}
	}

	anyPresent := false
	toolsWithPolicy := []string{}
	for _, mc := range result.ManagedConfigs {
		if mc.Present {
			anyPresent = true
			toolsWithPolicy = append(toolsWithPolicy, mc.Tool)
		}
	}

	if anyPresent {
		check.Status = StatusPass
		check.Details = fmt.Sprintf("Organization policy deployed for: %s", strings.Join(toolsWithPolicy, ", "))
	} else {
		check.Status = StatusFail
		check.Details = "No managed MCP server organization policy detected"
		check.Remediation = "Deploy a managed configuration policy via MDM (JumpCloud, Jamf, Intune)"
	}

	return []CheckResult{check}
}

// checkFilePermissions verifies config file permissions are restrictive (GP-04).
func checkFilePermissions(result *scanner.ScanResult) []CheckResult {
	var checks []CheckResult

	for _, tc := range result.ToolConfigs {
		if !tc.Exists {
			continue
		}

		check := CheckResult{
			ID:       "GP-04",
			Name:     "Config file permissions restrictive",
			Category: "Governance",
			Severity: SevMedium,
			Tool:     tc.Tool,
		}

		info, err := os.Stat(tc.Path)
		if err != nil {
			check.Status = StatusSkip
			checks = append(checks, check)
			continue
		}

		perm := info.Mode().Perm()
		// Flag if world-readable (others have read permission)
		if perm&0007 != 0 {
			check.Status = StatusFail
			check.Details = fmt.Sprintf("Config file is world-accessible (%04o): %s", perm, tc.Path)
			check.Remediation = "Run: chmod 600 " + tc.Path
		} else {
			check.Status = StatusPass
			check.Details = fmt.Sprintf("Permissions OK (%04o): %s", perm, tc.Path)
		}
		checks = append(checks, check)
	}

	return checks
}

// --- Operational Hygiene Checks ---

// checkDuplicateServers detects MCP servers with identical URLs within the same tool (OH-01).
// Cross-tool duplicates (e.g. same Vercel server in Claude Code and Codex CLI) are expected
// since each tool has its own config format — there's no way to share a single configuration.
func checkDuplicateServers(result *scanner.ScanResult) []CheckResult {
	var checks []CheckResult

	// Group by tool+URL for remote servers (only flag dupes within same tool)
	type toolURL struct {
		tool string
		url  string
	}
	urlServers := make(map[toolURL][]scanner.MCPServer)
	for _, s := range result.MCPServers {
		if s.URL != "" {
			key := toolURL{tool: s.Tool, url: s.URL}
			urlServers[key] = append(urlServers[key], s)
		}
	}

	for key, servers := range urlServers {
		if len(servers) > 1 {
			names := make([]string, 0, len(servers))
			for _, s := range servers {
				names = append(names, s.Name)
			}
			checks = append(checks, CheckResult{
				ID:          "OH-01",
				Name:        "No duplicate MCP servers",
				Category:    "Operational Hygiene",
				Severity:    SevLow,
				Status:      StatusFail,
				Tool:        key.tool,
				Details:     fmt.Sprintf("Duplicate URL in %s: %s (servers: %s)", key.tool, key.url, strings.Join(names, ", ")),
				Remediation: "Remove the duplicate configuration",
			})
		}
	}

	if len(checks) == 0 {
		checks = append(checks, CheckResult{
			ID:       "OH-01",
			Name:     "No duplicate MCP servers",
			Category: "Operational Hygiene",
			Severity: SevLow,
			Status:   StatusPass,
		})
	}

	return checks
}

// checkDebugFlags detects debug/verbose flags in production configs (OH-02).
func checkDebugFlags(server scanner.MCPServer) CheckResult {
	check := CheckResult{
		ID:         "OH-02",
		Name:       "No debug flags in production",
		Category:   "Operational Hygiene",
		Severity:   SevLow,
		ServerName: server.Name,
		Tool:       server.Tool,
	}

	// Check args
	for _, arg := range server.Args {
		lower := strings.ToLower(arg)
		for _, pattern := range debugPatterns {
			if lower == pattern {
				check.Status = StatusFail
				check.Details = fmt.Sprintf("Debug flag in args: %s", arg)
				check.Remediation = "Remove debug flags from production configurations"
				return check
			}
		}
	}

	// Check env
	for k, v := range server.Env {
		upper := strings.ToUpper(k)
		for _, pattern := range debugEnvPatterns {
			if strings.Contains(upper, pattern) {
				lower := strings.ToLower(v)
				if lower == "true" || lower == "1" || lower == "debug" || lower == "trace" || lower == "verbose" {
					check.Status = StatusFail
					check.Details = fmt.Sprintf("Debug env var: %s=%s", k, v)
					check.Remediation = "Remove debug environment variables from production configurations"
					return check
				}
			}
		}
	}

	check.Status = StatusPass
	return check
}

// checkServerSprawl flags excessive MCP server count (OH-03).
func checkServerSprawl(result *scanner.ScanResult) CheckResult {
	check := CheckResult{
		ID:       "OH-03",
		Name:     "Reasonable MCP server count",
		Category: "Operational Hygiene",
		Severity: SevInfo,
	}

	threshold := 15
	count := len(result.MCPServers)

	if count > threshold {
		check.Status = StatusWarn
		check.Details = fmt.Sprintf("%d MCP servers configured (threshold: %d)", count, threshold)
		check.Remediation = "Review and remove unused or redundant MCP servers"
	} else {
		check.Status = StatusPass
		check.Details = fmt.Sprintf("%d MCP servers configured", count)
	}

	return check
}

// --- Scoring & Maturity ---

func (r *BenchmarkReport) computeScore() {
	for _, c := range r.Checks {
		if c.Status != StatusFail {
			continue
		}
		switch c.Severity {
		case SevCritical:
			r.Score -= 10
		case SevHigh:
			r.Score -= 5
		case SevMedium:
			r.Score -= 2
		case SevLow:
			r.Score -= 1
		}
	}
	if r.Score < 0 {
		r.Score = 0
	}
}

func (r *BenchmarkReport) computeMaturity(result *scanner.ScanResult) {
	// Level 1: Scan completed (we're running, so at least level 1)
	r.MaturityLevel = 1
	r.MaturityName = "Visible"

	// Level 2: All L1 checks evaluated (we just ran them all)
	r.MaturityLevel = 2
	r.MaturityName = "Assessed"

	// Level 3: Zero critical/high failures
	hasCriticalOrHigh := false
	for _, c := range r.Checks {
		if c.Status == StatusFail && (c.Severity == SevCritical || c.Severity == SevHigh) {
			hasCriticalOrHigh = true
			break
		}
	}
	if !hasCriticalOrHigh {
		r.MaturityLevel = 3
		r.MaturityName = "Hardened"
	}

	// Level 4: Managed config deployed AND no critical/high
	if r.MaturityLevel == 3 {
		managedDeployed := false
		for _, c := range r.Checks {
			if c.ID == "GP-01" && c.Status == StatusPass {
				managedDeployed = true
				break
			}
		}
		if managedDeployed {
			r.MaturityLevel = 4
			r.MaturityName = "Governed"
		}
	}

	// Level 5 requires the full AgentShield platform (not achievable via scanner alone)
}

func (r *BenchmarkReport) computeSummary() {
	for _, c := range r.Checks {
		var cat *CategoryCount
		switch c.Category {
		case "Credential Security":
			cat = &r.Summary.CredentialSecurity
		case "Transport Security":
			cat = &r.Summary.TransportSecurity
		case "Authentication":
			cat = &r.Summary.Authentication
		case "Supply Chain":
			cat = &r.Summary.SupplyChain
		case "Governance":
			cat = &r.Summary.Governance
		case "Operational Hygiene":
			cat = &r.Summary.OperationalHygiene
		default:
			continue
		}

		switch c.Status {
		case StatusPass:
			cat.Pass++
		case StatusFail:
			cat.Fail++
		case StatusWarn:
			cat.Warn++
		case StatusSkip:
			cat.Skip++
		}
	}
}

// FailedChecks returns only checks that failed or warned.
func (r *BenchmarkReport) FailedChecks() []CheckResult {
	var failed []CheckResult
	for _, c := range r.Checks {
		if c.Status == StatusFail || c.Status == StatusWarn {
			failed = append(failed, c)
		}
	}
	return failed
}

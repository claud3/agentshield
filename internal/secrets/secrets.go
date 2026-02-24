package secrets

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/claud3/agentshield/internal/scanner"
	"gopkg.in/yaml.v3"
)

// Severity levels for credential findings.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Finding represents a detected credential or secret.
type Finding struct {
	Severity    string `json:"severity"`
	Vendor      string `json:"vendor"`
	Type        string `json:"type"`        // e.g. "bearer_token", "api_key", "pat"
	Description string `json:"description"`
	Location    string `json:"location"`    // file path
	Context     string `json:"context"`     // where in the config (args, env, headers)
	Match       string `json:"match"`       // redacted match value
	ServerName  string `json:"server_name"` // MCP server name if applicable
	Tool        string `json:"tool"`        // AI tool name
}

// Pattern defines a regex pattern for detecting a specific credential type.
type Pattern struct {
	Name        string `yaml:"name"`
	Vendor      string `yaml:"vendor"`
	Type        string `yaml:"type"`
	Severity    string `yaml:"severity"`
	Regex       string `yaml:"regex"`
	Description string `yaml:"description"`
	compiled    *regexp.Regexp
}

// PatternConfig holds all credential detection patterns.
type PatternConfig struct {
	Patterns          []Pattern `yaml:"patterns"`
	EntropyThreshold  float64   `yaml:"entropy_threshold"`
	MinEntropyLength  int       `yaml:"min_entropy_length"`
}

// LoadPatterns loads secret detection patterns from YAML.
func LoadPatterns(configDir string) (*PatternConfig, error) {
	var data []byte
	var err error

	if configDir != "" {
		data, err = os.ReadFile(filepath.Join(configDir, "secrets_patterns.yaml"))
		if err != nil {
			return nil, fmt.Errorf("reading secrets_patterns.yaml from %s: %w", configDir, err)
		}
	} else {
		data, err = os.ReadFile("configs/secrets_patterns.yaml")
		if err != nil {
			return defaultPatterns(), nil
		}
	}

	var config PatternConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing secrets_patterns.yaml: %w", err)
	}

	// Compile all regex patterns
	for i := range config.Patterns {
		compiled, err := regexp.Compile(config.Patterns[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("compiling pattern %q: %w", config.Patterns[i].Name, err)
		}
		config.Patterns[i].compiled = compiled
	}

	return &config, nil
}

// Detect scans all discovered MCP servers for credential exposure.
func Detect(result *scanner.ScanResult, patterns *PatternConfig) []Finding {
	var findings []Finding

	for _, server := range result.MCPServers {
		serverFindings := detectInServer(server, patterns)
		findings = append(findings, serverFindings...)
	}

	return findings
}

func detectInServer(server scanner.MCPServer, patterns *PatternConfig) []Finding {
	var findings []Finding

	// Scan command args
	for _, arg := range server.Args {
		for _, f := range scanString(arg, "args", server, patterns) {
			findings = append(findings, f)
		}
	}

	// Scan environment variables
	for key, val := range server.Env {
		for _, f := range scanString(val, fmt.Sprintf("env[%s]", key), server, patterns) {
			findings = append(findings, f)
		}
	}

	// Scan headers
	for key, val := range server.Headers {
		for _, f := range scanString(val, fmt.Sprintf("headers[%s]", key), server, patterns) {
			findings = append(findings, f)
		}
	}

	// Scan URL for embedded credentials
	if server.URL != "" {
		for _, f := range scanString(server.URL, "url", server, patterns) {
			findings = append(findings, f)
		}
	}

	// Scan raw config for known patterns only (skip entropy to avoid false positives
	// on JSON structure). Extract individual string values from the raw config.
	if server.RawConfig != nil {
		var rawMap map[string]interface{}
		if err := json.Unmarshal(server.RawConfig, &rawMap); err == nil {
			existingCopy := make([]Finding, len(findings))
			copy(existingCopy, findings)
			extractStrings(rawMap, "raw_config", server, patterns, existingCopy, &findings)
		}
	}

	return findings
}

func scanString(value, context string, server scanner.MCPServer, patterns *PatternConfig) []Finding {
	var findings []Finding

	// Check against known patterns
	for _, pattern := range patterns.Patterns {
		if pattern.compiled == nil {
			continue
		}
		if pattern.compiled.MatchString(value) {
			match := pattern.compiled.FindString(value)
			findings = append(findings, Finding{
				Severity:    pattern.Severity,
				Vendor:      pattern.Vendor,
				Type:        pattern.Type,
				Description: pattern.Description,
				Location:    server.ConfigPath,
				Context:     context,
				Match:       redact(match),
				ServerName:  server.Name,
				Tool:        server.Tool,
			})
		}
	}

	// Entropy-based detection for unrecognized high-entropy strings
	if patterns.EntropyThreshold > 0 && len(value) >= patterns.MinEntropyLength {
		if shannonEntropy(value) >= patterns.EntropyThreshold && !isKnownSafe(value) {
			// Only flag if no pattern already matched this value
			alreadyMatched := false
			for _, f := range findings {
				if f.Match != "" {
					alreadyMatched = true
					break
				}
			}
			if !alreadyMatched {
				findings = append(findings, Finding{
					Severity:    SeverityMedium,
					Vendor:      "unknown",
					Type:        "high_entropy_string",
					Description: "High-entropy string detected (possible credential)",
					Location:    server.ConfigPath,
					Context:     context,
					Match:       redact(value),
					ServerName:  server.Name,
					Tool:        server.Tool,
				})
			}
		}
	}

	return findings
}

// extractStrings recursively extracts string values from a JSON map and scans
// each individual value. This avoids false-positive entropy on JSON structure.
func extractStrings(m map[string]interface{}, context string, server scanner.MCPServer, patterns *PatternConfig, existing []Finding, findings *[]Finding) {
	for key, val := range m {
		ctx := context + "." + key
		switch v := val.(type) {
		case string:
			for _, f := range scanString(v, ctx, server, patterns) {
				isDuplicate := false
				for _, e := range *findings {
					if e.Match == f.Match && e.Vendor == f.Vendor {
						isDuplicate = true
						break
					}
				}
				if !isDuplicate {
					*findings = append(*findings, f)
				}
			}
		case map[string]interface{}:
			extractStrings(v, ctx, server, patterns, *findings, findings)
		case []interface{}:
			for i, item := range v {
				if s, ok := item.(string); ok {
					itemCtx := fmt.Sprintf("%s[%d]", ctx, i)
					for _, f := range scanString(s, itemCtx, server, patterns) {
						isDuplicate := false
						for _, e := range *findings {
							if e.Match == f.Match && e.Vendor == f.Vendor {
								isDuplicate = true
								break
							}
						}
						if !isDuplicate {
							*findings = append(*findings, f)
						}
					}
				}
			}
		}
	}
}

// shannonEntropy calculates the Shannon entropy of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}

	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// isKnownSafe returns true for strings that look high-entropy but are not secrets.
func isKnownSafe(s string) bool {
	safePrefixes := []string{
		"npx", "uvx", "node", "python", "go ", "/usr/", "/bin/",
		"http://127.0.0.1", "http://localhost",
		"https://mcp.", "https://api.",
	}
	lower := strings.ToLower(s)
	for _, prefix := range safePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// redact masks a credential value, showing only the first 6 and last 4 characters.
func redact(s string) string {
	if len(s) <= 12 {
		return strings.Repeat("*", len(s))
	}
	return s[:6] + strings.Repeat("*", len(s)-10) + s[len(s)-4:]
}

// defaultPatterns returns hardcoded default patterns.
func defaultPatterns() *PatternConfig {
	config := &PatternConfig{
		EntropyThreshold: 4.5,
		MinEntropyLength: 20,
		Patterns: []Pattern{
			{
				Name:        "databricks_token",
				Vendor:      "databricks",
				Type:        "bearer_token",
				Severity:    SeverityCritical,
				Regex:       `dapi[a-f0-9]{32}`,
				Description: "Databricks personal access token",
			},
			{
				Name:        "github_pat_classic",
				Vendor:      "github",
				Type:        "pat",
				Severity:    SeverityCritical,
				Regex:       `ghp_[A-Za-z0-9_]{36}`,
				Description: "GitHub personal access token (classic)",
			},
			{
				Name:        "github_pat_fine",
				Vendor:      "github",
				Type:        "pat",
				Severity:    SeverityCritical,
				Regex:       `github_pat_[A-Za-z0-9_]{82}`,
				Description: "GitHub fine-grained personal access token",
			},
			{
				Name:        "aws_access_key",
				Vendor:      "aws",
				Type:        "access_key",
				Severity:    SeverityCritical,
				Regex:       `AKIA[0-9A-Z]{16}`,
				Description: "AWS access key ID",
			},
			{
				Name:        "anthropic_api_key",
				Vendor:      "anthropic",
				Type:        "api_key",
				Severity:    SeverityHigh,
				Regex:       `sk-ant-[A-Za-z0-9\-_]{20,}`,
				Description: "Anthropic API key",
			},
			{
				Name:        "openai_api_key",
				Vendor:      "openai",
				Type:        "api_key",
				Severity:    SeverityHigh,
				Regex:       `sk-[A-Za-z0-9]{20,}`,
				Description: "OpenAI API key",
			},
			{
				Name:        "slack_bot_token",
				Vendor:      "slack",
				Type:        "bot_token",
				Severity:    SeverityHigh,
				Regex:       `xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}`,
				Description: "Slack bot token",
			},
			{
				Name:        "slack_user_token",
				Vendor:      "slack",
				Type:        "user_token",
				Severity:    SeverityHigh,
				Regex:       `xoxp-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}`,
				Description: "Slack user token",
			},
			{
				Name:        "atlassian_api_token",
				Vendor:      "atlassian",
				Type:        "api_token",
				Severity:    SeverityCritical,
				Regex:       `ATATT3x[A-Za-z0-9+/=\-_]{30,}`,
				Description: "Atlassian API token",
			},
			{
				Name:        "generic_bearer",
				Vendor:      "unknown",
				Type:        "bearer_token",
				Severity:    SeverityMedium,
				Regex:       `[Bb]earer\s+[A-Za-z0-9\-_.~+/]{20,}`,
				Description: "Generic bearer token in authorization header",
			},
			{
				Name:        "generic_basic_auth",
				Vendor:      "unknown",
				Type:        "basic_auth",
				Severity:    SeverityMedium,
				Regex:       `[Bb]asic\s+[A-Za-z0-9+/=]{20,}`,
				Description: "Basic auth credentials (base64 encoded)",
			},
			{
				Name:        "private_key_header",
				Vendor:      "unknown",
				Type:        "private_key",
				Severity:    SeverityCritical,
				Regex:       `-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`,
				Description: "Private key embedded in configuration",
			},
			{
				Name:        "allow_http_flag",
				Vendor:      "unknown",
				Type:        "insecure_transport",
				Severity:    SeverityMedium,
				Regex:       `--allow-http`,
				Description: "Insecure HTTP transport explicitly allowed",
			},
			{
				Name:        "allow_insecure_host",
				Vendor:      "unknown",
				Type:        "insecure_transport",
				Severity:    SeverityMedium,
				Regex:       `--allow-insecure-host`,
				Description: "TLS verification bypassed for specific host",
			},
		},
	}

	// Compile patterns
	for i := range config.Patterns {
		config.Patterns[i].compiled = regexp.MustCompile(config.Patterns[i].Regex)
	}

	return config
}

// MarshalJSON implements custom JSON marshaling for Finding to ensure redacted output.
func (f Finding) MarshalJSON() ([]byte, error) {
	type Alias Finding
	return json.Marshal(&struct {
		Alias
	}{
		Alias: Alias(f),
	})
}

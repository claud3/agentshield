package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/claud3/agentshield/internal/compliance"
	"github.com/claud3/agentshield/internal/report"
	"github.com/claud3/agentshield/internal/scanner"
	"github.com/claud3/agentshield/internal/secrets"
)

var version = "dev"

func main() {
	jsonOutput := flag.Bool("json", false, "Output results as JSON")
	showVersion := flag.Bool("version", false, "Print version and exit")
	configDir := flag.String("configs", "", "Path to configs directory (default: embedded)")
	reportURL := flag.String("report-url", "", "URL to POST scan results to (env: AGENTSHIELD_REPORT_URL)")
	apiKey := flag.String("api-key", "", "API key for report URL authentication (env: AGENTSHIELD_API_KEY)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("agentshield-scan %s\n", version)
		os.Exit(0)
	}

	// Env var fallback for report-url and api-key
	if *reportURL == "" {
		*reportURL = os.Getenv("AGENTSHIELD_REPORT_URL")
	}
	if *apiKey == "" {
		*apiKey = os.Getenv("AGENTSHIELD_API_KEY")
	}

	// Load config path definitions
	paths, err := scanner.LoadPaths(*configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config paths: %v\n", err)
		os.Exit(1)
	}

	// Load secret detection patterns
	patterns, err := secrets.LoadPatterns(*configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading secret patterns: %v\n", err)
		os.Exit(1)
	}

	// Phase 1: Scan for AI tool configurations
	scanResult := scanner.Scan(paths)

	// Phase 2: Detect credentials in discovered configs
	findings := secrets.Detect(scanResult, patterns)

	// Phase 3: Run MCP Security Benchmark
	benchmark := compliance.RunBenchmark(scanResult, findings)

	// Phase 4: Output results
	result := report.Result{
		ScannerVersion: version,
		ScanResult:     scanResult,
		Findings:       findings,
		Benchmark:      benchmark,
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		report.PrintTerminal(result)
	}

	// Phase 5: Report to console (if configured)
	if *reportURL != "" {
		if err := reportToConsole(*reportURL, *apiKey, result); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to report to console: %v\n", err)
		}
	}

	// Exit with non-zero status if critical findings exist
	if result.HasCriticalFindings() {
		os.Exit(2)
	}
}

// reportToConsole POSTs the scan result JSON to the AgentShield Console API.
func reportToConsole(url, apiKey string, result report.Result) error {
	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send report: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}

	return nil
}

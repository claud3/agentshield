package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/claud3/agentshield/internal/report"
	"github.com/claud3/agentshield/internal/scanner"
	"github.com/claud3/agentshield/internal/secrets"
)

var version = "dev"

func main() {
	jsonOutput := flag.Bool("json", false, "Output results as JSON")
	showVersion := flag.Bool("version", false, "Print version and exit")
	configDir := flag.String("configs", "", "Path to configs directory (default: embedded)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("agentshield-scan %s\n", version)
		os.Exit(0)
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

	// Phase 3: Output results
	result := report.Result{
		ScanResult: scanResult,
		Findings:   findings,
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

	// Exit with non-zero status if critical findings exist
	if result.HasCriticalFindings() {
		os.Exit(2)
	}
}

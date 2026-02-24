package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("agentshield %s\n", version)
		os.Exit(0)
	}

	fmt.Println("agentshield - Enterprise AI Agent Governance Platform")
	fmt.Println()
	fmt.Println("Available commands:")
	fmt.Println("  auth       Authenticate with vendor services")
	fmt.Println("  scan       Run endpoint scanner (same as agentshield-scan)")
	fmt.Println("  policy     View and sync policies")
	fmt.Println("  vendors    Manage vendor configurations")
	fmt.Println("  config     CLI configuration")
	fmt.Println("  doctor     Diagnose connectivity and credential stores")
	fmt.Println("  version    Print version")
	fmt.Println()
	fmt.Println("Run 'agentshield <command> --help' for more information.")
}

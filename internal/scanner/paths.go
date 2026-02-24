package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ToolPaths defines config file locations for one AI tool on one platform.
type ToolPaths struct {
	Tool         string   `yaml:"tool"`
	ConfigPaths  []string `yaml:"config_paths"`
	ManagedPaths []string `yaml:"managed_paths,omitempty"`
}

// PlatformConfig defines all tool paths for a specific platform.
type PlatformConfig struct {
	Tools []ToolPaths `yaml:"tools"`
}

// PathConfig holds the full path configuration across platforms.
type PathConfig struct {
	MacOS   PlatformConfig `yaml:"macos"`
	Linux   PlatformConfig `yaml:"linux"`
	Windows PlatformConfig `yaml:"windows"`
}

// LoadPaths loads config path definitions from YAML.
// If configDir is empty, it looks in the default configs/ directory
// relative to the binary, then falls back to embedded defaults.
func LoadPaths(configDir string) (*PathConfig, error) {
	var data []byte
	var err error

	if configDir != "" {
		data, err = os.ReadFile(filepath.Join(configDir, "paths.yaml"))
		if err != nil {
			return nil, fmt.Errorf("reading paths.yaml from %s: %w", configDir, err)
		}
	} else {
		// Try configs/ relative to working directory
		data, err = os.ReadFile("configs/paths.yaml")
		if err != nil {
			// Fall back to embedded defaults
			return defaultPaths(), nil
		}
	}

	var config PathConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing paths.yaml: %w", err)
	}

	return &config, nil
}

// GetPlatformPaths returns the tool paths for the given OS.
func (pc *PathConfig) GetPlatformPaths(goos string) []ToolPaths {
	switch goos {
	case "darwin":
		return pc.MacOS.Tools
	case "linux":
		return pc.Linux.Tools
	case "windows":
		return pc.Windows.Tools
	default:
		return pc.Linux.Tools // fallback
	}
}

// defaultPaths returns hardcoded defaults when no paths.yaml is available.
func defaultPaths() *PathConfig {
	return &PathConfig{
		MacOS: PlatformConfig{
			Tools: []ToolPaths{
				{
					Tool: "claude-code",
					ConfigPaths: []string{
						"~/.claude.json",
						"~/.claude/settings.json",
						".claude/settings.json",
						".mcp.json",
					},
					ManagedPaths: []string{
						"/Library/Application Support/ClaudeCode/managed-settings.json",
						"/Library/Application Support/ClaudeCode/managed-mcp.json",
					},
				},
				{
					Tool: "claude-desktop",
					ConfigPaths: []string{
						"~/Library/Application Support/Claude/claude_desktop_config.json",
					},
				},
				{
					Tool: "cursor",
					ConfigPaths: []string{
						"~/.cursor/mcp.json",
						".cursor/mcp.json",
					},
				},
				{
					Tool: "vscode-copilot",
					ConfigPaths: []string{
						".vscode/mcp.json",
						".vscode/settings.json",
					},
				},
				{
					Tool: "codex-cli",
					ConfigPaths: []string{
						"~/.codex/config.toml",
						".codex/config.toml",
					},
					ManagedPaths: []string{
						"/etc/codex/requirements.toml",
						"/etc/codex/managed_config.toml",
					},
				},
				{
					Tool: "windsurf",
					ConfigPaths: []string{
						"~/.codeium/windsurf/mcp_config.json",
					},
				},
				{
					Tool: "continue-dev",
					ConfigPaths: []string{
						"~/.continue/config.json",
					},
				},
				{
					Tool: "aider",
					ConfigPaths: []string{
						"~/.aider.conf.yml",
					},
				},
			},
		},
		Linux: PlatformConfig{
			Tools: []ToolPaths{
				{
					Tool: "claude-code",
					ConfigPaths: []string{
						"~/.claude.json",
						"~/.claude/settings.json",
						".claude/settings.json",
						".mcp.json",
					},
					ManagedPaths: []string{
						"/etc/claude-code/managed-settings.json",
						"/etc/claude-code/managed-mcp.json",
					},
				},
				{
					Tool: "cursor",
					ConfigPaths: []string{
						"~/.cursor/mcp.json",
						".cursor/mcp.json",
					},
				},
				{
					Tool: "vscode-copilot",
					ConfigPaths: []string{
						".vscode/mcp.json",
						".vscode/settings.json",
					},
				},
				{
					Tool: "codex-cli",
					ConfigPaths: []string{
						"~/.codex/config.toml",
						".codex/config.toml",
					},
					ManagedPaths: []string{
						"/etc/codex/requirements.toml",
						"/etc/codex/managed_config.toml",
					},
				},
				{
					Tool: "windsurf",
					ConfigPaths: []string{
						"~/.codeium/windsurf/mcp_config.json",
					},
				},
				{
					Tool: "continue-dev",
					ConfigPaths: []string{
						"~/.continue/config.json",
					},
				},
				{
					Tool: "aider",
					ConfigPaths: []string{
						"~/.aider.conf.yml",
					},
				},
			},
		},
		Windows: PlatformConfig{
			Tools: []ToolPaths{
				{
					Tool: "claude-code",
					ConfigPaths: []string{
						"~/.claude.json",
						"~/.claude/settings.json",
						".claude/settings.json",
						".mcp.json",
					},
					ManagedPaths: []string{
						"C:\\Program Files\\ClaudeCode\\managed-settings.json",
						"C:\\Program Files\\ClaudeCode\\managed-mcp.json",
						"C:\\ProgramData\\ClaudeCode\\managed-settings.json",
						"C:\\ProgramData\\ClaudeCode\\managed-mcp.json",
					},
				},
				{
					Tool: "cursor",
					ConfigPaths: []string{
						"~/.cursor/mcp.json",
						".cursor/mcp.json",
					},
				},
				{
					Tool: "vscode-copilot",
					ConfigPaths: []string{
						".vscode/mcp.json",
						".vscode/settings.json",
					},
				},
				{
					Tool: "codex-cli",
					ConfigPaths: []string{
						"~/.codex/config.toml",
						".codex/config.toml",
					},
				},
				{
					Tool: "windsurf",
					ConfigPaths: []string{
						"~/.codeium/windsurf/mcp_config.json",
					},
				},
				{
					Tool: "continue-dev",
					ConfigPaths: []string{
						"~/.continue/config.json",
					},
				},
				{
					Tool: "aider",
					ConfigPaths: []string{
						"~/.aider.conf.yml",
					},
				},
			},
		},
	}
}

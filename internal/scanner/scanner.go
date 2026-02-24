package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// ToolConfig represents a discovered AI tool configuration file.
type ToolConfig struct {
	Tool      string `json:"tool"`
	Path      string `json:"path"`
	Exists    bool   `json:"exists"`
	Readable  bool   `json:"readable"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
}

// MCPServer represents a discovered MCP server entry.
type MCPServer struct {
	Name          string            `json:"name"`
	Tool          string            `json:"tool"`             // Which AI tool config this came from
	ConfigPath    string            `json:"config_path"`      // File where this was found
	Type          string            `json:"type"`             // stdio, http, sse, url
	Command       string            `json:"command,omitempty"`
	Args          []string          `json:"args,omitempty"`
	URL           string            `json:"url,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	RawConfig     json.RawMessage   `json:"raw_config"`
}

// ManagedConfig tracks whether managed configuration is deployed.
type ManagedConfig struct {
	Tool     string `json:"tool"`
	Path     string `json:"path"`
	Present  bool   `json:"present"`
	Readable bool   `json:"readable"`
}

// ScanResult contains all discovered configurations from one endpoint.
type ScanResult struct {
	Hostname       string          `json:"hostname"`
	Platform       string          `json:"platform"`
	Username       string          `json:"username"`
	ToolConfigs    []ToolConfig    `json:"tool_configs"`
	MCPServers     []MCPServer     `json:"mcp_servers"`
	ManagedConfigs []ManagedConfig `json:"managed_configs"`
}

// Scan discovers AI tool configurations on the current endpoint.
func Scan(paths *PathConfig) *ScanResult {
	hostname, _ := os.Hostname()
	currentUser, _ := user.Current()
	username := ""
	if currentUser != nil {
		username = currentUser.Username
	}

	result := &ScanResult{
		Hostname: hostname,
		Platform: runtime.GOOS,
		Username: username,
	}

	platformPaths := paths.GetPlatformPaths(runtime.GOOS)

	for _, toolDef := range platformPaths {
		for _, configPath := range toolDef.ConfigPaths {
			expanded := expandPath(configPath)
			tc := scanConfigFile(toolDef.Tool, expanded)
			result.ToolConfigs = append(result.ToolConfigs, tc)

			if tc.Exists && tc.Readable {
				servers := extractMCPServers(toolDef.Tool, expanded)
				result.MCPServers = append(result.MCPServers, servers...)
			}
		}

		for _, managedPath := range toolDef.ManagedPaths {
			expanded := expandPath(managedPath)
			mc := scanManagedConfig(toolDef.Tool, expanded)
			result.ManagedConfigs = append(result.ManagedConfigs, mc)
		}
	}

	return result
}

func scanConfigFile(tool, path string) ToolConfig {
	tc := ToolConfig{
		Tool: tool,
		Path: path,
	}

	info, err := os.Stat(path)
	if err != nil {
		return tc
	}

	tc.Exists = true
	tc.SizeBytes = info.Size()

	f, err := os.Open(path)
	if err != nil {
		return tc
	}
	f.Close()
	tc.Readable = true

	return tc
}

func scanManagedConfig(tool, path string) ManagedConfig {
	mc := ManagedConfig{
		Tool: tool,
		Path: path,
	}

	_, err := os.Stat(path)
	if err != nil {
		return mc
	}
	mc.Present = true

	f, err := os.Open(path)
	if err != nil {
		return mc
	}
	f.Close()
	mc.Readable = true

	return mc
}

// extractMCPServers parses a config file and extracts MCP server entries.
func extractMCPServers(tool, path string) []MCPServer {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var servers []MCPServer

	// Try to parse as JSON (covers most AI tool configs)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	// Look for mcpServers key (Claude Code, Claude Desktop, Cursor, VS Code)
	mcpServersRaw, ok := raw["mcpServers"]
	if !ok {
		return nil
	}

	var mcpServers map[string]json.RawMessage
	if err := json.Unmarshal(mcpServersRaw, &mcpServers); err != nil {
		return nil
	}

	for name, serverRaw := range mcpServers {
		server := MCPServer{
			Name:       name,
			Tool:       tool,
			ConfigPath: path,
			RawConfig:  serverRaw,
		}

		var serverMap map[string]interface{}
		if err := json.Unmarshal(serverRaw, &serverMap); err == nil {
			if t, ok := serverMap["type"].(string); ok {
				server.Type = t
			}
			if cmd, ok := serverMap["command"].(string); ok {
				server.Command = cmd
			}
			if args, ok := serverMap["args"].([]interface{}); ok {
				for _, a := range args {
					if s, ok := a.(string); ok {
						server.Args = append(server.Args, s)
					}
				}
			}
			if u, ok := serverMap["url"].(string); ok {
				server.URL = u
			}
			if envMap, ok := serverMap["env"].(map[string]interface{}); ok {
				server.Env = make(map[string]string)
				for k, v := range envMap {
					if s, ok := v.(string); ok {
						server.Env[k] = s
					}
				}
			}
			if hdrMap, ok := serverMap["headers"].(map[string]interface{}); ok {
				server.Headers = make(map[string]string)
				for k, v := range hdrMap {
					if s, ok := v.(string); ok {
						server.Headers[k] = s
					}
				}
			}

			// Infer type from content if not explicitly set
			if server.Type == "" {
				if server.URL != "" {
					server.Type = "url"
				} else if server.Command != "" {
					server.Type = "stdio"
				}
			}
		}

		servers = append(servers, server)
	}

	return servers
}

// expandPath expands ~ and environment variables in paths.
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[2:])
		}
	}
	return os.ExpandEnv(path)
}

// Summary returns a human-readable summary of the scan.
func (r *ScanResult) Summary() string {
	configsFound := 0
	for _, tc := range r.ToolConfigs {
		if tc.Exists {
			configsFound++
		}
	}

	managedCount := 0
	for _, mc := range r.ManagedConfigs {
		if mc.Present {
			managedCount++
		}
	}

	return fmt.Sprintf(
		"Host: %s | Platform: %s | Configs found: %d | MCP servers: %d | Managed configs: %d",
		r.Hostname, r.Platform, configsFound, len(r.MCPServers), managedCount,
	)
}

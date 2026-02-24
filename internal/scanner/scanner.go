package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
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
	Tool          string            `json:"tool"`              // Which AI tool config this came from
	ConfigPath    string            `json:"config_path"`       // File where this was found
	Project       string            `json:"project,omitempty"` // Project path (for per-project configs like ~/.claude.json)
	Type          string            `json:"type"`              // stdio, http, sse, url
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

	// Track already-scanned absolute paths to avoid duplicates when
	// a global path (e.g. ~/.cursor/mcp.json) and a project-relative
	// path (e.g. .cursor/mcp.json) resolve to the same file.
	scannedPaths := make(map[string]bool)

	platformPaths := paths.GetPlatformPaths(runtime.GOOS)

	for _, toolDef := range platformPaths {
		for _, configPath := range toolDef.ConfigPaths {
			expanded := expandPath(configPath)
			absPath, err := filepath.Abs(expanded)
			if err != nil {
				absPath = expanded
			}

			tc := scanConfigFile(toolDef.Tool, absPath)
			result.ToolConfigs = append(result.ToolConfigs, tc)

			if tc.Exists && tc.Readable && !scannedPaths[absPath] {
				scannedPaths[absPath] = true
				servers := extractMCPServers(toolDef.Tool, absPath)
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
// Dispatches to the appropriate parser based on file extension.
func extractMCPServers(tool, path string) []MCPServer {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return extractMCPServersJSON(tool, path)
	case ".toml":
		return extractMCPServersTOML(tool, path)
	case ".yaml", ".yml":
		return extractMCPServersYAML(tool, path)
	default:
		// Try JSON first (most common), fall back to TOML, then YAML
		if servers := extractMCPServersJSON(tool, path); servers != nil {
			return servers
		}
		if servers := extractMCPServersTOML(tool, path); servers != nil {
			return servers
		}
		return extractMCPServersYAML(tool, path)
	}
}

// extractMCPServersJSON handles JSON config files.
func extractMCPServersJSON(tool, path string) []MCPServer {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	var servers []MCPServer

	// Check for top-level mcpServers (Cursor, Claude Desktop, VS Code, .mcp.json)
	if mcpServersRaw, ok := raw["mcpServers"]; ok {
		servers = append(servers, parseMCPServersMap(tool, path, "", mcpServersRaw)...)
	}

	// Check for projects.*.mcpServers (Claude Code ~/.claude.json)
	if projectsRaw, ok := raw["projects"]; ok {
		var projects map[string]json.RawMessage
		if err := json.Unmarshal(projectsRaw, &projects); err == nil {
			for projectPath, projectRaw := range projects {
				var project map[string]json.RawMessage
				if err := json.Unmarshal(projectRaw, &project); err != nil {
					continue
				}
				if mcpServersRaw, ok := project["mcpServers"]; ok {
					servers = append(servers, parseMCPServersMap(tool, path, projectPath, mcpServersRaw)...)
				}
			}
		}
	}

	return servers
}

// extractMCPServersTOML handles TOML config files (e.g. Codex CLI).
// Expected structure:
//
//	[mcp_servers.server-name]
//	type = "stdio"
//	command = "/path/to/binary"
//	args = ["arg1", "arg2"]
//
//	[mcp_servers.server-name.env]
//	KEY = "value"
func extractMCPServersTOML(tool, path string) []MCPServer {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var raw map[string]interface{}
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil
	}

	return extractMCPServersFromGenericMap(tool, path, raw)
}

// extractMCPServersYAML handles YAML config files (e.g. Aider).
func extractMCPServersYAML(tool, path string) []MCPServer {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}

	return extractMCPServersFromGenericMap(tool, path, raw)
}

// extractMCPServersFromGenericMap extracts MCP servers from a generic map
// (works with TOML and YAML parsed data). Looks for keys: mcpServers, mcp_servers,
// mcpservers (case variations common across tools).
func extractMCPServersFromGenericMap(tool, path string, raw map[string]interface{}) []MCPServer {
	var servers []MCPServer

	// Try common key names for MCP server blocks
	mcpKeys := []string{"mcpServers", "mcp_servers", "mcpservers", "mcp-servers"}
	for _, key := range mcpKeys {
		if serversMap, ok := raw[key]; ok {
			if sm, ok := serversMap.(map[string]interface{}); ok {
				for name, serverVal := range sm {
					if serverMap, ok := serverVal.(map[string]interface{}); ok {
						server := parseServerFromMap(name, tool, path, serverMap)
						servers = append(servers, server)
					}
				}
			}
		}
	}

	return servers
}

// parseServerFromMap builds an MCPServer from a generic map[string]interface{}.
func parseServerFromMap(name, tool, configPath string, serverMap map[string]interface{}) MCPServer {
	server := MCPServer{
		Name:       name,
		Tool:       tool,
		ConfigPath: configPath,
	}

	// Marshal the map back to JSON for RawConfig
	if raw, err := json.Marshal(serverMap); err == nil {
		server.RawConfig = raw
	}

	if t, ok := serverMap["type"].(string); ok {
		server.Type = t
	}
	if cmd, ok := serverMap["command"].(string); ok {
		server.Command = cmd
	}
	if u, ok := serverMap["url"].(string); ok {
		server.URL = u
	}

	// Handle args ([]interface{} from TOML/YAML)
	if args, ok := serverMap["args"].([]interface{}); ok {
		for _, a := range args {
			if s, ok := a.(string); ok {
				server.Args = append(server.Args, s)
			}
		}
	}

	// Handle env
	if envMap, ok := serverMap["env"].(map[string]interface{}); ok {
		server.Env = make(map[string]string)
		for k, v := range envMap {
			if s, ok := v.(string); ok {
				server.Env[k] = s
			}
		}
	}

	// Handle headers
	if hdrMap, ok := serverMap["headers"].(map[string]interface{}); ok {
		server.Headers = make(map[string]string)
		for k, v := range hdrMap {
			if s, ok := v.(string); ok {
				server.Headers[k] = s
			}
		}
	}

	// Infer type if not set
	if server.Type == "" {
		if server.URL != "" {
			server.Type = "url"
		} else if server.Command != "" {
			server.Type = "stdio"
		}
	}

	return server
}

// parseMCPServersMap parses a {"serverName": {...}} map into MCPServer entries.
// projectPath is set when the servers come from a per-project config (e.g. ~/.claude.json projects).
func parseMCPServersMap(tool, configPath, projectPath string, mcpServersRaw json.RawMessage) []MCPServer {
	var mcpServers map[string]json.RawMessage
	if err := json.Unmarshal(mcpServersRaw, &mcpServers); err != nil {
		return nil
	}

	var servers []MCPServer
	for name, serverRaw := range mcpServers {
		server := MCPServer{
			Name:       name,
			Tool:       tool,
			ConfigPath: configPath,
			RawConfig:  serverRaw,
		}
		if projectPath != "" {
			server.Project = projectPath
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

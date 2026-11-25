package rules

import "embed"

// QuarryYAMLFS embeds all declarative Project Quarry YAML rules shipped with Argus
// so CLI, daemon, and MCP runtime paths enforce them offline with zero disk I/O.
//
//go:embed quarry/*.yaml
var QuarryYAMLFS embed.FS

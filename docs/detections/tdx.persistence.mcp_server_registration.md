# `tdx.persistence.mcp_server_registration`

This rule matches named `mcp add` requests for Codex, Claude Code, and OpenCode, and the bare `opencode mcp add` wizard. It reads `tool.command` and `tool.arguments`, including the Codex `compatible` profile's shell-command array and OpenCode's shell-command string. A match identifies a requested operation, not a completed registration or a trusted server.

The bundled `mcp.server_enumeration` rule covers probing and repeated listing, while `mcp.tool_metadata.prompt_injection` covers injection text in MCP metadata or results. Neither detects a client command that registers a new server. This rule adds an observable signal for durable expansion of the agent's tool surface.

## Read-only help vs. registration

The named form requires a server-name token, allowing common leading options such as `--transport`, `--scope`, and `--url`. The bare OpenCode form requires the command to end after `add`. This keeps `mcp add --help`, `mcp add -h`, `mcp list`, and `mcp add-json --help` out of the rule. It does not exclude an entire tool call when it sees help: a separate registration in the same shell request still matches. In the pinned Codex and OpenCode assessment, `detection.mcp_add_help` was clean and `detection.mcp_help_then_registration` was detected and alerting in both formats.

Authorized setup, integration tests, quoted registration examples, and help placed after a server name can still match.

Severity is medium and the rule contributes 40 points at `test` maturity. A matching scenario is `detected`; whether it alerts depends on the combined session score and is assessed separately.

## Coverage limits

Coverage is limited to the named and bare registration commands above as they appear in `tool.command` and `tool.arguments`; the rule does not parse the full command-line grammar. Other registration paths, such as direct configuration edits or graphical tools, and indirect command construction are out of scope for this rule.

## Changes

- 2026-10-13: Added as an experimental rule.
- 2026-10-20: Promoted to `test` and shipped in the community package.
- 2026-10-23: Tightened the `mcp add` boundaries and recorded the help false positives.
- 2026-11-18: Kept requested help out of registration alerts.
- 2026-11-18: Converted to Rule v2, Telltale's Sigma profile, with no change in behaviour.

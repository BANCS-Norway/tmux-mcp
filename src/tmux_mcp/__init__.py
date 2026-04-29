"""tmux-mcp — MCP server bridging Claude Chat ↔ Claude Code via tmux.

Submodules are import-safe: importing ``tmux_mcp.reports`` (or any other
module) does not pull in the OAuth-server config and therefore does not
require the server's env vars to be set. The ``tmux-mcp`` console script
points at ``tmux_mcp.server:main`` directly.
"""

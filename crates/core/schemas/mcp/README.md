# MCP schemas

These files are the official MCP JSON Schemas, copied without change. `crates/core/src/mcp.rs` validates each upstream tool result against the schema of the protocol version that the upstream negotiated.

| File | Source |
|---|---|
| `2025-06-18.json` | `schema/2025-06-18/schema.json` |
| `2025-11-25.json` | `schema/2025-11-25/schema.json` |
| `2026-07-28.json` | `schema/2026-07-28/schema.json` |

- Repository: <https://github.com/modelcontextprotocol/modelcontextprotocol>
- Commit: `271ecc9accafdd9b83a3c869fa67c22953b2af80`, the same commit that `rmcp` 3.7.0 cites.
- License: `LICENSE` in this directory, copied from that repository. The specification is under Apache-2.0. Older parts stay under MIT.

To add a version:

1. Copy its `schema.json` here without change.
2. Add a variant to `ProtocolVersion` in `crates/core/src/mcp.rs`.
3. Add fixtures for that version to the tests in that file.

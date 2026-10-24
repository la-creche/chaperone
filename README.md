# chaperone

chaperone is a policy layer between an agent app and its tools. Point an app such as LibreChat at chaperone as its MCP server. chaperone decides every tool call with a deterministic function over a policy file. It allows the call, denies it, or holds it until a human approves it.

The app never holds an upstream credential. No model takes part in a decision. A plugin can narrow what an app may reach. A plugin can never widen it.

## Status

Build step 3 is done. `chaperone serve` decides and audits each call from an MCP client. No upstream runs yet, so an allowed call fails with `not_connected`. `docs/design.md` section 13 lists the build order.

## Documents

| Document | Contents |
|---|---|
| `docs/design.md` | What chaperone guarantees, its parts, plugins, configuration, version 1 |
| `AGENTS.md` | Rules for every contributor and every agent |
| `plugins/AGENTS.md` | Plugin kinds, slots, hooks and the plugin manifest |
| `docs/writing-standard.md` | How every document in this repository is written |

## License

Licensed under either of:

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.

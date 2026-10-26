# chaperone

chaperone is a policy layer between an agent app and its tools. The app runs inside a sandbox, and chaperone is its only path to a tool. The app uses chaperone as its MCP server. chaperone decides every tool call with a deterministic function over a policy file. It allows the call, denies it, or holds it until a human approves it.

The app never holds an upstream credential. No model takes part in a decision. A plugin can narrow what an app may reach. A plugin can never widen it.

## Status

Build steps 1 to 9 are done. `chaperone serve` decides and audits each call from an MCP client. It runs an allowed call through its upstream. It asks the approval channel about a gated call and runs the call after an approval. Step 10 holds the rest of version 1. `docs/design.md` section 13 lists the build order.

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

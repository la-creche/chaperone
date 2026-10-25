# crates/chaperone/AGENTS.md

Rules for the `chaperone` program. Read the root `AGENTS.md` first.

This crate wires the parts together. It reads the configuration, starts the plugins, counts calls, keeps gate state, writes the audit and serves the admin socket and the CLI. It does not decide. It calls `core` to decide.

## Rules

1. Read each file with the strict reader in `core`. Do not parse JSON any other way.
2. Read the time through the clock slot, and pass it to `core` (G3). Never read a clock anywhere else in this crate.
3. Keep the rate counters and the gate state here. Pass them to `core` as values.
4. Write the audit line through the audit sink before you return a result (G6).
5. Blank each exact secret value in a tool result before the audit write and before the return (G9).
6. Start effect plugins with the `command` from `plugin.json`. Send secrets over stdin (`docs/design.md` section 7.5). Check every upstream result before you return it (`docs/design.md` section 7.7).
7. Build a manifest only from upstream tools that the policy grants. Never add a hook tool (G8).
8. Refuse to start when a slot is empty or a named plugin is missing (G2, G10).
9. Construct a compiled plugin only through a row of `src/registry.rs`. No other file names a plugin. A slot plugin without a row refuses start (G2).

## CLI and admin socket

Each CLI command and its admin socket endpoint call the same function. Write the function once. The CLI and the socket are two thin callers.

| CLI | Socket |
|---|---|
| `chaperone schema` | `GET /schema` |
| `chaperone check <file>` | `POST /check` |
| `chaperone token new <app>` | `POST /token` |

The admin socket is a Unix socket. Only the editor's OS user can open it. Never serve these endpoints on the front-door port.

## Never do these

1. Do not decide in this crate. A rule that changes an outcome belongs in `core`.
2. Do not pass a secret to a plugin that `install.toml` does not bind it to.
3. Do not put a secret in argv or the environment of a child, except for an effect plugin in `added/` with `secret_delivery = "env"` in the install file. Log the warning each time.
4. Do not retry a denied call on behalf of an app.

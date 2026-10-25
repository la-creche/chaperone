# plugins/AGENTS.md

Rules for every plugin. Each kind directory has its own `AGENTS.md` with more rules. `docs/design.md` section 7 is the source of these rules.

## What a plugin is

A plugin changes how chaperone behaves through a named hook. chaperone calls the hook. A model never calls a hook (G8). A plugin never decides a call on its own. It supplies a hook result, and the core combines the results (G7).

## The three kinds

| Kind | How it runs | Can do I/O | Can change a decision |
|---|---|---|---|
| decision | Compiled into chaperone, as a Rust trait | No | Yes. It can deny, gate or pass. |
| adapter | Compiled into chaperone, as a Rust trait | Yes | No |
| effect | A separate process. chaperone speaks MCP to it over stdio. | Yes | Only the approval channel, and only to complete a gate (`docs/design.md` section 5.3) |

The directory names the kind. Put a plugin only in the directory of its kind.

## The hook catalog

| Hook | Kind | Slot | Input | Output |
|---|---|---|---|---|
| identity | decision | identity (required) | The request credential, the request facts, the policy | An app instance, or nothing. Optionally a narrower reach. |
| fence | decision | none, any number | App instance, tool, arguments, the plugin's policy section | Pass, `Deny(reason)` or `Gate` |
| front door | adapter | front door (required) | Inbound connections | Calls the `Gateway` trait in `crates/core` |
| secret source | adapter | secret source (required) | A secret name | A `Secret` |
| audit sink | adapter | audit sink (required) | One audit record | Written, or an error |
| clock | adapter | clock (required) | Nothing | The current time, as a `Timestamp` |
| approval | effect | approval channel (required) | Gate ID, app instance, summary | `Approved`, `Denied(reason)`, or an error |
| upstream tools | effect | none, any number | An MCP `tools/call` | An MCP result |

Each compiled hook is one trait in `crates/core/src/hook.rs`. That file is the whole contract. A change to this table changes `docs/design.md` and that file in the same pull request.

## Layout

| Path | Contents | In git |
|---|---|---|
| `default/` | One plugin per slot. chaperone does not start without them. | Yes |
| `<kind>/included/` | Plugins that ship with chaperone | Yes |
| `<kind>/added/` | The operator's own plugins | No. `.gitignore` excludes them. |

- One directory holds one plugin.
- A plugin with two halves of different kinds is two plugins with the same name, one per kind directory. Each half names the other in `plugin.json`.
- A plugin in `default` or `included` must pass the contract test of every hook it serves.

## The plugin manifest

Each plugin directory holds a `plugin.json`. The strict reader reads it. It holds:

- `name`, `version` and `kind`
- `slot`, if the plugin can fill one
- `hooks`: the hooks it serves
- `secrets`: the secret parameters it needs. Never a value. A decision plugin takes none.
- `pairs_with`: the kind of the other half, if any
- for an effect plugin: `command`

`crates/core/src/plugin.rs` holds the exact shape. A compiled plugin's policy schema comes from its Rust type. The operator sets `secret_delivery` in `install.toml`, not here.

## Slots and overrule

1. Each slot needs exactly one plugin.
2. The plugin in `default/` fills a slot when `install.toml` names no other plugin for it.
3. To overrule a default, name another plugin for that slot in `install.toml`.
4. chaperone refuses to start in these cases:
   1. A slot is empty.
   2. `install.toml` names a plugin that does not exist.
   3. Two enabled plugins claim one slot and `install.toml` does not choose.
   4. A plugin names a pair half that does not exist.
5. A plugin on disk does nothing until `install.toml` enables it (G10).

## Never do these

1. Do not read another plugin's state, files or secrets.
2. Do not read a secret that `install.toml` does not bind to this plugin.
3. Do not log a secret value or a token (G9).
4. Do not depend on load order or directory order (G10).
5. Do not add a hook without a row in the catalog above and in `docs/design.md`.

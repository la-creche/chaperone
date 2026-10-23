# plugins/effect/AGENTS.md

Rules for effect plugins. Read `plugins/AGENTS.md` first.

An effect plugin is a separate process. chaperone launches it with the `command` from `plugin.json` and speaks MCP to it over stdio. chaperone is the MCP client. The plugin can be written in any language.

Two kinds of effect plugin exist:

| Kind | Its tools | Who sees them |
|---|---|---|
| upstream | Ordinary tools, such as `ha_call` | An app, through the manifest, if the policy grants them |
| hook plugin | Hook tools, such as the approval hook | Only the core (G8) |

## Rules

1. Read your secrets from the first message on stdin. `docs/design.md` section 7.5 states the delivery.
2. Keep each secret in memory only.
3. Answer every hook call with a result that matches the hook's schema. chaperone treats any other answer as a fault, and a fault is a deny (G2).
4. An approval plugin returns `Approved` only for a human approval of that exact gate ID.
5. An approval plugin owns any listener its flow needs, such as a callback endpoint. The core opens no inbound approval port.

## Never do these

1. Do not write a secret value to stdout, stderr or a log (G9). chaperone reads stderr as log text.
2. Do not use `"secret_delivery": "env"` in a plugin under `included/`. That exception is only for an operator's third-party server in `added/`.
3. Do not expose a hook tool and an upstream tool from one plugin. One plugin has one role.
4. Do not trust the arguments of a call because chaperone sent them. Check their shape anyway.

## Patterns

- `ha-approval` is the reference approval plugin. It sends the request through the operator's existing approval flow and waits for the tap.
- A third-party MCP server that reads secrets from the environment goes in `added/`, with `"secret_delivery": "env"` in `install.json`. chaperone logs a warning at each start.

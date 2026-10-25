# The version 1 run

This document lists what the operator does to run version 1 by hand (`docs/design.md` section 12). It names no deployment. Every address below is a TEST-NET-1 placeholder. The operator's own files live under `deploy/`, which git ignores, and under `plugins/effect/added/`, which git ignores too.

## 1. What the run proves

Version 1 is done when a LibreChat agent makes three calls through chaperone with this result:

1. An allowed call runs.
2. A call to a tool with no grant is denied.
3. A gated call returns "awaiting permission", the operator approves it on the phone, chaperone runs it, and an identical call collects the result.

The audit file shows all three.

## 2. Build

```bash
cargo build --release --workspace --locked
```

The binaries land in `target/release/`: `chaperone`, `chaperone-deny-all`, `chaperone-ha-approval`, `chaperone-ha-call` and `chaperone-editor`. chaperone looks for a plugin's program next to its own binary first (`docs/design.md` 7.7), so they stay together.

## 3. Files

| Path | Holds | Written by |
|---|---|---|
| `deploy/config/install.json` | The enabled plugins, their secret bindings and their arguments | The operator, by hand |
| `deploy/config/policy.json` | The app instance, its grants, its limits and its `ha-call` section | The operator, through the editor or by hand |
| `deploy/secrets/<name>` | One secret value per file, mode 0600 | The operator |
| `deploy/editor.token` | The editor's admin token, one line, mode 0600 | The operator |
| `deploy/vikunja-mcp.sh` | The wrapper that starts the Vikunja MCP server with its URL | The operator |
| `plugins/effect/added/vikunja/plugin.json` | The manifest of the Vikunja upstream, with the wrapper as its command | The operator |

Fill each placeholder before the run:

| Placeholder | Where | Put |
|---|---|---|
| `http://192.0.2.10:8123` | `install.json`, `ha-call` args | The Home Assistant URL |
| `http://127.0.0.1:1881/hook/approval` | `install.json`, `ha-approval` args | The hook of the Node-RED flow |
| `192.0.2.10:8310` | `install.json`, `ha-approval` args | The address where the flow posts the tap back. Not an unspecified address. |
| `http://192.0.2.20:3456` and the command | `deploy/vikunja-mcp.sh` | The Vikunja URL and the command that starts its MCP server |
| `REPLACE_ME` | Each file in `deploy/secrets/` and `deploy/editor.token` | The value, as one line with no trailing newline for a secret |
| `list_tasks`, `create_task` | `policy.json`, the `vikunja` grant | The tool names the Vikunja MCP server lists. chaperone warns at start about each granted tool the upstream does not list. |
| `light.kitchen` | `policy.json`, the `ha-call` section | The entities the agent may act on |
| The zero digest | `policy.json`, `token_sha256` | See section 5 |

The secrets `APPROVAL_TOKEN` and `RESUME_TOKEN` hold the same values as the flow's own environment.

## 4. Check

```bash
target/release/chaperone check deploy/config/install.json --plugins-dir plugins
```

```bash
target/release/chaperone check deploy/config/policy.json --plugins-dir plugins
```

Each prints `ok`, or the first rule the file breaks. The check reads no secret.

## 5. The token

```bash
target/release/chaperone token new librechat --config-dir deploy/config
```

It prints the token once and stores only its digest. Copy the token into the LibreChat configuration (section 8). Then remove the zero digest from `policy.json`, in the editor or by hand, and run the check again. The zero digest authenticates nothing, but each app instance holds at most two.

## 6. Serve

```bash
target/release/chaperone serve --config-dir deploy/config --plugins-dir plugins --audit-file deploy/audit.jsonl --secrets-dir deploy/secrets --admin-socket deploy/admin.sock --listen 127.0.0.1:8300 --allowed-host host.docker.internal:8300
```

chaperone refuses to start when a slot is empty, a secret cannot be read, an upstream does not start, or the approval channel does not list `approve`. It logs a warning for the env exception of `vikunja` and for each granted tool that an upstream does not list. It then serves MCP on the loopback address and the admin socket at `deploy/admin.sock`.

`--allowed-host` names the `Host` an app in Docker sends. LibreChat in Docker reaches the host as `host.docker.internal`.

## 7. The editor

```bash
target/release/chaperone-editor --listen 127.0.0.1:8301 --admin-socket deploy/admin.sock --config-dir deploy/config --token-file deploy/editor.token
```

Open `http://127.0.0.1:8301/policy`. The browser asks for a user name and a password. The user name is free. The password is the token in `deploy/editor.token`. Check and save go through the admin socket. The previous file stays as `policy.json.prev`.

## 8. LibreChat

LibreChat's MCP configuration takes a URL and headers for a streamable HTTP server. Add chaperone as the server named `chaperone`, with the token from section 5 in the `Authorization` header as `Bearer <token>`. The URL is `http://host.docker.internal:8300/mcp` from inside Docker. Keep the token out of the file: put it in an environment variable of the LibreChat container and reference the variable in the header, the way LibreChat's configuration allows.

The agent then sees one MCP server with the granted tools: `vikunja__list_tasks`, `vikunja__create_task` and `ha-call__call_service`.

## 9. The flow

Point the resume URL of the Node-RED flow at the `--listen` address of `ha-approval` (`docs/design.md` section 12). The flow's `APPROVAL_TOKEN` and `RESUME_TOKEN` equal the two secret files. Nothing else in the flow changes.

## 10. The three calls

Ask the agent to:

1. List the tasks. The audit holds `decided` with `allow`, then `ran`.
2. Call a tool that is not granted. The audit holds `decided` with `deny:tool_not_granted`.
3. Create a task. The agent gets "Awaiting permission for tool call vikunja__create_task". The phone shows the card. Tap Approve. The audit holds `decided` with the gate, `waiting`, then `ran`. Ask the agent to try again. It gets the result, and the audit holds `decided` with `allow` and `delivered`.

Deny the card instead, and the audit holds `failed` with `approval_denied`. An identical call is then denied until the gate expires.

## 11. Stop

Stop chaperone and the editor with SIGINT. chaperone stops its plugins with it.

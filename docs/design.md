# Design

This document states what chaperone is, what it guarantees and how its parts fit. `AGENTS.md` turns it into rules. When code and this document disagree, the code is wrong or this document needs a change in the same pull request.

## 1. Purpose

chaperone is a policy layer between an agent app and the tools that app uses. Examples of an agent app are LibreChat, Open WebUI and OpenHands. The app sends each tool call to chaperone. chaperone decides the call with a pure function over a policy file. It then runs the call, holds it for a human approval, or denies it.

The decision is deterministic. The same policy, request, counters and gate state give the same decision. No model takes part in a decision.

## 2. Threat model

chaperone assumes two untrusted parties:

1. **The model.** A model can be confused or prompt-injected. It must not reach a tool, an argument or a host outside its grant.
2. **The app.** An app process can be compromised. It must not reach more than its grant, and it must never hold an upstream credential.

The work comes in two stages:

| Stage | The app | What bounds the app |
|---|---|---|
| (a) | Trusted. It runs outside any sandbox. chaperone is its MCP server. | chaperone decides every tool call. |
| (b) | Untrusted. It runs inside an sbx microVM. | The sandbox network allows only chaperone. chaperone decides every call. |

Version 1 is stage (a). Stage (b) is designed after version 1 works. Version 1 keeps two constraints so that stage (b) needs no policy change:

1. A front door is a plugin. Stage (b) adds a second front door: an OpenAI-compatible model pass-through.
2. The security boundary is the app instance. One app instance becomes one sandbox in stage (b).

## 3. The guarantee

Each rule has an ID. Code comments, tests and pull requests cite the ID.

| ID | Rule |
|---|---|
| G1 | **Deterministic.** The same policy, request, counters and gate state give the same decision. No model call anywhere in the core. |
| G2 | **Fail closed.** An unhandled error, a plugin fault or an unanswered hook is a deny. A policy that does not load denies every call. An empty slot or a missing plugin refuses start. |
| G3 | **Pure decision.** The decision function does no I/O. It reads no clock and no global state. The caller passes the time as an argument. |
| G4 | **One identity kind.** A credential resolves to one app instance, or to nothing. An identity plugin can narrow what that app instance may reach. It can never widen it. |
| G5 | **chaperone holds every credential.** An upstream credential never reaches an app, a model or a sandbox. |
| G6 | **Audit before acting.** chaperone writes a decision record before it runs a call. It writes a final record before it returns a result. A call that fails before a decision has one final record. If a decision record fails, chaperone does not run the call. If a final record fails, chaperone does not return the result. |
| G7 | **Plugins only narrow.** The policy file is the ceiling. Each decision hook can deny, gate or pass. The most restrictive result wins. No plugin can grant reach that the policy file does not grant. |
| G8 | **No hook is visible to a model.** A manifest lists only upstream tools. A hook tool of an effect plugin never appears in a manifest. |
| G9 | **Secrets stay hidden.** No secret value appears in a log line, an audit record, a manifest, a tool result, argv, the policy file or an error message. A log line can name a secret. It never shows the value. An audit record holds only policy-bounded names and fixed-shape values. |
| G10 | **The install file decides.** A plugin on disk does nothing until the install file enables it. Directory order never changes behavior. |

Limits of the guarantee:

- An upstream plugin that holds a secret is trusted code. chaperone blanks exact copies of a secret in a result (G9). It cannot detect an encoded copy, such as base64.
- An agent that can change chaperone's code can change where a secret goes. The defense is outside the code: secrets belong to a separate OS user, and only a maintainer releases code.

## 4. Parts

| Part | Path | Job |
|---|---|---|
| core | `crates/core` | Policy types, the strict JSON reader, the decision function, the decision-hook traits. No I/O. |
| chaperone | `crates/chaperone` | The program. It hosts the adapter plugins and the effect plugins, writes the audit, serves the admin socket and runs the CLI. |
| editor | `crates/editor` | A separate program. It serves HTML forms that edit the policy file. |
| plugins | `plugins/` | Every plugin. See section 7. |

## 5. The decision

### 5.1 Inputs and output

The decision function takes:

- the loaded policy
- the resolved app instance, or nothing
- the tool name and its arguments
- the rate counter of the app instance
- the pending gates and the approved gates of the app instance
- the results of every enabled fence plugin
- the current time, as an argument

It returns one of:

- `Allow`
- `Deny(reason)`
- `Gate(gate_id)`: the call waits for an approval

### 5.2 Order

The rows apply in this order. The first row that matches decides.

0. No valid policy is loaded: `Deny(policy_not_loaded)`.
1. No app instance, or an app instance the policy does not hold: `Deny(unknown_credential)`.
2. The app instance made `calls_per_minute` calls or more in the current minute: `Deny(rate_limited)`.
3. The policy does not grant the tool, or the caller's narrowed reach excludes it: `Deny(tool_not_granted)`.
4. A policy argument fence refuses an argument: `Deny(argument_fenced)`.
   - An `allow` fence needs the argument present and equal to a listed value.
   - A `deny` fence refuses a listed value, and refuses an argument that is not a scalar.
5. A fence plugin returns deny: `Deny(fence)` with that plugin's reason. The reason is a fixed text of the plugin. A fence plugin faults: `Deny(fence_fault)`. Fences run in plugin name order. The first deny wins.
6. The policy marks the tool `"approval": "required"`, or a fence plugin returns gate:
   1. The gate is denied and not expired: `Deny(approval_denied)`.
   2. The gate is approved and not expired: `Allow`.
   3. The gate is pending and not expired: `Gate(gate_id)`.
   4. The count of pending gates that are not expired is at `max_pending_gates`: `Deny(gate_cap)`.
   5. Otherwise: `Gate(gate_id)`.
7. Otherwise: `Allow`.

The core pull request may refine the reason names. It may not change the order without a change to this section.

### 5.3 Gates

The gate ID is the first 16 bytes of a SHA-256 hash over the app instance, the upstream, the tool name and the canonical arguments, separated by NUL bytes. The canonical arguments are the arguments with sorted keys and no white space. An identical retry produces the same gate ID.

A gated call goes through these steps:

1. The core calls the approval hook of the approval channel slot.
2. chaperone waits up to the wait window for the answer. The default window is 60 seconds.
3. If the answer comes inside the window, the call runs or is denied at once.
4. If no answer comes inside the window, chaperone returns a result that says: "waiting for approval, gate `<gate_id>`, call again with the same arguments after approval".
5. chaperone keeps waiting for the hook answer until the gate expires.
6. An identical call after the approval finds the gate approved and runs.

A gate is *pending* while it waits for an answer. It is *approved* after the approval channel answers `Approved`. The policy caps the number of pending gates per app instance, so a looping model cannot flood the operator's phone.

Only the approval channel can complete a gate. It can complete only a gate that a decision created, only with a matching gate ID, and only before the gate expires. A gate completion does not break G7: the policy already said "allowed if approved".

### 5.4 Audit records

`CallAudit` in `crates/core` is the only way to build an audit record. Each call path yields these records:

| Path | Records |
|---|---|
| The call fails before a decision | `failed` |
| Deny | `decided` |
| Allow, then the call runs | `decided`, `ran` |
| Allow, then the call cannot run | `decided`, `failed` |
| Gate, then the wait window ends | `decided`, `waiting` |
| Gate, then the approval channel fails | `decided`, `failed` |
| Gate, then the approval comes | `decided`, then `ran` or `failed` |

Each record holds a run ID and a call number. These values match all records of one call.

Each record also holds the start time and the event time. A final record uses the time when the call ended.

The record keeps an app ID only when the policy configures that exact app instance. All other app text becomes no app.

The record keeps a tool name only when the policy configures that exact tool. All other tool text becomes `<unknown>`.

The record keeps the arguments only as the SHA-256 of their canonical form. Closed types prevent other text from entering these fields.

`CallAudit` consumes itself when it makes the decision record. The next state can make only the applicable final records.

## 6. Configuration

All configuration is JSON. The strict reader reads every file. It refuses duplicate keys, a byte order mark, invalid UTF-8, unknown fields and input over the size cap. The Rust types are the source of truth. chaperone generates the JSON Schema from the types.

| File | Who writes it | What it holds |
|---|---|---|
| `install.json` | The operator, by hand | Enabled plugins, the plugin for each slot, launch commands, secret bindings |
| `policy.json` | The operator, through the editor or by hand | App instances, token digests, grants, argument fences, gates, limits |
| `plugin.json` | The plugin author | One per plugin directory. See section 7.4. |
| A secret file | The operator | One secret value per file |

Rules:

- Each file names its schema in `$schema`.
- Grants and install entries take a typed `note` field for the reason. JSON has no comments.
- The policy file names a plugin by name only. It cannot launch a binary or bind a secret.
- The editor's OS user cannot write `install.json`.
- chaperone reloads `policy.json` when the file changes. A reload that fails denies every call until a valid file loads (G2).
- A JSON Schema cannot express a rule across files. `chaperone check` is the only authority on a valid configuration.

## 7. Plugins

### 7.1 Kinds

| Kind | How it runs | Purity | Example jobs |
|---|---|---|---|
| decision | Compiled into chaperone | Pure. The purity lint applies. | Identity, argument fences |
| adapter | Compiled into chaperone | Does I/O | Front door, secret source, audit sink |
| effect | A separate process. chaperone speaks MCP to it over stdio. | Does I/O | Approval channel, upstream tools |

### 7.2 Slots

A slot is a job that exactly one plugin must do. chaperone refuses to start when a slot is empty.

| Slot | Kind | Default plugin |
|---|---|---|
| front door | adapter | MCP over streamable HTTP |
| identity | decision | Bearer token to app instance |
| secret source | adapter | One file per secret |
| audit sink | adapter | Append-only JSONL file |
| approval channel | effect | Answers `Denied("no approval channel")` to every request |

The default approval channel makes every gated call fail closed until the operator enables a real channel.

Fences and upstreams are not slots. The install file can enable any number of them.

### 7.3 Layout

| Path | Contents | In git |
|---|---|---|
| `plugins/default/` | One plugin per slot. chaperone does not start without them. | Yes |
| `plugins/<kind>/included/` | Plugins that ship with chaperone | Yes |
| `plugins/<kind>/added/` | The operator's own plugins | No |

`<kind>` is `adapter`, `decision` or `effect`. The directory names the kind. A plugin with two halves of different kinds is two plugins with the same name, one per kind directory. Each half declares the other in `plugin.json`. chaperone refuses to start when a declared half is missing.

To overrule a default plugin, the operator names a different plugin for that slot in `install.json`. When the install file names no plugin for a slot, the default plugin fills it. chaperone refuses to start when two enabled plugins claim one slot and the install file does not choose.

A release binary contains the decision and adapter plugins from `default` and `included`. A decision or adapter plugin in `added` needs a build from source. An effect plugin in `added` works with a release binary, because it runs as its own process.

### 7.4 The plugin manifest

Each plugin directory holds a `plugin.json`. It holds:

- the name, the version and the kind
- the slot the plugin can fill, if any
- the hooks it serves
- the secret parameters it needs: the names under which it receives secrets. A decision plugin takes none.
- the kind of its other half, if it has two halves
- for an effect plugin: the launch command

An effect plugin serves one role: upstream or approval. A compiled plugin's policy-section schema comes from its Rust type, not from `plugin.json`, so the schema has one source. The secret delivery mode is the operator's choice, so it sits in `install.json`.

### 7.5 Secret delivery to an effect plugin

chaperone sends each bound secret over the plugin's stdin, in the first message after launch. A secret never goes on argv or into the environment.

One exception exists for third-party MCP servers that read secrets from the environment. The install file can set `"secret_delivery": "env"` for one plugin. chaperone then logs a warning at each start. The warning names the plugin and the cost. A plugin in `default` or `included` can never use this exception.

### 7.6 The front door

The front door is the adapter that receives an app's connection. It turns each request into a call of the `Gateway` trait in `crates/core`, and turns the answer back into its protocol. It decides nothing.

An app sees one MCP server with the tools of every granted upstream. Each tool has an exposed name: `<upstream>__<tool>`, for example `vikunja__list_tasks`.

- A plugin name cannot contain `__`, so the first `__` always ends the upstream name.
- An exposed name holds only `A-Z`, `a-z`, `0-9`, `_` and `-`, up to 50 characters. LibreChat passes each tool to the model as `<tool>_mcp_<server>`, and model APIs allow 64 such characters.
- The manifest leaves out a tool whose exposed name breaks these rules. chaperone logs a warning that names the tool.

Version 1 configures the LibreChat MCP server name as `chaperone`. This name has nine characters. A 50-character exposed name becomes 64 characters after LibreChat adds its suffix.

In version 1, the default front door serves plain HTTP only on a loopback address. chaperone refuses to start when the front door address is not loopback and TLS is not set up. TLS comes before the move to the host.

## 8. Secrets

- A secret is one file, mode 0600. chaperone checks the owner and the mode before it reads the file.
- In production, a dedicated `chaperone` OS user owns the secrets directory. Agents that edit code run as a different user and cannot read it.
- In code, a secret is a `Secret` value. It has no `Display` and no `Serialize`. Its `Debug` prints only the name. One named method exposes the value. The memory is wiped when the value is dropped.
- chaperone replaces each exact secret value in a tool result with `[redacted]`. It does this before it returns the result and before it writes the final audit record.

## 9. Tokens

`chaperone token new <app>` creates a bearer token for an app instance:

1. It takes 32 bytes from the OS random source, through `getrandom`.
2. It writes the bytes as 64 lower-case hex characters. This text is the token. It prints the token once.
3. It stores only the SHA-256 digest of the token text in `policy.json`, through `sha2`.

The `bearer` identity plugin refuses bearer text that is not 64 lower-case hex characters. A digest of any other text in `policy.json` authenticates nothing.

Each app instance can hold two digests, so a token can rotate with no downtime. chaperone compares digests in constant time, through `subtle`. chaperone uses no cryptography code of its own.

## 10. Admin socket and CLI

The admin socket is a Unix socket. Only the editor's OS user can open it. It is never on the front-door port.

| CLI command | Socket endpoint | Job |
|---|---|---|
| `chaperone schema` | `GET /schema` | Print the JSON Schema of every config file and every plugin policy section |
| `chaperone check <file>` | `POST /check` | Run the strict reader and every cross-file rule |
| `chaperone token new <app>` | `POST /token` | Create a token, as in section 9 |

A CLI command and its endpoint call the same function. They cannot drift. The CLI works when the chaperone service is down, so a broken policy can be fixed.

## 11. The editor

The editor is a separate program, so a change to the editor needs no chaperone restart.

- It runs as its own OS user, on its own port, with its own admin token.
- It renders server-side HTML forms. It uses no JavaScript framework.
- It builds each form from `chaperone schema`. A new plugin needs no editor code.
- It saves only after `chaperone check` passes. It then renames the file atomically and keeps the previous version.
- It shows that a token digest exists. It never shows a token or a secret.

## 12. Version 1

Version 1 proves the idea with one client app.

| Part | Choice |
|---|---|
| Client app | LibreChat, run with Docker Compose |
| Upstream | An existing Vikunja MCP server, unchanged, with the env exception |
| Decision plugin | `ha-call` decision half: an entity allow-list for Home Assistant calls |
| Effect plugins | `ha-call` effect half: the Home Assistant call. `ha-approval`: the approval channel, through the operator's existing approval flow. |

Version 1 is done when a LibreChat agent makes three calls with this result:

1. An allowed call runs.
2. A call to a tool with no grant is denied.
3. A gated call waits, the operator approves it on the phone, and it runs.

The audit file shows all three calls.

Version 1 is installed by hand. The project publishes tagged versions with built binaries. A release pipeline is not part of version 1.

## 13. Build order

One pull request per step:

1. `AGENTS.md` files and this document.
2. `core`, in two pull requests:
   1. The workspace, CI, the strict reader, the name types, `Secret`, argument values and time.
   2. The config types, slot resolution, the decision, the hook traits and the property tests.
3. In two pull requests:
   1. The `Gateway` contract, exposed names, the `bearer` identity plugin and the `audit-jsonl` audit sink. The audit sink moves here from step 5, so the first program that runs already writes the audit (G6).
   2. The `chaperone` program and the `mcp-http` front door.
4. The effect host, the upstream result check and the Vikunja upstream.
5. The secret source.
6. Gates, the approval hook and `ha-approval`.
7. `ha-call`, both halves.
8. The admin socket, the CLI and the editor.

## 14. Open items

| Item | Settle in |
|---|---|
| The final name of the approval hook, and its answer type | Step 6 |
| The exact framing of the secret message on stdin | Step 4 |
| The adapter traits: front door, secret source, audit sink | Steps 3 and 5 |
| JSON Schema generation for the editor | Step 8 |
| Stage (b): sandbox per app instance, the OpenHands runtime, the model pass-through | After version 1 |

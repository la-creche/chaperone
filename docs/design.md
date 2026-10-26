# Design

This document states what chaperone is, what it guarantees and how its parts fit. `AGENTS.md` turns it into rules. When code and this document disagree, the code is wrong or this document needs a change in the same pull request.

## 1. Purpose

chaperone is a policy layer between an agent app and the tools that app uses. The app is an agent runtime that runs inside an sbx microVM, the sandbox. The app sends each tool call to chaperone. chaperone decides the call with a pure function over a policy file. It then runs the call, holds it for a human approval, or denies it.

chaperone sees tool calls only. The sandbox reaches the model gateway directly, outside chaperone.

The decision is deterministic. The same policy, request, counters and gate state give the same decision. No model takes part in a decision.

## 2. Threat model

chaperone assumes two untrusted parties:

1. **The model.** A model can be confused or prompt-injected. It must not reach a tool, an argument or a host outside its grant.
2. **The app.** An app process can be compromised. It must not reach more than its grant, and it must never hold an upstream credential.

The sandbox is the trust boundary. chaperone trusts nothing that comes out of the sandbox. The sandbox network lets the app reach a tool only through chaperone. chaperone is the MCP server of the app and decides every tool call. Version 1 is this design.

The security boundary inside chaperone is the app instance. One app instance is one sandbox.

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
| core | `crates/core` | Policy types, the strict reader, the decision function, the hook traits. No I/O. |
| chaperone | `crates/chaperone` | The program. It hosts the adapter plugins and the effect plugins, writes the audit, serves the admin socket and runs the CLI. |
| plugins | `plugins/` | Every plugin. See section 7. |
| run-as | `crates/run-as` | The helper `chaperone-as`. It starts an effect plugin as its own OS user (section 8). |

## 5. The decision

### 5.1 Inputs and output

The decision function takes:

- the loaded policy
- the resolved app instance, or nothing
- the tool name and its arguments
- the rate counter of the app instance
- the count of the calls of the app instance to the upstream that are in flight
- the pending gates and the approved gates of the app instance
- the results of every enabled fence plugin
- the current time, as an argument

It returns one of:

- `Allow`
- `Deny(reason)`
- `Gate(gate_id)`: the call waits for an approval

The `chaperone` program bounds the time of one decision. A decision that does not return inside the bound fails the call before a decision, with the fault `no_decision` (G2).

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
6. The upstream grant sets `max_inflight`, and that many calls of the app instance to the upstream are in flight: `Deny(rate_limited)`. Rows 2 and 6 give one reason, because each one limits the load of an app instance. A call that row 7 gates skips this row when its gate exists and is not expired. That call starts no run. It gets the waiting text, the kept result or `approval_denied` (section 5.3).
7. The policy marks the tool `approval = "required"`, or a fence plugin returns gate:
   1. The gate is denied and not expired: `Deny(approval_denied)`.
   2. The gate is approved and not expired: `Allow`.
   3. The gate is pending and not expired: `Gate(gate_id)`.
   4. The count of pending gates that are not expired is at `max_pending_gates`: `Deny(gate_cap)`.
   5. Otherwise: `Gate(gate_id)`.
8. Otherwise: `Allow`.

The core pull request may refine the reason names. It may not change the order without a change to this section.

### 5.3 Gates

The gate ID is the first 16 bytes of a SHA-256 hash over the app instance, the upstream, the tool name and the canonical arguments, separated by NUL bytes. The canonical arguments are the arguments with sorted keys and no white space. An identical retry produces the same gate ID.

A gated call never holds the app. It goes through these steps:

1. The decision creates the gate. chaperone writes the `decided` record, then a `waiting` record, and returns at once an error result with a fixed text: "Awaiting permission for tool call `<exposed name>` (gate `<gate_id>`). Call again with the exact same arguments to gather the result." The text is the same for every identical call, so a model sees one stable message. The app's turn ends there.
2. chaperone calls the approval hook of the approval channel slot on its own task and waits for the answer until the gate expires.
3. When the answer is `Approved`, chaperone runs the call through its upstream, writes the `ran` record of the original call, and keeps the checked result until the gate expires.
4. When the answer is `Denied`, chaperone writes the `failed` record of the original call with `approval_denied`. The gate stays denied until it expires.
5. An identical call while the gate is pending, or while the call runs, returns the same text again, with its own `decided` and `waiting` records and nothing after them. An identical call after the run collects the kept result, with a `decided` and a `delivered` record, and removes the gate. An identical call after a denial is denied with `approval_denied`.

A gate is *pending* while it waits for an answer, *running* while the call runs, *done* while it holds a result, and *denied* after a denial or a fault. The policy caps the number of pending gates per app instance, so a looping model cannot flood the operator's phone.

Only the approval channel can complete a gate. It can complete only a gate that a decision created, only with a matching gate ID, and only before the gate expires. A gate completion does not break G7: the policy already said "allowed if approved".

The approval hook is the tool `approve` of the approval channel plugin. chaperone calls it once per gate, when the decision creates the gate, with these arguments:

| Argument | Value |
|---|---|
| `gate` | The gate ID, as 32 lower-case hex characters |
| `app` | The app ID |
| `tool` | The exposed name of the tool |
| `arguments` | The arguments of the call, as the app sent them |

The answer is one text block that holds one strict JSON object: `{"answer":"approved"}` or `{"answer":"denied","reason":"<text>"}`. The reason is at most 200 characters. Any other result is a fault: an error result, another block, other JSON, an unknown field. A fault denies the gate for the rest of its life (G2), and the call fails with `approval_fault`.

A gate lives 10 minutes from its creation (section 5.5). A denial, or a fault, holds for that life: an identical call finds the gate denied. An approval runs one call, and its result is collected once. When two identical calls read the done gate at the same time, one call collects the result. The other call fails with `approval_spent` and does not run. chaperone removes the gate when the result is collected, so the next identical call needs a new approval. A result that nobody collects goes with the gate when it expires.

In version 1 the app collects a kept result by asking again. Nothing tells the app that the result is there. A later step can change this: the agent runtime in the sandbox subscribes to chaperone for the results of its gates, and chaperone publishes each kept result to it when the run ends. The kept result and the `delivered` record stay as they are, so that step adds a transport and changes no record (section 14).

### 5.4 Audit records

`CallAudit` in `crates/core` is the only way to build an audit record. Each call path yields these records:

| Path | Records |
|---|---|
| The call fails before a decision | `failed` |
| Deny | `decided` |
| Allow, then the call runs | `decided`, `ran` |
| Allow, then the call cannot run | `decided`, `failed` |
| Gate | `decided`, `waiting`, then one of the rows below when the answer comes |
| Gate, then the approval channel fails | `failed` |
| Gate, then the approval is denied | `failed` |
| Gate, then the approval comes and the call runs | `ran` or `failed` |
| An identical call collects a kept result | `decided`, `delivered` |

Each record holds a run ID and a call number. These values match all records of one call.

Each record also holds the start time and the event time. A final record uses the time when the call ended. For a gated call, that is when the approval answer is handled, which can be minutes after the app's request returned.

The record keeps an app ID only when the policy configures that exact app instance. All other app text becomes no app.

The record keeps a tool name only when the policy configures that exact tool. All other tool text becomes `<unknown>`.

The record keeps the arguments only as the SHA-256 of their canonical form. Closed types prevent other text from entering these fields.

`CallAudit` writes each record through the audit sink as it changes state. The next state exists only after the sink reports the record durable (G6). No other code holds a record, so no call can run before its decision record. The next state can make only the applicable final records. The transition from a gated call to an allowed call arrives with the approval answer type in step 6.

### 5.5 Time bounds

| Part | Bound | Why |
|---|---|---|
| The decision | 5 seconds. A decision that takes longer fails the call with `no_decision` (G2). | A pure function over a policy file takes far less. A larger bound holds a caller longer on a stuck fence. A smaller bound fails a call on a slow host. |
| The identity hook | None | The hook runs on the caller's thread, because `Credentials` borrows the request. A hook that never returns holds only that one call. A bound would need an owned copy of the bearer token. The hook is compiled code that the operator chooses in `install.toml`. |
| A call to an upstream | The `timeout_s` of the upstream grant of the app instance: 1 to 120 seconds, and 30 seconds when the grant does not set it (section 6). A call that takes longer fails with `upstream_timeout` (G2). The audit holds a `failed` record. | Most tools answer in well under a second. A delegate call of `attendance` can take up to 120 seconds (section 12). A larger bound holds a caller on a stuck upstream. The upstream may still finish its work after the bound. chaperone does not retry (`crates/chaperone/AGENTS.md`). |
| The life of a gate | 10 minutes from its creation. The approval hook call ends with it, and so does a kept result. | Long enough for a human away from the phone. Short enough that a forgotten gate does not approve a call hours later. |

A call is in flight from the start of its decision until its final record (row 6 of section 5.2). Each call counts the calls in flight before it, so two calls never read the same count. A call that the decision denies or gates is in flight only until it returns. The run of an approved gate is in flight until its `ran` or `failed` record. The limit does not stop that run, because its decision came before. The limit also does not stop an identical call of a live gate, because that call starts no run (row 6).

## 6. Configuration

The install file, the policy file and the plugin manifest are TOML. No file has a `$schema` field. The strict reader reads every file. It refuses duplicate keys, a byte order mark, invalid UTF-8, unknown fields and input over the size cap. The Rust types are the source of truth.

| File | Who writes it | What it holds |
|---|---|---|
| `install.toml` | The operator, by hand | Enabled plugins, the plugin for each slot, launch commands, secret bindings, the front door guard |
| `policy.toml` | The operator, by hand or with an external tool | App instances, token digests, grants, argument fences, gates, limits |
| `plugin.toml` | The plugin author | One per plugin directory. See section 7.4. |
| A secret file | The operator | One secret value per file |

Rules:

- Grants and install entries take a typed `note` field for the reason. A TOML file can also hold comments.
- The policy file holds maps keyed by app ID, plugin name, tool name and argument name, as TOML tables. A tool name or an argument name can hold a `.`, so it needs a quoted key, such as `"tasks.list" = {}`.
- An install entry of an effect plugin can hold `args`: arguments that chaperone appends to the command of the manifest at launch. The manifest names the program. The install file adds what differs per deployment, such as an address. An argument is never a secret value (G9).
- An install entry of an effect plugin can hold `user`: the OS user that the plugin runs as (section 8). The value is `mcp-`, then `a-z`, then 1 to 30 of `a-z`, `0-9` and `-`. An entry of a plugin with no effect half that holds `user` refuses start. Any other value refuses start.
- The install entry of the front door plugin can hold `guard`: `loopback` or `host-firewall` (section 7.6). An entry without `guard` takes `loopback`. An entry of another plugin that holds `guard` refuses start. Any other value refuses start.
- An upstream grant can hold `timeout_s`: the bound of one call to that upstream, in whole seconds (section 5.5). The value is an integer from 1 to 120. A grant without it takes 30. Any other value does not load, and the error names the rule.
- An upstream grant can hold `max_inflight`: the most calls of the app instance to that upstream that can be in flight at one time (section 5.2). The value is an integer from 1 to 8. A grant without it sets no limit. Any other value does not load, and the error names the rule.

  ```toml
  [apps.research.grants.attendance]
  timeout_s = 120
  max_inflight = 2
  ```

- The policy file names a plugin by name only. It cannot launch a binary or bind a secret.
- An external tool that writes the policy file runs as an OS user that cannot write `install.toml`.
- chaperone reloads `policy.toml` when the file changes. Before each call, it compares the device, inode, size and modification time of the file with the file it loaded. One policy decides the whole call. A reload that fails denies every call until a valid file loads (G2). A bad write by the operator therefore stops every app until a valid file lands.
- `chaperone check` is the only authority on a valid configuration. It runs the strict reader and every rule across files.

## 7. Plugins

### 7.1 Kinds

| Kind | How it runs | Purity | Example jobs |
|---|---|---|---|
| decision | Compiled into chaperone | Pure. The purity lint applies. | Identity, argument fences |
| adapter | Compiled into chaperone | Does I/O | Front door, secret source, audit sink, clock |
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
| clock | adapter | The OS clock |

The default approval channel makes every gated call fail closed until the operator enables a real channel.

The clock plugin is the one source of the time that the program passes to the decision (G3). It is trusted code, like every adapter. A clock that runs slow or backwards weakens the rate limit and the gate expiry, so the default reads the OS clock and nothing else.

Fences and upstreams are not slots. The install file can enable any number of them.

### 7.3 Layout

| Path | Contents | In git |
|---|---|---|
| `plugins/default/` | One plugin per slot. chaperone does not start without them. | Yes |
| `plugins/<kind>/included/` | Plugins that ship with chaperone | Yes |
| `plugins/<kind>/added/` | The operator's own plugins | No |

`<kind>` is `adapter`, `decision` or `effect`. The directory names the kind. A plugin with two halves of different kinds is two plugins with the same name, one per kind directory. Each half declares the other in `plugin.toml`. chaperone refuses to start when a declared half is missing.

To overrule a default plugin, the operator names a different plugin for that slot in `install.toml`. When the install file names no plugin for a slot, the default plugin fills it. chaperone refuses to start when two enabled plugins claim one slot and the install file does not choose.

`crates/core/src/hook.rs` holds every contract between chaperone and a compiled plugin: the trait a decision or adapter plugin implements, and the `Gateway` trait a front door calls. A plugin implements a trait from that module and nothing else of `core`.

A release binary contains the decision and adapter plugins from `default` and `included`. `crates/chaperone/src/registry.rs` is the one table that names each compiled plugin and how the build constructs it, slot plugins and fences alike. A compiled plugin that `install.toml` puts in a slot without a row there refuses start (G2). A decision or adapter plugin in `added` needs a row and a build from source. An effect plugin in `added` works with a release binary, because it runs as its own process.

### 7.4 The plugin manifest

Each plugin directory holds a `plugin.toml`. It holds:

- the name, the version and the kind
- the slot the plugin can fill, if any
- the hooks it serves
- the secret parameters it needs: the names under which it receives secrets. A decision plugin takes none.
- the kind of its other half, if it has two halves
- for an effect plugin: the launch command

An effect plugin serves one role: upstream or approval. The shape of a compiled plugin's policy section comes from its Rust type, not from `plugin.toml`, so the shape has one source. The secret delivery mode is the operator's choice, so it sits in `install.toml`.

### 7.5 Secret delivery to an effect plugin

chaperone sends each bound secret over the plugin's stdin, in the first message after launch. A secret never goes on argv or into the environment.

The first message is one line: a JSON object with one key, `secrets`, whose value maps each secret parameter of the manifest to its value, followed by one newline. Nothing else is on the line. chaperone writes it before the MCP `initialize` request. A plugin that declares no secret receives no such line, so a third-party server that declares none sees plain MCP from the first byte.

```json
{"secrets":{"VIKUNJA_TOKEN":"..."}}
```

One exception exists for third-party MCP servers that read secrets from the environment. The install file can set `"secret_delivery": "env"` for one plugin. chaperone then logs a warning at each start. The warning names the plugin and the cost. A plugin in `default` or `included` can never use this exception.

### 7.6 The front door

The front door is the adapter that receives an app's connection. It turns each request into a call of the `Gateway` trait in `crates/core`, and turns the answer back into its protocol. It decides nothing.

An app sees one MCP server with the tools of every granted upstream. Each tool has an exposed name: `<upstream>__<tool>`, for example `vikunja__list_tasks`.

- A plugin name cannot contain `__`, so the first `__` always ends the upstream name.
- An exposed name holds only `A-Z`, `a-z`, `0-9`, `_` and `-`, up to 50 characters. LibreChat passes each tool to the model as `<tool>_mcp_<server>`, and model APIs allow 64 such characters.
- The manifest leaves out a tool whose exposed name breaks these rules. chaperone logs a warning that names the tool.

Version 1 has no client that adds the LibreChat suffix. The agent runtime of version 1 names its connection to chaperone `ch`, so the model sees `mcp__ch__<upstream>__<tool>`. The 50-character budget can widen (section 14).

`chaperone serve` starts the front door. It takes `--config-dir` (the directory of `install.toml` and `policy.toml`), `--plugins-dir`, `--audit-file`, `--secrets-dir` and `--listen`. Section 8 gives the defaults of `--config-dir` and `--plugins-dir`. The front door reads each request body through the strict reader before the MCP library parses it, with a cap of 1 MiB. It accepts only loopback `Host` headers, to stop DNS rebinding. Each `--allowed-host` adds one more, such as `host.docker.internal:8300` for an app in Docker.

The front door answers `GET /healthz` with no bearer. The answer is `200` with the body `{"ok":true}` while a valid policy is loaded. It is `503` with the body `{"ok":false}` while no valid policy is loaded (section 6). The body is fixed. It shows no policy content, no secret and no version.

The default front door serves plain HTTP. The guard is the rule that limits who reaches the front door address. The install entry of the front door plugin sets it:

| `guard` | Addresses that start | What the operator states |
|---|---|---|
| `loopback`, the default | A loopback address | Nothing. Only the host reaches the port. |
| `host-firewall` | A loopback address or a LAN unicast address | A host firewall rule limits who reaches the port. |

```toml
[plugins.mcp-http]
guard = "host-firewall"
```

chaperone refuses to start in these cases. The error names the rule.

1. The address is unspecified: `0.0.0.0` or `::`.
2. The address is multicast or broadcast.
3. The address is not loopback, and the guard is `loopback`.

With `host-firewall` and a LAN address, chaperone logs a warning at each start. The warning names the address and states that only the host firewall limits who reaches it. chaperone does not check the firewall. An app on the LAN sends the LAN address in its `Host` header, so the operator adds it with `--allowed-host`, such as `192.0.2.10:8300`.

### 7.7 The effect host

The effect host is the part of `chaperone serve` that runs effect plugins. It is the MCP client of each one.

Start:

1. After the configuration loads, the host launches each active upstream with the `command` of its manifest, in plugin name order, then the approval channel the same way. A command whose program has no directory is looked up next to the chaperone binary first, then on `PATH`, so the plugins that ship with chaperone are found before any other program of that name.
2. The host pipes stdin, stdout and stderr. It writes the secret line of section 7.5 when the manifest declares a secret. It sends the MCP `initialize` request, then `tools/list`, and keeps the list.
3. A launch that fails, an `initialize` that fails or a `tools/list` that fails refuses start (G2). An approval channel that does not list the tool `approve` refuses start.
4. The host reads stderr as log text. It logs each line with the plugin name, after it blanks each exact secret value (G9).

An effect plugin whose install entry holds `user` starts through the helper `chaperone-as` (section 8). The host runs `chaperone-as <user> <program> <args...>`, with the helper next to the chaperone binary. The program must be an absolute path, or a program next to chaperone. The host does not look it up on `PATH`. A missing helper, or a program that is not absolute, refuses start. A plugin without `user` starts as the user of chaperone.

A call:

1. The decision allowed the call and the `decided` record is durable (G6).
2. The host sends `tools/call` to the upstream with the tool name and the arguments. It waits up to the bound of section 5.5.
3. The result check: every content block is text, and the text of all blocks is at most 1 MiB together. A block of another type, or more text, fails the call with `bad_result`. Structured content is not forwarded. An MCP error from the upstream is a result with `is_error` set and the error message as its text.
4. The host blanks each exact secret value in each text block (section 8).
5. chaperone writes the `ran` record with the upstream's `is_error` flag, then returns the result.

The `_meta` of each `tools/call` holds the key `chaperone.app`. Its value is the app ID of the call, as a string. The approval channel gets the same key. The app ID is not a secret. The `_meta` holds no token, no secret and no session of chaperone. An effect plugin can use the app ID as the identity of the caller, because chaperone resolved it from the bearer token (G4). The app cannot set this key. A decision plugin does not get it.

An upstream that is not running, or whose connection is closed, fails a call with `not_connected`. Version 1 does not restart an upstream. The operator restarts chaperone.

The manifest an app sees holds a tool when the policy grants it, the caller's reach holds it, the upstream lists it and its exposed name is valid. chaperone logs a warning at start for each granted tool that its upstream does not list.

### 7.8 The fence hooks

A fence implements the trait `Fence` of `crates/core/src/hook.rs`. chaperone calls its three hooks at fixed points:

| Hook | When it runs | What it returns |
|---|---|---|
| `prepare` | At each policy load, once per app instance | The section of the app instance in the type of the fence, or a refusal of the section |
| `check_sections` | At each policy load, once, after every `prepare` of the fence | Nothing, or a refusal that names a caller app ID, a target app ID and the rule |
| `check` | At each call, in the decision (section 5.2) | Pass, `Deny(reason)` or `Gate` |

`check_sections` gets the prepared sections of every app instance, by app ID, and nothing else (G3). It can only refuse. A refusal stops the policy load (G2). `chaperone check` then refuses the file, and after a reload chaperone denies every call until a valid file loads. The rule of a refusal is a fixed text of the fence (G9). The default `check_sections` refuses nothing.

## 8. Secrets

- A secret is one file in the secrets directory, named after the secret, mode 0600. chaperone opens the file without following a symbolic link. It then checks the opened file: a regular file, mode 0600, owned by the user that runs chaperone. A file that fails a check refuses start.
- A secret value is one line of UTF-8, at most 4096 bytes, with no control character and no white space at either end. A file that ends with a newline refuses start, so a value never reaches an upstream with a stray character.
- chaperone reads every bound secret at start, through the secret source slot. A secret it cannot read refuses start (G2). The error names the plugin, the parameter and the secret. It never shows the value or the path (G9).
- In production, a dedicated `chaperone` OS user owns the secrets directory. Agents that edit code run as a different user and cannot read it.
- In code, a secret is a `Secret` value. It has no `Display` and no `Serialize`. Its `Debug` prints only the name. One named method exposes the value. The memory is wiped when the value is dropped.
- chaperone replaces each exact secret value in a tool result with `[redacted]`. It does this before it returns the result and before it writes the final audit record.
- In production, the service unit `systemd/creche-chaperone.service` runs chaperone as the `chaperone` user. Its `CapabilityBoundingSet` and its `AmbientCapabilities` are exactly `CAP_SETUID CAP_SETGID`. It sets `NoNewPrivileges=yes`.
- In production, every upstream runs as its own OS user, through `user` in the install file (section 6). An upstream user owns no secret file and cannot read the files of chaperone. A plugin that cannot run as its user does not run.

`chaperone-as` is the only code that uses the two capabilities. It takes these steps:

1. It reads its arguments: a user, then an absolute command, then the arguments of the command. A user is `mcp-`, then `a-z`, then 1 to 30 of `a-z`, `0-9` and `-`.
2. It reads the environment of the plugin from one variable, `CHAPERONE_CHILD_ENV`: one JSON object of strings. It reads nothing else of its own environment.
3. It finds the user in `/etc/passwd`, once. It refuses a user that is not there exactly once, root's ids and the ids of chaperone.
4. It calls `setgroups([])`, then `setresgid`, then `setresuid`.
5. It empties the ambient, effective, permitted and inheritable capability sets, and sets `no_new_privs`. It then reads `/proc/self/status` and checks the ids, the groups, the four sets, `NoNewPrivs` and `Threads: 1`.
6. It calls `execve` with the command, the arguments and the environment of step 2.

A step that fails writes one line to stderr and exits with 125, before the exec. The host reads that exit as an upstream that fails its `initialize`, so chaperone refuses start (section 7.7). The helper never writes stdout, because stdout is the MCP channel of the plugin.

The host starts the helper with the one variable and no other. It holds `CAP_SETUID` while it starts, and an ambient capability does not make the dynamic loader ignore `LD_PRELOAD`. A switch between two users that are not root keeps every capability, so step 5 is necessary. The calls of step 4 change the calling thread only, so the helper runs on one thread.

The production layout gives the default of two flags:

| Path | Contents | Default of |
|---|---|---|
| `/etc/chaperone` | `install.toml` and `policy.toml` | `--config-dir` |
| `/etc/chaperone/plugins` | The plugin tree of section 7.3 | `--plugins-dir` |

`chaperone serve`, `chaperone verify`, `chaperone check` and `chaperone token new` take the same defaults. One layout thus applies to the service and to each check of it. A flag overrules its default. The plugin tree is not in the install tree of the release tool (section 12). The release archive holds only programs, and the release tool replaces that tree at each install.

The service unit gives the other paths of the layout:

| Path | Contents | Who provides it |
|---|---|---|
| `/opt/components/chaperone/bin` | `chaperone`, `chaperone-as` and the program of each effect plugin of this repository | The release tool, from the release archive |
| `/etc/chaperone/secrets` | One file per secret, as above | The operator. The `chaperone` user owns the directory, mode 0700. |
| `/var/lib/chaperone/audit.jsonl` | The audit file | systemd makes the directory, mode 0700. chaperone makes the file. |
| `/run/chaperone/admin.sock` | The admin socket (section 10) | systemd makes the directory, mode 0750. chaperone makes the socket. |
| `/etc/creche/site.env` | `CHAPERONE_LISTEN`, the front door address | The operator |

The unit reads `CHAPERONE_LISTEN` from the site file. It passes the value to `--listen` and to `--allowed-host`. Before the first start, the operator does these steps:

1. Make the OS user and the group `chaperone`.
2. Write `install.toml` and `policy.toml` in `/etc/chaperone`.
3. Copy the plugin tree of this repository into `/etc/chaperone/plugins`. The program of each effect plugin of this repository is next to `chaperone`. Put the program of each other effect plugin on the `PATH` of the unit.
4. Write each bound secret in `/etc/chaperone/secrets`.
5. Set `CHAPERONE_LISTEN` in the site file.
6. Install the unit file once. The release tool refreshes an installed unit. It does not install a unit that is not installed.
7. Add a drop-in for each path that an upstream writes, such as a spool directory or the directory of a Unix socket. `ProtectSystem=strict` makes every other path read-only. A drop-in stays when the release tool refreshes the unit.

The unit gives chaperone no write access to `/etc/chaperone`. `POST /token` therefore fails on the service. The operator runs `chaperone token new` as root, with the service up or down.

## 9. Tokens

`chaperone token new <app>` creates a bearer token for an app instance:

1. It takes 32 bytes from the OS random source, through `getrandom`.
2. It writes the bytes as 64 lower-case hex characters. This text is the token. It prints the token once.
3. It stores only the SHA-256 digest of the token text in `policy.toml`, through `sha2`. The digest goes after the last digest of the app instance. The rest of the file stays as the operator wrote it, comments too.

The `bearer` identity plugin refuses bearer text that is not 64 lower-case hex characters. A digest of any other text in `policy.toml` authenticates nothing.

Each app instance can hold two digests, so a token can rotate with no downtime. chaperone compares digests in constant time, through `subtle`. chaperone uses no cryptography code of its own.

## 10. Admin socket and CLI

The admin socket is a Unix socket. It is never on the front-door port. `chaperone serve` creates it at `--admin-socket` with mode 0660, so the owner and the group open it and nobody else. The operator puts the OS user of an external tool in that group.

| CLI command | Socket endpoint | Job |
|---|---|---|
| `chaperone check <file>` | `POST /check` | Run the strict reader and every cross-file rule |
| `chaperone token new <app>` | `POST /token` | Create a token, as in section 9 |
| `chaperone verify` | None | Check the installed chaperone, for a release tool |

A CLI command and its endpoint call the same function. They cannot drift. The CLI works when the chaperone service is down, so a broken policy can be fixed.

`chaperone check <file>` takes `install.toml` or `policy.toml` in its configuration directory, and `--plugins-dir`. `POST /check` takes `{"file": "<name>", "content": "<text>"}` and answers `200 {"ok": true}` or `422 {"ok": false, "error": "<text>"}`. `POST /token` takes `{"app": "<id>"}` and answers `200 {"token": "<text>"}` once, or `422`. `chaperone token new` keeps the previous policy file as `policy.toml.prev` and lands the new one by an atomic rename. Each function runs on the service's own files. The socket does not take a path.

`chaperone verify` takes `--config-dir`, `--plugins-dir`, `--listen`, `--env-file`, `--listen-key` and `--json`. Without `--config-dir` and `--plugins-dir`, it reads the production layout (section 8). A release tool can thus run it with no directory flag. A configuration directory that does not exist fails the checks of `install.toml` and `policy.toml`. It is not an error of usage. The front door address comes from `--listen`, or from one key of an env file:

- `--env-file <path>` names an env file of the service, such as the `EnvironmentFile=` of its unit. `--listen-key <NAME>` names the key that holds the address. Without it, the key is `CHAPERONE_LISTEN`.
- `--listen` and `--env-file` cannot be used together. `--listen-key` needs `--env-file`.
- The reader of the env file is strict. Each line is `KEY=VALUE`, a comment that starts with `#`, or empty. A key is `A-Z`, then any of `A-Z`, `0-9` and `_`. The value is the text after the first `=`. The reader does no quoting and no expansion.

The env file check fails in these cases:

1. The file is larger than 64 KiB, or it is not UTF-8.
2. A line is not one of the three kinds. `export KEY=VALUE` is such a line, and so is a line with white space only.
3. A key appears on two lines.
4. The key is absent.
5. The value is not a socket address: an IP address and a port, such as `192.0.2.10:8300`.

A check result names a line by its number and a key by its name. It never shows a value of the file, the address included (G9).

`chaperone verify` does these checks in this order:

1. It runs the check of `chaperone check` on `install.toml` in the configuration directory.
2. It runs the same check on `policy.toml`.
3. With `--env-file` only: it reads the front door address from the env file. The check is named `env-file`.
4. It sends `GET /healthz` to the front door address and needs `200`. When the env file gives no address, this check fails.

It writes nothing. It reads no file of the secrets directory. Of the env file, it keeps only the address. It prints one line per check. With `--json` it prints one object: `{"ok": <bool>, "checks": [{"name": "<text>", "ok": <bool>, "detail": "<text>"}]}`. It exits with 0 when every check passes, and with 1 otherwise. An external release tool runs it after each install (section 12).

## 11. Writing the policy file

chaperone has no editor. The operator writes the policy file by hand, or with an external tool that is not part of this repository. `chaperone check` validates the file before it goes into use:

1. Edit a copy of the policy file. Keep the copy in a directory that also holds a copy of `install.toml`, because the check reads the install file next to it.
2. Run `chaperone check` on the copy.
3. When the check passes, keep the previous file and move the copy into place. chaperone reloads it (section 6).

An external tool can check a candidate file with `POST /check` and create a token with `POST /token` (section 10). It shows a token once. It never reads a secret.

## 12. Version 1

Version 1 proves the idea with one client app.

| Part | Choice |
|---|---|
| Client app | The agent runtime in the sandbox. The runtime of version 1 is Flue. |
| Upstream | An existing Vikunja MCP server, unchanged, with the env exception |
| Decision plugins | `ha-call` decision half: an entity allow-list for Home Assistant calls. `attendance` decision half: the families each app instance may reach. |
| Effect plugins | `ha-call` effect half: the Home Assistant call. `ha-approval`: the approval channel, through the operator's existing approval flow. `release`: one request file in the release spool per call. `attendance` effect half: the doors of the session service. |

`ha-call` is one plugin in two halves, both in `included`. The decision half is a fence. Each app instance lists the entities it may act on in its `ha-call` section of the policy file, as `entities = ["light.kitchen"]`. A call to the `ha-call` upstream passes only when every entity in its `entity_id` is on that list. A call with no `entity_id` is denied, because a service call without a target acts on every entity of its domain. An app instance with no section may act on no entity (G2). A call to any other upstream passes untouched. The effect half serves one tool, `call_service`, with `domain`, `service`, `entity_id` and optional `data`. It sends one `POST /api/services/<domain>/<service>` to Home Assistant with the long-lived token `HA_TOKEN` from the secret line, and returns the answer as text. It takes `--url` through `args` in `install.toml`.

`attendance` is one plugin in two halves. The decision half is a fence in `plugins/decision/included`. Each app instance lists the families it may reach in its `attendance` section of the policy file, such as `delegates = ["research"]`. A family name is `a-z`, then 1 to 30 of `a-z`, `0-9` and `-`.

| Key | Fences the tool | At most |
|---|---|---|
| `delegates` | `invoke_agent` | 32 families |
| `enqueue_targets` | `enqueue` | 64 families |

The fence applies these rules to a call to the `attendance` upstream:

1. A call of `invoke_agent` or `enqueue` passes only when its `family` argument is on the list for its tool.
2. A call with no section, or with an empty list for its tool, is denied (G2).
3. A call of `job_status` passes. The effect half limits it to the jobs of the caller.
4. A call of any other tool is denied.

A call to any other upstream passes untouched. Each deny reason starts with `tool_not_granted`. A section with another key, a bad family name or a list over its cap does not load.

The family of an app instance is its app ID. The `check_sections` hook of the fence (section 7.8) keeps delegation to one hop. A policy does not load in these cases:

1. An app instance lists its own app ID in `delegates`.
2. An app instance lists the app ID of another app instance in `delegates`, and that other app instance has a `delegates` list that is not empty.

The refusal names the caller app ID, the target app ID and the rule. The rule starts with `one_hop`. A family on a `delegates` list that is not an app ID of the policy has no check.

The effect half of `attendance` is an upstream in `plugins/effect/included`. It sends each call to a door of the session service, over HTTP on a Unix socket. It takes `--socket` through `args` in `install.toml`. It takes two secrets, `DELEGATE_TOKEN` and `DISPATCH_TOKEN`, each at least 32 bytes. A shorter or missing token refuses start. Each door call sends `Authorization: Bearer <token>` to the base URL `http://sessiond`.

The caller family of a call is the app ID in `_meta` (section 7.7). A call whose app ID is missing, or is not a family name, is refused before any request. The plugin mints a delegation ID per call: a ULID of 26 upper-case Crockford base32 characters.

| Tool | Arguments | Door call | Bound |
|---|---|---|---|
| `invoke_agent` | `family`, `message` of 1 to 65536 characters, optional `attachments` of up to 16 texts of up to 255 characters. The attachments are never sent. | `POST /delegate` with the bearer `DELEGATE_TOKEN` and `{caller_family, target_family, delegation_id, claimed_session_id: null, message}` | 120 seconds |
| `enqueue` | `family`, `message`, optional `idempotency_key` of up to 128 characters | `POST /dispatch` with the bearer `DISPATCH_TOKEN` and `{caller_family, target_family, delegation_id, chain: [caller_family, target_family], claimed_session_id: null, message, idempotency_key}` | 30 seconds |
| `job_status` | optional `session` of `A-Za-z0-9`, then those and `._-`, `since` as an RFC 3339 date-time, `limit` from 1 to 200 | `POST /dispatch/jobs` with the bearer `DISPATCH_TOKEN` and `{caller_family, session, since, limit}` | 30 seconds |

The body leaves out `idempotency_key`, `session`, `since` and `limit` when the call does not set them. The result is one text block that holds one JSON object:

1. `invoke_agent`: `{"untrusted": true, "source": "family:<target>", "content": "<text>"}`. The content is at most 65536 characters. A door answer `timeout` gives the reason `delegate_timeout`. These answers give the reason `upstream_failed`: the status `failed`, an unknown status, an HTTP status other than 200, and a body that is not a JSON object.
2. `enqueue`: `{"session", "family", "status", "created"}`. `created` is true unless the door answers exactly `false`. An answer with no `session_id` is `upstream_failed`.
3. `job_status`: `{"jobs": [...]}`, at most 200 rows. A row that is not a JSON object is dropped.

An error result holds `{"ok": false, "reason": "<reason>", "detail": "<text>"}`. The dispatch door answers an error with `{"error": {"code", "message"}}`. The plugin maps its code:

| Code | Reason |
|---|---|
| `dispatch_not_declared`, `forbidden`, `family_unknown`, `family_invalid` | `tool_not_granted` |
| `bad_request`, `idempotency_mismatch`, `payload_too_large` | `arg_validation` |
| `queue_full` | `rate_limited` |
| Any other code, a socket that does not answer | `upstream_failed` |

The detail is the door's `message`, or its code. A detail is at most 65536 characters. The plugin blanks each copy of either token in a detail and in the content (G9). An argument that breaks its rule gives `arg_validation`, and no request goes out.

An app instance that delegates sets `timeout_s = 120` on its `attendance` grant (section 6). With a lower bound, chaperone ends a longer delegate call with `upstream_timeout` (section 5.5). It can also set `max_inflight` on that grant to limit its delegate calls at one time. The limit counts each call to the `attendance` upstream, `enqueue` and `job_status` too.

`ha-approval` sits in `plugins/effect/included`. The operator's flow is a Node-RED instance in front of Home Assistant with two legs. The plugin speaks the flow's language and changes nothing in the flow:

1. **Out.** For each gate, the plugin sends `POST` to the flow's hook with the bearer `APPROVAL_TOKEN` and the body `{"job_id", "gate_id", "agent", "summary", "kind": "approval"}`. The flow pushes a card with Approve and Deny to the operator's phone. The gate ID of chaperone is 16 bytes. `job_id` is those bytes as 26 lower-case base32 characters of the ULID alphabet, and `gate_id` is the first 8 bytes as 16 hex characters, because the flow accepts only those shapes. `agent` is the app ID. `summary` is the exposed tool name and the canonical arguments, cut to 400 characters.
2. **Back.** The plugin serves `POST /resume` on the address of its `--listen` argument. The flow sends the tap there with the bearer `RESUME_TOKEN` and the body `{"job", "gate", "decision"}`, where `decision` is `approve` or `deny`. The plugin decodes `job` to the gate, answers chaperone's `approve` call, and returns `200`. A repeat of the same decision returns `200`. A contradicting decision returns `409` and the first answer stands. An unknown gate returns `404`. A wrong bearer returns `401`.

The plugin takes `--hook-url` and `--listen` through `args` in `install.toml`. It refuses an unspecified listen address. It holds the two tokens in memory only, from the secret line of section 7.5. A hook that does not answer `2xx`, or a tap that does not come in the life of the gate, is a denial.

`release` is an upstream in `plugins/effect/included`. It serves one tool, `request`, so the model sees `release__request` when the policy grants it. Each call writes one request file into the `requests/` directory of the release spool. An external release executor reads the file, resolves the components and asks the operator. The plugin approves nothing. It takes no secret. It takes `--requests-dir` and `--requested-by` through `args` in `install.toml`. The policy grants `release__request` to one app instance only, and `--requested-by` names that instance. The plugin does not read the app ID of a call (section 7.7), so a second instance with the grant would file requests under the same name.

The arguments are `components`, `kind` and `rollback_of`:

| Argument | Value |
|---|---|
| `components` | 1 to 8 component names, each with a version `x.y.z` or `latest`. A name is `a-z`, then 1 to 30 of `a-z`, `0-9` and `-`. |
| `kind` | `release`, the default, or `rollback` |
| `rollback_of` | Only for `rollback`: the request ID to reverse |

The file is `<ID>.json`, mode 0600. The ID is a ULID: 26 characters of upper-case Crockford base32, from the time in milliseconds and 80 random bits. The file holds one JSON object with these fields, in this order: `id`, `kind`, `components`, `rollback_of`, `requested_by`, `requester_session` and `ts`. `requested_by` is the `--requested-by` argument. `requester_session` is `null`. `ts` is the time in seconds since the Unix epoch, as a number, because the executor reads that shape.

The plugin writes the body to `.<ID>.json.tmp`, then gives it its name with a hard link and removes the temporary name. A link never replaces a file that exists. The plugin refuses a call in these cases, and writes no file:

1. An argument breaks its rule. The error names the rule and shows no value (G9).
2. The directory is missing, or is not a directory.
3. The directory holds 8 or more `.json` files.
4. A file of that name exists.
5. The body is larger than 4096 bytes.

Version 1 is done when the agent runtime in the sandbox makes three calls with this result:

1. An allowed call runs.
2. A call to a tool with no grant is denied.
3. A gated call waits, the operator approves it on the phone, and it runs.

The audit file shows all three calls.

The project publishes tagged versions with built binaries. An external release tool installs a version on the host and runs `chaperone verify` after the install (step 10.2). The release tool is not part of this repository.

The release tool reads `component.toml` at the root of this repository, at the commit of the tag. The file holds the text that the release tool expects, field for field. `crates/chaperone/tests/release.rs` holds each field, so a change fails `cargo test`. For each install, the release tool does these steps:

1. It checks the signature of the archive, then unpacks it to `/opt/components/chaperone`. It keeps the previous tree as `/opt/components/chaperone.prev`.
2. It copies `systemd/creche-chaperone.service` over the installed unit of that name, and keeps the previous unit. It restarts the unit.
3. It runs `chaperone verify --json --env-file /etc/creche/site.env --listen-key CHAPERONE_LISTEN` as root, with a bound of 60 seconds. It reads the exit code and stdout only.
4. When the check fails, it puts back the previous tree and the previous unit, and restarts the unit.

The release tool refuses a version that is not higher than the installed version. The first version that it installs is thus higher than each version of an earlier program under the same unit.

Releases come from `.github/workflows/release.yml`. To release, a pull request changes `version` in `crates/chaperone/Cargo.toml`. The workflow runs on each push to `main`. A version with a tag, or no version, releases nothing. Else the workflow does these steps:

1. It builds `chaperone`, `chaperone-as` and the program of each `plugin.toml` for `x86_64-unknown-linux-musl` with `cargo install --locked --no-track`. A `--bin` names each program, so no other binary of a package enters the archive. The `build` list of `component.toml` holds the same commands in the same order.
2. It packs the programs into `chaperone-x86_64-unknown-linux-musl.tar.gz`. The archive holds these members, each with mode 0755, in this order, and nothing else: `chaperone/bin/chaperone`, `chaperone/bin/chaperone-as`, `chaperone/bin/chaperone-attendance`, `chaperone/bin/chaperone-deny-all`, `chaperone/bin/chaperone-ha-approval`, `chaperone/bin/chaperone-ha-call` and `chaperone/bin/chaperone-release`. The release tool takes only members named `chaperone/bin/<program>`, so the plugin tree is not in the archive.
3. It signs the archive with a keyless Sigstore signature. The bundle is `chaperone-x86_64-unknown-linux-musl.tar.gz.sigstore.json`.
4. It makes the tag `chaperone-v<version>` at the merge commit, and a Release with the two files. The author of the Release is `github-actions[bot]`.

The certificate of the signature names the identity `https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/heads/main`, the issuer `https://token.actions.githubusercontent.com` and the merge commit. The workflow never moves a tag.

## 13. Build order

One pull request per step:

1. `AGENTS.md` files and this document.
2. `core`, in two pull requests:
   1. The workspace, CI, the strict reader, the name types, `Secret`, argument values and time.
   2. The config types, slot resolution, the decision, the hook traits and the property tests.
3. In five pull requests:
   1. The `Gateway` contract, exposed names, the `bearer` identity plugin and the `audit-jsonl` audit sink. The audit sink comes this early, so the first program that runs already writes the audit (G6).
   2. The `chaperone` program and the `mcp-http` front door.
   3. The registry of compiled plugins.
   4. The clock slot and the `system-clock` adapter.
   5. One module for every hook trait.
4. The secret source. It comes before the effect host, because the Vikunja upstream needs a secret.
5. The effect host, the upstream result check and the Vikunja upstream.
6. Gates, the approval hook and `ha-approval`.
7. `ha-call`, both halves.
8. In two pull requests:
   1. The admin socket and the CLI: `schema`, `check` and `token new`.
   2. The editor. A pull request before step 9.5 removes the editor and `chaperone schema`, because the operator writes the policy file by hand or with an external tool (section 11).
9. Configuration in TOML, in five pull requests:
   1. The `toml` crate.
   2. The strict TOML reader.
   3. The install file.
   4. The plugin manifest.
   5. The policy file.
10. The rest of version 1, one pull request each:
    1. Policy reload when the policy file changes (section 6).
    2. `GET /healthz` on the front door and `chaperone verify`.
    3. The `attendance` plugin, both halves, with three tools: `invoke_agent`, `enqueue` and `job_status` (section 12). Step 10.8 adds the in-flight limit. Step 10.9 adds the one-hop check.
    4. The `release` effect plugin. Each call writes one request file (section 12).
    5. A front door bound to a LAN address, under the guard `host-firewall` (section 7.6).
    6. The effect host launches each upstream as its own OS user, through `chaperone-as` (section 8).
    7. The bound of an upstream call, per upstream grant (section 5.5).
    8. The in-flight limit of an upstream grant (section 5.2).
    9. The `check_sections` fence hook, and the one-hop check of `attendance` through it (sections 7.8 and 12).
    10. `chaperone verify` reads the front door address from an env file (section 10).
11. The first install by the external release tool, one pull request each:
    1. The defaults of the production layout (section 8).
    2. The component manifest and the service unit (sections 8 and 12).
    3. The version `0.2.0` (section 12).

## 14. Open items

| Item | Settle in |
|---|---|
| The agent runtime subscribes to the results of its gates, and chaperone publishes each kept result when the run ends. The transport, and how a subscription is bound to one app instance, are open. | After version 1 |
| The 50-character budget of an exposed name (section 7.6) exists for LibreChat, a client that version 1 does not use. The budget can widen. | After version 1 |
| TLS on the front door. It can come as a third value of `guard` (section 7.6). | After version 1 |

# AGENTS.md

Rules for every contributor and every agent that edits this repository. A directory's own `AGENTS.md` adds rules for that directory. Read both before you edit.

## Read first

1. `docs/design.md`. It states what chaperone guarantees. The rules below exist to keep those guarantees. Each guarantee has an ID from G1 to G10.
2. `docs/writing-standard.md`. Every Markdown document follows it.
3. The `AGENTS.md` of the directory you edit.
4. For a Rust change: the [Google Rust Style Guide](https://google.github.io/styleguide/rustguide.html). "Rust style guide" below says how it applies.

## The structure in one table

| Path | Kind | Can do I/O | Rules in |
|---|---|---|---|
| `crates/core` | Library: policy types, strict reader, decision, hook traits | No | `crates/core/AGENTS.md` |
| `crates/chaperone` | The program: hosts plugins, audit, admin socket, CLI | Yes | `crates/chaperone/AGENTS.md` |
| `crates/editor` | A separate program: HTML forms for the policy file | Yes | `crates/editor/AGENTS.md` |
| `plugins/default` | One plugin per required slot | Per plugin kind | `plugins/default/AGENTS.md` |
| `plugins/decision` | Pure plugins, compiled in | No | `plugins/decision/AGENTS.md` |
| `plugins/adapter` | I/O plugins, compiled in | Yes | `plugins/adapter/AGENTS.md` |
| `plugins/effect` | Separate processes, MCP over stdio | Yes | `plugins/effect/AGENTS.md` |
| `plugins/` as a whole | Kinds, slots, `plugin.json`, overrule rules | | `plugins/AGENTS.md` |

## Never do these

Each line cites the guarantee it protects. A pull request that does one of these is not merged.

1. Do not add I/O, a clock read, randomness or global state to `crates/core` or to a decision plugin. (G3)
2. Do not call a model, an LLM API or any non-deterministic service from a decision path. (G1)
3. Do not add a code path where an error, a timeout or a missing answer leads to an allow. Every such path ends in a deny or a refusal to start. (G2)
4. Do not let a plugin result widen reach beyond the policy file. A fence returns deny, gate or pass. An identity plugin can only narrow. No hook returns "allow anyway". (G4, G7)
5. Do not put a hook tool of an effect plugin into a manifest. (G8)
6. Do not write a secret value to a log, an audit record, an error, a result, argv, the environment or the policy file. Do not add `Display`, `Serialize` or a value-printing `Debug` to `Secret`. (G9)
7. Do not run a call before its decision record is written. Do not return a result before its final record is written. Do not put app-chosen text in an audit record. (G6, G9)
8. Do not load, enable or order plugins by directory listing. Only `install.json` enables a plugin or fills a slot. (G10)
9. Do not write cryptography code. Use the crates named in `docs/design.md` section 9. Ask before you add another one.
10. Do not bind `0.0.0.0`. Bind a LAN address, `127.0.0.1` or a Unix socket.
11. Do not merge a pull request. Do not push to `main`. Do not publish a release or a tag. A maintainer does each of these.

## Patterns to follow

### Types carry the rules

- Parse at the edge. The strict reader turns bytes into typed values. No `serde_json::Value` passes beyond the reader.
- Give each ID its own newtype: `AppId`, `ToolName`, `PluginName`, `SecretName`, `GateId`. Do not pass a bare `String` where a newtype exists.
- Put `#[serde(deny_unknown_fields)]` on every type that a config file or a wire message fills.
- Use an enum, not a boolean, for a choice. Use an enum, not an `Option`, when "nothing" has more than one meaning.
- Match every variant of our own enums by name. Do not use a `_ =>` arm on them, so that a new variant breaks the build where it must be handled.
- Make an invalid state impossible to build. A constructor that can fail returns `Result`. Fields stay private.

### Rust style guide

The core style guide for Rust in this repository is the [Google Rust Style Guide](https://google.github.io/styleguide/rustguide.html). Read it before you write Rust.

When two rules conflict, this order decides:

1. This file and the `AGENTS.md` of the directory you edit.
2. The Google Rust Style Guide.
3. The Rust API Guidelines and the Rust Style Guide, which the Google guide defers to.

How the guide applies here:

- `crates/core` is library code, because the other crates and every plugin use it. The guide's library rules are binding there. The other crates are application code.
- The rules marked [Chrome], [Fuchsia] or [Android] do not apply. `async` is allowed, and tests use `#[test]` and `proptest`.

This repository departs from the guide in these places. Each departure is stricter, or the guide's rule is not available on stable Rust.

| The guide | This repository | Why |
|---|---|---|
| Use `panic!` for a bug. Prefer `expect` over `unwrap`. | No `panic!`, `unwrap` or `expect` outside tests. The guide allows a codebase that avoids panics. | A panic is an unhandled error. G2 needs every error to end in a deny. |
| Use a wildcard arm for variants you do not care about. | No `_ =>` arm on our own enums. | A new variant must break the build where it needs handling. |
| Use `#[non_exhaustive]` on public enums. | Do not use it. | One workspace holds every user. A change fixes every user in the same pull request. It also conflicts with the rule above. |
| Set `imports_granularity = Module` in rustfmt. | The reviewer checks it. | The option is not stable. The toolchain is stable. |
| Consider the `missing_docs` lint. | Do not turn it on. Document each public type, trait and function whose name does not say enough. | The lint asks for comments that only repeat a name. The guide refuses those comments too. |
| Keep the files of one crate in one flat directory. | Use the Cargo layout. `tests/` is allowed. | The guide marks this rule [Chrome]. |

### Errors

- Library code returns a typed error enum. Do not use `unwrap`, `expect` or `panic!` outside tests. Clippy enforces this.
- An error message names the item and the rule it broke. It never contains a secret value or a token.
- A fault at a trust boundary becomes a deny with a reason. It does not become a log line and a default value.

### Code style

- `unsafe` is forbidden in the whole workspace.
- Extract a repeated or meaningful value into a named constant. Keep a one-off value inline.
- Return early. Avoid deep nesting.
- Keep a function name under 30 characters.
- Keep a field or function private unless the design needs it public. Ask before you widen visibility.
- A layer talks only to the layer directly below it. Do not call through a layer.
- Edit only the lines the change needs. Do not add a comment to code you did not change.

## Every change

- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` pass. CI runs all three and is the merge gate.
- Fix a bug in this order:
  1. Write the test.
  2. Watch it fail.
  3. Write the fix.
  4. Watch it pass.
- A change to a guarantee, a slot, a hook or a config shape changes `docs/design.md` in the same pull request.
- One pull request does one step. `docs/design.md` section 13 lists the steps.

## Commit messages

1. Separate the subject from the body with one blank line.
2. Limit the subject to 50 characters. 72 is the hard limit.
3. Capitalize the subject. Do not end it with a period.
4. Write the subject in the imperative: "Add", not "Added" or "Adds".
5. Wrap the body at 72 characters.
6. Use the body for what changed and why. The code says how.
7. End the message with `Co-Authored-By` and nothing else.

## Sanitization

This repository is public. Name no host, no user, no domain, no address and no person of any deployment. Write "the operator" and "the host". In an example that needs an address, use `192.0.2.10` and the other TEST-NET-1 addresses. `docs/writing-standard.md` section 6 has the full rule.

## Time

A time in a file or in a wire message is a `date-time` of RFC 3339, section 5.6. A writer writes each time in UTC, with `Z` as the offset. The decision function receives the time as an argument (G3).

## When the design is silent

Take the most conservative reading: the one that denies more. Mark the spot with a `DESIGN-QUESTION:` comment. The comment names the section of `docs/design.md`, the reading you took and what a change would cost. Say the same in the pull request. Do not deviate quietly.

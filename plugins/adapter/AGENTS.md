# plugins/adapter/AGENTS.md

Rules for adapter plugins. Read `plugins/AGENTS.md` first.

An adapter plugin is a Rust crate that implements an adapter trait from `crates/core`. chaperone compiles it in. An adapter does I/O, but it never changes a decision. The three adapter slots are the front door, the secret source and the audit sink.

## Rules

1. Implement a trait from `crates/core`. Do not depend on `crates/chaperone`.
2. Return every failure as a typed error. chaperone turns it into a deny or a refusal to start (G2).
3. Treat every inbound byte as untrusted. Check its shape and size before use.

## Per slot

- **Front door.** Accept the app's connection. Pass the credential, the tool and the arguments to the core. Return the core's answer. Do not decide anything yourself. Do not cache a decision.
- **Secret source.** Return a `Secret` for a name. Check the owner and the mode of a secret file before you read it. Never return a value as a `String`.
- **Audit sink.** Write one record. Return success only after the record is durable. A write that fails returns an error, and the call fails (G6).

## Never do these

1. Do not log a secret value or a token (G9).
2. Do not bind `0.0.0.0`.
3. Do not start a background task that outlives the call, except where the slot needs it, such as a front-door listener.

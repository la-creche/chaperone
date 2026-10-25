# plugins/decision/AGENTS.md

Rules for decision plugins. Read `plugins/AGENTS.md` first.

A decision plugin is a Rust crate that implements `Identity` or `Fence` from `crates/core/src/hook.rs`. chaperone compiles it in. It runs inside the decision path, so it must be pure (G3).

## Rules

1. Implement a trait from `crates/core/src/hook.rs`. Depend on `crates/core` only. Do not depend on `crates/chaperone`.
2. Take every input as an argument. That includes the time.
3. Return a value. Do not write to anything.
4. A fence returns pass, `Deny(reason)` or `Gate`. An identity plugin returns an app instance or nothing, and can only narrow that instance's reach. No decision plugin has an "allow" result (G7).
5. Always end. Do not loop on input size without a bound.
6. Read only your own section of the policy. Your `plugin.toml` declares its schema.

## Never do these

1. Do not read a file, a socket, the network, the environment or a clock. The purity lint (`clippy::disallowed_methods`) bans `std::fs`, `std::net`, `std::env`, `std::time` and randomness in this directory.
2. Do not use interior mutability or a global to keep state between calls.
3. Do not call into an effect plugin. If the decision needs a fact from the outside world, a maintainer must design a new hook first.

## Patterns

- A fence plugin often has an effect half. `ha-call` is the example: the decision half checks the entity allow-list, and the effect half calls Home Assistant. Each half names the other in `pairs_with`.
- Test with `proptest`. Prove two properties: the same input gives the same result, and no input makes the plugin panic.

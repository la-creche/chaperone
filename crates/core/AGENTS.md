# crates/core/AGENTS.md

Rules for `crates/core`. Read the root `AGENTS.md` first.

`core` holds the policy types, the strict JSON reader, the decision function and the hook traits. It does no I/O. The crate boundary keeps the decision pure: `cargo` refuses a dependency on an I/O crate here, and review refuses an I/O call.

## What lives here

- The types of `install.json`, `policy.json` and `plugin.json`, with `deny_unknown_fields`.
- The strict JSON reader. It takes bytes. It refuses duplicate keys, a byte order mark, invalid UTF-8, unknown fields and input over the size cap.
- The JSON Schema generation from those types.
- The cross-file checks behind `chaperone check`.
- The decision function in `docs/design.md` section 5.
- The hook traits, all in `src/hook.rs`: what a decision or adapter plugin implements, and the `Gateway` trait a front door calls. The result types of effect hooks.
- The `Secret` type.

## Rules

1. Take bytes, not paths. The caller reads the file.
2. Take the time as an argument (G3).
3. The decision function returns a value. It has no side effect.
4. Keep the row order of `docs/design.md` section 5.2. A change to the order changes that section in the same pull request.
5. The default answer of every match on input is a deny (G2).

## Never do these

1. Do not depend on `tokio`, `std::fs`, `std::net`, `std::env` or `std::time::SystemTime`. The purity lint bans them in this crate. `tests/purity.rs` scans every source file for these names and for `HashMap`, `HashSet`, `Mutex`, `RefCell` and the other hidden-state types. A new source file needs a line in that test.
2. Do not add a global, a `static mut` or a lazy cache.
3. Do not add `Display`, `Serialize` or a value-printing `Debug` to `Secret` (G9).

## Tests

Use `proptest` for these properties:

1. The same input gives the same decision (G1).
2. Adding any fence result never turns a deny or a gate into an allow (G7).
3. A malformed policy always gives a deny (G2).
4. The strict reader refuses every input that breaks one of its rules.

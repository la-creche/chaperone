# Tooling evaluation

This report rates Rust tools for this repository. Each tool ran against the real code of `crates/core`. Each rating cites the guarantee (G1 to G10, `docs/design.md` section 3) that the tool protects. Section 12 lists the changes for one follow-up pull request.

## 1. Method

| Item | Value |
|---|---|
| Base commit | `origin/main` at `24816d6`. The brief named `origin/core/decision`. Pull request #5 merged that branch into `main`, and the remote branch no longer exists. |
| Branch | `tooling-eval`. Each trial is a separate commit. Section 13 lists them. |
| Cross-check | `origin/step3/program` at `fc79a4b`, the open step 3 work. cargo-deny and clippy also ran on it, in a separate worktree. No file of that branch changed. |
| Machine | macOS on aarch64, 10 cores, 32 GiB. A CI runner of type `ubuntu-latest` has 4 cores. CI times can be 2 to 3 times the local times. |
| Code under test | `crates/core`: 3502 lines, 80 tests (53 unit tests, 27 integration tests, of which several are proptest properties). |

## 2. Summary

| Tool | Result on our code | Cost | Recommendation | Guarantee |
|---|---|---|---|---|
| Toolchain 1.99.1 | 0 format changes, 0 new lints, 80 of 80 tests pass | 1 line | Adopt now | All |
| cargo-deny | `main` passes. Step 3 fails: `rand` and `chacha20` ship through `rmcp`. `subtle` needs `BSD-3-Clause`. | 1 file, about 15 s of CI | Adopt now | Rule 9, G2 |
| Extra clippy lints | 4 hits in core library code, 0 print or `dbg!` hits, 1 pedantic hit. Step 3 adds 7 pedantic hits. Core uses a `HashSet`, which reads OS randomness. | 4 small code fixes | Adopt now | G2, G3, G9 |
| zizmor | 3 findings, none high | 3 YAML edits, under 10 s of CI | Adopt now | G5 |
| actionlint | 0 findings | under 5 s | Later | None |
| cargo-mutants | 54 of 215 viable mutants survive. 2 survivors break G7 fences. | 162 s locally | Adopt the tests now. Run the tool later, on demand. | G7, G2 |
| cargo-fuzz | 82 million runs, 0 crashes | Nightly toolchain, 4 targets | Later, as a scheduled job | G2 |
| bolero | Runs on stable. Does not reuse proptest strategies. | 1 harness | Skip | G2 |
| Kani | No proof finished: out of memory, or no verdict within the cap, in 7 runs | Nightly toolchain, 12 to 90 lines per proof, up to 30 minutes per run | Skip | G7, G2 |
| cargo-llvm-cov | 92.7 % of lines, 89.3 % of functions | 13 s | Later, as a report | G2 |
| cargo-nextest | No speed gain at 80 tests | none | Later | None |
| cargo-shear | 1 unused workspace dependency: `schemars` | under 1 s | Later | None |
| cargo-auditable | Builds core with no change | 1 CI step | Later, at the first release | G5 |
| Flux | Not tried | Nightly, research tool | Skip | G2 |

## 3. Toolchain bump to 1.99.1

**Trial.** Commit `d8177ad` sets `channel = "1.99.1"` in `rust-toolchain.toml` and `rust-version = "1.99"` in `Cargo.toml`.

**Result.**

1. `cargo fmt --all --check` reports no change.
2. `cargo clippy --workspace --all-targets --locked -- -D warnings` reports no warning. This is true with `rust-version = "1.92"` and with `rust-version = "1.99"`. The newer MSRV unlocks no lint on our code.
3. `cargo test --workspace --locked` passes 80 of 80 tests.
4. `RUSTDOCFLAGS="-D warnings" cargo doc -p chaperone-core --no-deps` fails with one error: the public documentation of `strict` links to the private item `Check` (`crates/core/src/strict.rs:13`). The error also occurs on 1.92.0. CI does not build the documentation, so CI does not see it.

**Cost.** One line. A warm local check runs in about 20 s. The runner downloads the toolchain in both cases.

**Side effect.** A fuzz or Kani build reads `rust-version`. With `rust-version = "1.99"`, a nightly older than 1.99 refuses the crate. The trial used `nightly-2026-10-20`.

**Recommendation.** Adopt now. Set `rust-version` to the pinned version, because `publish = false` and no outside user needs an older MSRV.

## 4. cargo-deny

**Trial.** Commit `a7d97d1` adds `deny.toml`. It checks four things:

1. Advisories. Every RustSec advisory fails the check, including "unmaintained" and "yanked".
2. Licenses. Only licenses that are compatible with `MIT OR Apache-2.0` pass.
3. Sources. Only crates.io. No git source.
4. Bans. Duplicate versions fail. A ban list enforces `AGENTS.md` rule 9. The list names 28 crypto crates and `rand`: other hashes, MACs, KDFs, ciphers, signature crates, and the stacks `ring`, `openssl`, `native-tls`, `aws-lc-rs` and `boring`. `rand` may enter only through an approved wrapper.

The RustCrypto support crates of `sha2` stay allowed: `digest`, `block-buffer`, `crypto-common`, `cpufeatures`, `const-oid`, `hybrid-array`.

**Result on `main`.**

1. The first run failed. `proptest` 1.12 uses `chacha20` and `rand` as its test RNG. Both are dev dependencies only.
2. With `proptest` as a wrapper, all four checks pass: 0 advisories, 0 duplicates, crates.io only.
3. Every license is `Apache-2.0`, `MIT`, `Unicode-3.0`, or `Unlicense OR MIT`.
4. A probe added `sha1` to core. The ban list refused it. The probe was then removed.

**Result on step 3 (`fc79a4b`).** The same file fails. With dev dependencies excluded, these findings remain:

| Finding | Cause | Proposed answer |
|---|---|---|
| `rand` 0.10 ships in the binary | `rmcp` 3.7 depends on it | Add `rmcp` as a wrapper of `rand`. Our crates still cannot depend on `rand`. A maintainer decides. See section 14. |
| `chacha20` ships in the binary | `rand` depends on it | Add `rand` as a wrapper of `chacha20`. |
| `subtle` is refused | `subtle` is `BSD-3-Clause`. Design section 9 names `subtle`. | Allow `BSD-3-Clause`. |
| `matchit` is refused | `MIT AND BSD-3-Clause`, through `axum` | The same answer. |
| `syn` 2 and `syn` 3 | `tracing-attributes` uses `syn` 2. It is a proc macro and does not ship. | Skip `syn@2` with a reason. |

With dev dependencies included, the dev dependency `rmcp` with the `reqwest` feature adds `rustls` and `aws-lc-rs`. That brings 3 more licenses (`ISC`, `CDLA-Permissive-2.0` and `MIT-0`) and 2 more banned crates. These crates do not ship. The proposal sets `exclude-dev = true`, so that the ban list and the license list judge only what ships.

**Cost.** Setup took 15 minutes. A run takes 1.4 s plus the fetch of the advisory database. A source install takes 77 s. A prebuilt binary can install in under 10 s.

**Final file.** Commit `c1e0948` replaces the trial file with the proposal of section 12, change 2. It passes on `main` and on step 3. On `main`, 3 warnings remain for entries that only step 3 uses.

**Recommendation.** Adopt now. The ban list turns rule 9 from a review rule into a build gate. The advisory check covers G2 at the supply-chain level. The exact file is in section 12, change 2.

## 5. Extra clippy lints

**Trial.** One clippy run with these lints set to warn: `print_stdout`, `print_stderr`, `dbg_macro`, `allow_attributes_without_reason`, `arithmetic_side_effects`, `indexing_slicing`, `string_slice` and the `pedantic` group.

**Hits on `main`.**

| Lint | Library code of core | Tests of core | Class |
|---|---|---|---|
| `print_stdout`, `print_stderr`, `dbg_macro` | 0 | 0 | No cost to deny |
| `allow_attributes_without_reason` | 0 | 0 | No cost to deny |
| `arithmetic_side_effects` | 2: `hook.rs:74` `end -= 1`, `strict.rs:163` `self.depth + 1` | 1: `tests/decide.rs:703` | Library hits are safe today, but only a reviewer proves it |
| `indexing_slicing` | 1: `decide.rs:35` `&digest[..16]` | 0 | Safe by the digest length |
| `string_slice` | 1: `hook.rs:76` `text[..end]` | 1: `tests/decide.rs:705` | Safe by the loop above it |
| `pedantic` | 0 | 1: `manual_let_else` at `tests/decide.rs:163` | Style |

**Fixes.** Commit `0d88733` removes each library hit with no `allow`:

1. `hook.rs`: `text.floor_char_boundary(Self::MAX)` replaces the loop. `text.get(..end)` replaces the slice. `floor_char_boundary` is stable since Rust 1.91.
2. `strict.rs`: `self.depth.saturating_add(1)`. The depth check at `DEPTH_MAX` already bounds the value.
3. `decide.rs`: `digest.split_ref::<U16>()` from `hybrid-array` splits the 32-byte digest at a size the type system checks. No index remains.

**Justified exceptions.** The integration test file `tests/decide.rs` already allows `unwrap_used` and `panic` with a reason. The trial adds `arithmetic_side_effects` and `string_slice` to that list. A panic in a test is a failed test, not a G2 fault.

**Hits on step 3.** The new code adds these hits:

| Lint | Place | Proposed answer |
|---|---|---|
| `zero_sized_map_values` (3) | `crates/core/src/gateway.rs:61`, `:63`, `:96`. Each is a map of `IgnoredAny`. | `#[expect(clippy::zero_sized_map_values, reason = "the map only checks the shape")]` |
| `doc_markdown` (1) | `crates/core/src/exposed.rs:2` | Put `LibreChat` in backticks, or add it to `doc-valid-idents` |
| `format_collect` (1) | `plugins/default/bearer/src/lib.rs:100` | Use `hex::encode` |
| `redundant_closure_for_method_calls` (1) | `plugins/default/audit-jsonl/src/lib.rs:79` | Use `.map(AppId::as_str)` |
| `unused_async_trait_impl` (1) | `crates/chaperone/src/gateway.rs:98` | `#[expect(..., reason = "the rmcp trait is async")]` |

Outside core, step 3 has 6 `indexing_slicing` hits, all in tests, and 1 `arithmetic_side_effects` hit. The proposal does not apply these two lints outside core.

**Recommendation.** Adopt now:

1. Deny `print_stdout`, `print_stderr`, `dbg_macro` and `allow_attributes_without_reason` in the whole workspace. A stray print can leak a secret value (G9). A reason on every `allow` keeps each exception reviewable.
2. Deny `arithmetic_side_effects`, `indexing_slicing` and `string_slice` in core only. Each one marks a place where a panic can hide (G2).
3. Warn on `pedantic`. CI runs clippy with `-D warnings`, so a pedantic hit fails CI. Each toolchain bump can add pedantic lints. The pull request of the bump then fixes them.

## 6. zizmor and actionlint

**Trial.** zizmor 1.31.1 ran offline and online, with the `pedantic` persona. actionlint 1.7.12 ran with its default rules.

**Result.** zizmor reports 3 findings on `.github/workflows/ci.yml`. The online audits find no impostor commit and no known-vulnerable action. The SHA pins pass.

| Finding | Severity | Fix |
|---|---|---|
| `artipacked`: `actions/checkout` keeps the token in `.git/config` | Medium offline, low online | `persist-credentials: false` |
| `concurrency-limits`: no concurrency group | Low | A group per workflow and ref. Cancel only pull request runs, so each run on `main` completes. |
| `anonymous-definition`: the job has no name | Informational | `name: Format, lint and test` |

After commit `fa8d8b8`, zizmor reports no finding. actionlint reports 0 errors before and after.

**Cost.** Each tool runs in under 1 s on this file. zizmor in CI needs an install step, for example `pipx run zizmor==1.31.1`. pipx is on the `ubuntu-latest` image.

**Recommendation.** Adopt the 3 fixes and a zizmor step now. The token in `.git/config` is a credential within reach of every later step (G5). Run actionlint later, when the workflows grow. zizmor already covers the security checks.

## 7. cargo-mutants

**Trial.** `cargo mutants -p chaperone-core -j 4`, cargo-mutants 27.1.0.

**Result.** 269 mutants in 162 s wall time. Other builds shared the machine during the run.

| Outcome | Count |
|---|---|
| Caught | 161 |
| Missed | 54 |
| Unviable (does not build) | 54 |
| Timeout | 0 |

The mutation score is 161 of 215 viable mutants: 75 %.

**Survivors that break a guarantee.** Each row names a test that kills the mutant.

| Mutant | Effect | Test that kills it | Guarantee |
|---|---|---|---|
| `decide.rs:193` `==` to `!=` in `matches`, the `Bool` arm | An `allow` fence on a boolean allows every other value | Fence an argument with `{"allow": [false]}`. Check that `true` is denied and `false` is allowed. | G7 |
| `decide.rs:195` `==` to `!=` in `matches`, the `String` arm | An `allow` fence on a string allows every value except the listed one | Fence an argument with `{"allow": ["safe"]}` and `{"deny": ["prod"]}`. Check both directions. | G7 |
| `value.rs:87` `>` to `<`, `>=`, `==` in the array writer | `[1,2]` and `[12]` get the same canonical text, so they share a gate ID. An approval of one call then approves the other. | Check that `GateId::from_call` differs for the arguments `{"a":[1,2]}` and `{"a":[12]}`. | G7 |
| `value.rs:122` `write_float` to `()` | Every float writes as nothing. Calls that differ only in a float share a gate ID. | Check that the gate IDs of `{"a":1.5}` and `{"a":2.5}` differ. | G7 |
| `hook.rs:78` `FenceReason::as_str` to `""` | A deny loses its reason. The current test checks only "at most 200 bytes" and "only `é`", and an empty text passes both. | Check that 150 `é` characters give exactly 100 characters. | G2 |
| `policy.rs:324` `>` to `>=` in the digest count | A policy with two digests does not load. Token rotation (design section 9) breaks. | Load an app instance with two digests. | G2 |
| `strict.rs:108` `>` to `>=` in the size cap | A text of exactly the cap is refused | Read a text of exactly `cap` bytes. | G2 |
| `install.rs:14`, `plugin.rs:13`, `policy.rs:17` `*` to `+` in the caps | The cap of 1 MiB becomes 2 KiB | Read a valid file of 4 KiB through each reader. | G2 |
| `plugin.rs:184` `\|\|` to `&&`, `>` to `>=`, `>` to `==` in the version check | An empty version or an over-long version passes | Check an empty version, a version of `VERSION_MAX` characters and one of `VERSION_MAX + 1`. | G2 |
| `install.rs:330` `&&` to `\|\|` in `check_pairs` | A half pair passes when only the kind matches | Pair a decision half with an effect half whose `pairs_with` names the wrong kind. | G10 |
| `ids.rs:195`, `:203`, `:206`, `:208`, `:209`, `:223` in `is_param` and the `is_valid` of `ArgName` and `SecretParam` | Any text passes as an argument name or a secret parameter | Check a table of bad names for each kind: `""`, `"1a"`, `"a-b"`, 65 characters. | G9 |

**Survivors with no caller yet.** 32 mutants change an accessor, a `Display` or a `Debug` that no code calls yet: `note()` (5 accessors), `GateId::to_hex`, the `Debug` and `Display` of `GateId`, the `Debug` of `TokenDigest`, `Manifest::version`, `App::digests`, `App::granted`, `Policy::apps`, `Bearer::expose`, `Timestamp::unix_millis`, the `Display` of `Slot` and `Check::expecting`. Step 3 and later steps call several of them. Two deserve a test before that: `Bearer::expose` (G5) and the `Debug` of `GateId`, because an audit line can print it.

**Cost.** About 3 minutes locally. Expect 6 to 9 minutes on a runner of 4 cores. `cargo mutants --in-diff` tests only the mutants in a pull request's diff.

**Recommendation.** Adopt the 11 groups of tests above now. Run cargo-mutants by hand before each core pull request, or as a weekly job. Do not make it a merge gate yet. An accessor survivor fails it until its first caller exists.

## 8. Fuzzing: cargo-fuzz and bolero

**cargo-fuzz trial.** Commit `7fb6b8c` adds `fuzz/`, a crate outside the workspace with 4 targets:

| Target | What it checks |
|---|---|
| `strict_read` | `strict::read_value` never panics. Each text that it accepts is also plain JSON for `serde_json`. |
| `policy_load` | `Policy::load` never panics, with a fixed install file and no fence |
| `manifest_read` | `Manifest::read` never panics |
| `install_read` | `InstallFile::read` never panics |

A JSON dictionary and one seed file per target start each run. A unit test checks that the policy seed loads.

**Result.** Each target ran 5 minutes, 4 in parallel, built with `-O` and AddressSanitizer.

| Target | Runs | Runs per second | Coverage at start, at end |
|---|---|---|---|
| `strict_read` | 15.9 million | 52 800 | 613, 1619 |
| `policy_load` | 19.2 million | 63 900 | 653, 2312 |
| `manifest_read` | 25.0 million | 82 900 | 317, 1627 |
| `install_read` | 22.1 million | 73 500 | 223, 1402 |

No target found a crash or a failed assertion. Two limits apply:

1. libFuzzer grows the input length slowly. At the end, inputs were 40 bytes or less. A longer run needs `-len_control=0` or `-max_len` with a larger seed set.
2. `policy_load` coverage still grew at the end. `strict_read` stopped growing after about 9 million runs.

**bolero trial.** `trials/bolero/` holds one harness on the strict reader.

1. bolero 0.13.7 has no proptest bridge. Its generators are its own `TypeGenerator` and the `arbitrary` crate. The proptest strategies of `tests/decide.rs` cannot move to bolero without a rewrite.
2. On stable, `cargo test` runs the harness on random bytes for 1 s. Random bytes rarely form JSON, so this mode tests little beyond rule 2.
3. `cargo bolero test` runs libFuzzer and needs nightly, as cargo-fuzz does.
4. bolero can run the same harness under Kani, through `bolero-kani`. Section 9 shows that Kani cannot yet run the strict reader in useful time, so this gives no gain today.

**Cost.** Setup took about 20 minutes, mostly the nightly toolchain. A build of the 4 targets takes 16 s. A run uses one core per target.

**Recommendation.** cargo-fuzz: later. Add a weekly scheduled job of 30 minutes per target, with `-len_control=0` and a cached corpus. Do it when step 3 lands, because the front door then reads untrusted request bodies through the strict reader (G2). Add a front door target at that time. bolero: skip. It adds a second harness style and no reuse.

## 9. Kani pilot

**Trial.** Kani 0.68.0. The reader and G7 harnesses are in `crates/core/src/proofs.rs`. The fence-table harnesses are in a module at the end of `crates/core/src/decide.rs`, because `passes` is private. All of them are behind `#[cfg(kani)]`. Normal builds do not compile them. Two crate-private helpers, also behind `#[cfg(kani)]`, build a policy without JSON (`policy::proof_policy`) and a fixed gate ID (`GateId::from_bytes`).

**Setup.** `cargo install --locked kani-verifier` took 19 s. `cargo kani setup` took 21 s and wrote 352 MB to `~/.kani`. Kani brings its own nightly toolchain. A G7 proof needs `-Z stubbing`.

**Harness effort.** The G7 proof has about 90 lines, most of them fixture. The policy helper has 36 lines. The reader proof has 12 lines. The fence-table proof in `decide.rs` has about 50 lines. Each proof took under 30 minutes to write. The runs took the time.

**Result.** No proof finished with a verdict. Each run had a cap of 30 minutes or less, and a watchdog stopped each run that reached its cap.

| Proof | Bound | Result | Time |
|---|---|---|---|
| (a) The strict reader does not panic on any 2-byte input | `unwind(4)` | No verdict. Symbolic execution did not end. At the stop it was inside `memchr`, which `serde_json` uses to count lines for an error position. | Stopped at 2 h 46 min. A watchdog fault let it run past its cap. |
| (b) G7 with the real gate hash | `unwind(3)` | Fails on an unwinding assertion inside `hybrid-array`, where `sha2` sets up its state. Kani also lists the aarch64 SHA instructions of `sha2` as unsupported. | 91 s |
| (b) G7, gate hash replaced by a fixed ID | `unwind(5)` | No verdict. At the stop it was still in symbolic execution, in the drop code of the policy's `BTreeMap`. | Stopped at 28 min |
| (b) G7, fixed ID, one-character names | `unwind(3)` | CBMC ran out of memory | 13.6 min |
| (b) G7, fixed ID, drops skipped with `mem::forget` | `unwind(3)` | Symbolic execution ended in 84 s: 835 772 steps, 10 342 checks after simplification. CBMC then ran out of memory while it built the solver formula. | 13.4 min |
| Fence table, all scalar kinds | `unwind(3)` | No verdict | Stopped at 10 min |
| Fence table, booleans and integers only | `unwind(3)` | CBMC ran out of memory | 128 s |

The G7 runs and the first fence run shared the 32 GiB of the machine. A run alone may need less memory than that. The last fence run ran alone and still ran out of memory.

**Where Kani stops.**

1. `sha2`. On aarch64, `sha2` uses the SHA instructions of the CPU. Kani does not support them. The loops of `hybrid-array` also need a large unwind bound. A stub of `GateId::from_call` removes both. The G7 proof decides one call twice, so one fixed ID stands for any ID of that call. The stub does not weaken the proof.
2. `serde_json`. A reader proof on 2 bytes did not leave symbolic execution in 2 h 46 min. The float writer of `serde_json` (the `zmij` crate) uses NEON instructions that Kani does not support. Only the canonical text of a float reaches that code.
3. `std` maps and the recursive `ArgValue`. `ArgValue::Object` holds a `BTreeMap<String, ArgValue>`. The drop code of that type recurses. The fence-table proof builds no map, but its log shows that Kani unwound this drop code and the `BTreeMap` drop code. That run then ran out of memory.

**Recommendation.** Skip. Kani cannot prove a property of `decide()` or of the strict reader in under 30 minutes on this machine. The proptest property `g7_a_new_fence_only_narrows` already tests G7 on random fences in under 1 s. The mutation tests of section 7 close the gaps that it leaves. Look at Kani again in one of two cases:

1. Core gains a small kernel with no map, no string and no recursive type, such as the gate state machine of design section 5.3.
2. A Kani release reports better support for `BTreeMap` and for recursive drop code.

The harnesses stay on `tooling-eval` for that later attempt.

## 10. Brief notes

**cargo-nextest 0.9.149.** It ran all 80 tests in 0.59 s. `cargo test` runs them in 0.14 s. nextest runs each test in its own process, which isolates a test that leaks global state. Core has no global state (G3). Later, when `crates/chaperone` adds slow tests or tests that bind sockets.

**cargo-llvm-cov 0.9.1.** Core coverage is 92.73 % of lines, 92.40 % of regions and 89.25 % of functions. A run takes 13 s. These G2 error paths have no test:

1. `policy.rs:277`: a wrong `version` refuses the policy.
2. `policy.rs:330`: one app instance lists the same digest twice.
3. `policy.rs:345`: an upstream grant with no tool.
4. `strict.rs:228`: an object, not an array, nests deeper than `DEPTH_MAX`.

The mutation tests in section 7 and these four tests close most of the gap. Later, as a report in CI with no threshold. A threshold invites tests that only execute lines.

**cargo-shear 1.14.0.** One finding: `schemars` is a workspace dependency that no crate uses. The JSON Schema generation of design step 8 needs it. Later. Remove it until step 8, or add `[workspace.metadata.cargo-shear] ignored = ["schemars"]`.

**cargo-auditable 0.7.7.** `cargo auditable build -p chaperone-core --release` builds with no change in 7.5 s. The tool embeds the dependency list in a binary, so a scanner can check a deployed binary for advisories. Core is a library and ships no binary. Later, at the first tagged release of `crates/chaperone` (design section 12).

**Flux.** Not tried. Flux adds refinement types such as "a `usize` at most `DEPTH_MAX`". It needs nightly and its own driver, and it is a research tool. The newtypes and the clippy lints of section 5 already cover the cases in core. Skip. Look again if Flux reaches stable Rust or if core gains arithmetic that a guarantee depends on.

**Not evaluated:** Miri (core forbids `unsafe`), cargo-semver-checks (`publish = false`), cargo-vet (cargo-deny covers the supply chain at this size). Nothing in the trials changed this reasoning.

## 11. What the tools found in the code

These items need a change in the code or the tests, independent of any tool:

1. Fences on booleans and strings have no test. A broken comparison passes the whole test suite (section 7, G7).
2. The canonical text of arrays and floats has no test. A bug there makes two different calls share a gate ID (section 7, G7).
3. The test `refuses_a_duplicate_key_written_with_an_escape` (`strict.rs:297`) uses the same input as `refuses_a_duplicate_key`: `{"a": 1, "a": 2}`. It does not write the key with an escape. The intended input is likely `{"a": 1, "a": 2}`.
4. The rustdoc of `strict` links to a private item (section 3).
5. The `rand` crate ships through `rmcp` in step 3 (section 4).
6. The strict reader checks duplicate keys with a `HashSet` (`strict.rs:230`). `HashSet::new` uses `RandomState`, which reads random keys from the OS. The result stays deterministic, but core then reads OS randomness, which `crates/core/AGENTS.md` refuses (G3). The core clippy bans do not list `HashMap` or `HashSet`. Commit `5ec90e9` uses a `BTreeSet` and adds both types to `disallowed-types`. All 80 tests pass.

## 12. The follow-up pull request

Five changes, ranked by the guarantee value per hour of work. Each change states its exact configuration. The list assumes that the pull request lands after step 3.

### Change 1: tests that kill the G7 and G2 survivors

Add the tests of section 7, table "Survivors that break a guarantee", and the 4 tests of section 10. Fix the escape test of section 11, item 3. About 2 hours. No configuration.

Verify with:

```bash
cargo mutants -p chaperone-core -j 4
```

The guarantee rows of section 7 must then show as caught.

### Change 2: cargo-deny

Add `deny.toml` at the repository root:

```toml
[graph]
all-features = true
# The ban list and the license list judge only what ships.
exclude-dev = true

[advisories]
unmaintained = "all"
yanked = "deny"
ignore = []

[licenses]
allow = [
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-3-Clause",
    "MIT",
    "Unicode-3.0",
    "Zlib",
]
confidence-threshold = 0.93
unused-allowed-license = "allow"

[licenses.private]
ignore = true

[bans]
multiple-versions = "deny"
wildcards = "deny"
allow-wildcard-paths = true
highlight = "all"
skip = [
    { crate = "syn@2", reason = "tracing-attributes uses syn 2. A proc macro does not ship." },
]
deny = [
    { crate = "md-5", reason = "AGENTS.md rule 9" },
    { crate = "md5", reason = "AGENTS.md rule 9" },
    { crate = "sha1", reason = "AGENTS.md rule 9" },
    { crate = "sha3", reason = "AGENTS.md rule 9" },
    { crate = "blake2", reason = "AGENTS.md rule 9" },
    { crate = "blake3", reason = "AGENTS.md rule 9" },
    { crate = "hmac", reason = "AGENTS.md rule 9" },
    { crate = "hkdf", reason = "AGENTS.md rule 9" },
    { crate = "pbkdf2", reason = "AGENTS.md rule 9" },
    { crate = "argon2", reason = "AGENTS.md rule 9" },
    { crate = "bcrypt", reason = "AGENTS.md rule 9" },
    { crate = "scrypt", reason = "AGENTS.md rule 9" },
    { crate = "aes", reason = "AGENTS.md rule 9" },
    { crate = "aes-gcm", reason = "AGENTS.md rule 9" },
    { crate = "chacha20", wrappers = ["rand"], reason = "AGENTS.md rule 9. rand uses it as its RNG." },
    { crate = "chacha20poly1305", reason = "AGENTS.md rule 9" },
    { crate = "ed25519-dalek", reason = "AGENTS.md rule 9" },
    { crate = "x25519-dalek", reason = "AGENTS.md rule 9" },
    { crate = "curve25519-dalek", reason = "AGENTS.md rule 9" },
    { crate = "p256", reason = "AGENTS.md rule 9" },
    { crate = "rsa", reason = "AGENTS.md rule 9" },
    { crate = "ring", reason = "AGENTS.md rule 9" },
    { crate = "openssl", reason = "AGENTS.md rule 9" },
    { crate = "openssl-sys", reason = "AGENTS.md rule 9" },
    { crate = "native-tls", reason = "AGENTS.md rule 9" },
    { crate = "aws-lc-rs", reason = "AGENTS.md rule 9" },
    { crate = "aws-lc-sys", reason = "AGENTS.md rule 9" },
    { crate = "boring", reason = "AGENTS.md rule 9" },
    { crate = "rand", wrappers = ["rmcp"], reason = "design.md 9: tokens use getrandom. Only rmcp may use rand." },
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

On `main` alone, the `rand` and `chacha20` wrappers report "wrapper not encountered" as a warning. The check still passes.

### Change 3: clippy lints

In the root `Cargo.toml`:

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
missing_debug_implementations = "warn"

[workspace.lints.clippy]
pedantic = { level = "warn", priority = -1 }
allow_attributes_without_reason = "deny"
dbg_macro = "deny"
expect_used = "deny"
panic = "deny"
print_stderr = "deny"
print_stdout = "deny"
unwrap_used = "deny"
wildcard_enum_match_arm = "deny"
```

At the top of `crates/core/src/lib.rs`, after the crate comment:

```rust
// G2: a panic is an unhandled error. These lints refuse the panics that
// arithmetic and slicing can hide.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::string_slice
)]
```

Then:

1. Apply the 3 library fixes of section 5, from commit `0d88733`.
2. Add `clippy::arithmetic_side_effects` and `clippy::string_slice` to the `#![allow]` list of `crates/core/tests/decide.rs`.
3. Fix the 7 step 3 hits of section 5 as the table there says.
4. In `crates/core/src/strict.rs`, use `BTreeSet` in place of `HashSet`. Add these lines to `disallowed-types` in `crates/core/clippy.toml`:

```toml
  { path = "std::collections::HashMap", reason = "G3: RandomState reads OS randomness. Use BTreeMap" },
  { path = "std::collections::HashSet", reason = "G3: RandomState reads OS randomness. Use BTreeSet" },
```

About 1 hour.

### Change 4: CI hardening

In `.github/workflows/ci.yml`:

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  gate:
    name: Format, lint and test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      # The existing steps follow here.
      - name: Dependencies
        run: |
          cargo install --locked cargo-deny@0.20.2
          cargo deny check
      - name: Workflows
        run: pipx run zizmor==1.31.1 --offline .github/workflows
```

The source install of cargo-deny adds about 2 minutes per run. A prebuilt binary can install in under 10 s, through an install action pinned to a full SHA. The org policy needs that pin. A maintainer picks the action.

### Change 5: toolchain 1.99.1

In `rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.99.1"
components = ["rustfmt", "clippy"]
```

In the root `Cargo.toml`:

```toml
[workspace.package]
rust-version = "1.99"
```

Ten minutes. Run the bump first in the pull request, so that the lints of change 3 run on the new toolchain.

### Not in the follow-up pull request

1. cargo-fuzz as a scheduled job: after step 3, with a front door target (section 8).
2. cargo-mutants as a weekly job (section 7).
3. Kani: skip (section 9).
4. Coverage as a CI report (section 10).

## 13. Trial commits on `tooling-eval`

| Commit | Trial |
|---|---|
| `d8177ad` | Toolchain 1.99.1 |
| `0d88733` | Extra clippy lints and the 3 library fixes |
| `a7d97d1` | `deny.toml` for `main` |
| `fa8d8b8` | zizmor fixes in `ci.yml` |
| `c1e0948` | The proposed `deny.toml`, which also passes on step 3 |
| `7fb6b8c` | cargo-fuzz targets and the bolero harness |
| `aba251e` | Kani proofs of the strict reader and of G7 |
| `1ef9746` | The first draft of this report |
| `8531f09` | Kani proofs of the argument-fence table |
| `5ec90e9` | A `BTreeSet` in the strict reader, and a ban on hash collections in core |

## 14. Questions for a maintainer

1. `rmcp` brings `rand` and `chacha20` into the binary. Change 2 allows them only through `rmcp`. Is that acceptable under rule 9, or must the front door avoid `rmcp`?
2. Change 2 allows `BSD-3-Clause`. `subtle`, which design section 9 names, needs it. Confirm.
3. Change 3 sets `pedantic` to warn. With `-D warnings` in CI, a pedantic hit fails CI. Confirm that each toolchain bump may need small lint fixes.

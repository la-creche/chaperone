//! Compile-fail tests: each file in `tests/ui` must not compile. Each one
//! proves that a type rule of `docs/design.md` holds at compile time.

#[test]
fn type_rules_hold_at_compile_time() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*.rs");
}

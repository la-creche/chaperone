//! Kani proofs. `cargo kani -p chaperone-core` runs them. Normal builds do
//! not compile this module.

use std::collections::{BTreeMap, BTreeSet};

use crate::decide::{Decision, GateId, Gates, Request, decide};
use crate::hook::{Caller, FenceReason, FenceVerdict, PreparedFence, Reach, ToolCall};
use crate::ids::{AppId, PluginName, ToolName};
use crate::policy::{Approval, Limits, proof_policy};
use crate::strict::{self, ByteCap};
use crate::time::Timestamp;

#[derive(Debug)]
struct Fixed(FenceVerdict);

impl PreparedFence for Fixed {
    fn check(&self, _: &ToolCall<'_>) -> FenceVerdict {
        self.0.clone()
    }
}

fn any_verdict() -> FenceVerdict {
    let pick: u8 = kani::any();
    kani::assume(pick < 3);
    match pick {
        0 => FenceVerdict::Pass,
        1 => FenceVerdict::Gate,
        _ => FenceVerdict::Deny(FenceReason::new("no")),
    }
}

fn name(text: &str) -> PluginName {
    let Ok(name) = PluginName::try_new(text) else {
        unreachable!()
    };
    name
}

/// (a) The strict reader does not panic on any input of `N` bytes.
fn strict_reader_no_panic<const N: usize>() {
    let bytes: [u8; N] = kani::any();
    let _ = strict::read_value(&bytes, ByteCap::new(N));
}

#[kani::proof]
#[kani::unwind(4)]
fn strict_reader_no_panic_2() {
    strict_reader_no_panic::<2>();
}

#[kani::proof]
#[kani::unwind(6)]
fn strict_reader_no_panic_4() {
    strict_reader_no_panic::<4>();
}

/// The gate ID is a SHA-256 hash. G7 holds for every ID, so the proof
/// replaces the hash with one fixed ID. Kani cannot run the aarch64 SHA
/// instructions of `sha2`.
fn fixed_gate_id(_: &ToolCall<'_>) -> GateId {
    GateId::from_bytes([7; 16])
}

/// (b) G7: one more fence never turns a deny or a gate into an allow.
#[kani::proof]
#[kani::stub(GateId::from_call, fixed_gate_id)]
#[kani::unwind(5)]
fn g7_a_fence_never_widens() {
    let (Ok(app), Ok(tool)) = (AppId::try_new("app"), ToolName::try_new("t")) else {
        unreachable!()
    };
    let upstream = name("up");
    let limits = Limits {
        calls_per_minute: kani::any(),
        max_pending_gates: kani::any(),
    };
    let approval = if kani::any() {
        Approval::Required
    } else {
        Approval::None
    };
    let base = any_verdict();
    let extra = any_verdict();

    let narrow = proof_policy(
        app.clone(),
        limits,
        upstream.clone(),
        tool.clone(),
        approval,
        vec![(name("a"), Box::new(Fixed(base.clone())))],
    );
    let wide = proof_policy(
        app.clone(),
        limits,
        upstream.clone(),
        tool.clone(),
        approval,
        vec![
            (name("a"), Box::new(Fixed(base))),
            (name("zz"), Box::new(Fixed(extra))),
        ],
    );

    let arguments = BTreeMap::new();
    let now = Timestamp::from_unix_millis(kani::any());
    let id = GateId::from_call(&ToolCall {
        app: &app,
        upstream: &upstream,
        tool: &tool,
        arguments: &arguments,
        now,
    });
    let mut pending = BTreeSet::new();
    if kani::any() {
        pending.insert(id);
    }
    let mut approved = BTreeMap::new();
    if kani::any() {
        approved.insert(id, Timestamp::from_unix_millis(kani::any()));
    }
    let mut denied = BTreeMap::new();
    if kani::any() {
        denied.insert(id, Timestamp::from_unix_millis(kani::any()));
    }
    let caller = Caller {
        app,
        reach: if kani::any() {
            Reach::Full
        } else {
            Reach::Only(BTreeMap::new())
        },
    };
    let request = Request {
        caller: Some(&caller),
        upstream: &upstream,
        tool: &tool,
        arguments: &arguments,
        calls_this_minute: kani::any(),
        gates: Gates {
            pending: &pending,
            approved: &approved,
            denied: &denied,
        },
        now,
    };

    let before = decide(Some(&narrow), &request);
    let after = decide(Some(&wide), &request);
    if before != Decision::Allow {
        assert!(after != Decision::Allow);
    }
}

/// (b) G7, small variant: one-character names, so `unwind(3)` covers
/// every name check.
#[kani::proof]
#[kani::stub(GateId::from_call, fixed_gate_id)]
#[kani::unwind(3)]
fn g7_small_names() {
    let (Ok(app), Ok(tool)) = (AppId::try_new("p"), ToolName::try_new("t")) else {
        unreachable!()
    };
    let upstream = name("u");
    let limits = Limits {
        calls_per_minute: kani::any(),
        max_pending_gates: kani::any(),
    };
    let approval = if kani::any() {
        Approval::Required
    } else {
        Approval::None
    };
    let base = any_verdict();
    let extra = any_verdict();

    let narrow = proof_policy(
        app.clone(),
        limits,
        upstream.clone(),
        tool.clone(),
        approval,
        vec![(name("a"), Box::new(Fixed(base.clone())))],
    );
    let wide = proof_policy(
        app.clone(),
        limits,
        upstream.clone(),
        tool.clone(),
        approval,
        vec![
            (name("a"), Box::new(Fixed(base))),
            (name("z"), Box::new(Fixed(extra))),
        ],
    );

    let arguments = BTreeMap::new();
    let now = Timestamp::from_unix_millis(kani::any());
    let id = GateId::from_call(&ToolCall {
        app: &app,
        upstream: &upstream,
        tool: &tool,
        arguments: &arguments,
        now,
    });
    let mut pending = BTreeSet::new();
    if kani::any() {
        pending.insert(id);
    }
    let mut approved = BTreeMap::new();
    if kani::any() {
        approved.insert(id, Timestamp::from_unix_millis(kani::any()));
    }
    let mut denied = BTreeMap::new();
    if kani::any() {
        denied.insert(id, Timestamp::from_unix_millis(kani::any()));
    }
    let caller = Caller {
        app,
        reach: if kani::any() {
            Reach::Full
        } else {
            Reach::Only(BTreeMap::new())
        },
    };
    let request = Request {
        caller: Some(&caller),
        upstream: &upstream,
        tool: &tool,
        arguments: &arguments,
        calls_this_minute: kani::any(),
        gates: Gates {
            pending: &pending,
            approved: &approved,
            denied: &denied,
        },
        now,
    };

    let before = decide(Some(&narrow), &request);
    let after = decide(Some(&wide), &request);
    if before != Decision::Allow {
        assert!(after != Decision::Allow);
    }
}

/// (b) G7, small variant without drops. `mem::forget` skips the drop code
/// of the maps, which costs Kani most of its time.
#[kani::proof]
#[kani::stub(GateId::from_call, fixed_gate_id)]
#[kani::unwind(3)]
fn g7_small_no_drop() {
    let (Ok(app), Ok(tool)) = (AppId::try_new("p"), ToolName::try_new("t")) else {
        unreachable!()
    };
    let upstream = name("u");
    let limits = Limits {
        calls_per_minute: kani::any(),
        max_pending_gates: kani::any(),
    };
    let approval = if kani::any() {
        Approval::Required
    } else {
        Approval::None
    };
    let base = any_verdict();
    let extra = any_verdict();

    let narrow = proof_policy(
        app.clone(),
        limits,
        upstream.clone(),
        tool.clone(),
        approval,
        vec![(name("a"), Box::new(Fixed(base.clone())))],
    );
    let wide = proof_policy(
        app.clone(),
        limits,
        upstream.clone(),
        tool.clone(),
        approval,
        vec![
            (name("a"), Box::new(Fixed(base))),
            (name("z"), Box::new(Fixed(extra))),
        ],
    );

    let arguments = BTreeMap::new();
    let now = Timestamp::from_unix_millis(kani::any());
    let id = GateId::from_call(&ToolCall {
        app: &app,
        upstream: &upstream,
        tool: &tool,
        arguments: &arguments,
        now,
    });
    let mut pending = BTreeSet::new();
    if kani::any() {
        pending.insert(id);
    }
    let mut approved = BTreeMap::new();
    if kani::any() {
        approved.insert(id, Timestamp::from_unix_millis(kani::any()));
    }
    let mut denied = BTreeMap::new();
    if kani::any() {
        denied.insert(id, Timestamp::from_unix_millis(kani::any()));
    }
    let caller = Caller {
        app,
        reach: if kani::any() {
            Reach::Full
        } else {
            Reach::Only(BTreeMap::new())
        },
    };
    let request = Request {
        caller: Some(&caller),
        upstream: &upstream,
        tool: &tool,
        arguments: &arguments,
        calls_this_minute: kani::any(),
        gates: Gates {
            pending: &pending,
            approved: &approved,
            denied: &denied,
        },
        now,
    };

    let before = decide(Some(&narrow), &request);
    let after = decide(Some(&wide), &request);
    if before != Decision::Allow {
        assert!(after != Decision::Allow);
    }
    std::mem::forget((narrow, wide, pending, approved, denied, caller, arguments));
}

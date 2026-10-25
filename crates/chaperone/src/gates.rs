//! The gate state of each app instance (`docs/design.md` 5.3). The program
//! keeps it here and passes it to the decision as values (G3). Each gate
//! carries a watch channel that the approval task moves along.

use std::collections::BTreeMap;
use std::time::Duration;

use chaperone_core::{AppId, DenialReason, GateId, Timestamp, UpstreamResult};
use tokio::sync::watch;

/// The life of a gate from its creation (`docs/design.md` 5.5).
pub const GATE_LIFE: Duration = Duration::from_secs(600);

/// Where one gate stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateStatus {
    /// The approval channel has not answered.
    Pending,
    /// The approval channel approved, and the call runs.
    Running,
    /// The call ran. The result waits to be collected once.
    Done(UpstreamResult),
    /// The approval channel denied, with its reason.
    Denied(DenialReason),
    /// The approval channel gave no answer of the right shape, or none in
    /// the life of the gate, or the call could not run. The gate counts as
    /// denied (G2).
    Faulted,
}

#[derive(Debug)]
struct Gate {
    status: watch::Sender<GateStatus>,
    expires: Timestamp,
}

/// Whether `open` found a live gate or created one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
    Created,
    Found,
}

/// The gates of one app instance, as the decision takes them. Each value is
/// the time the gate expires.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GateMaps {
    pub pending: BTreeMap<GateId, Timestamp>,
    pub approved: BTreeMap<GateId, Timestamp>,
    pub denied: BTreeMap<GateId, Timestamp>,
}

/// Every live gate of every app instance.
#[derive(Debug, Default)]
pub struct GateBook {
    gates: BTreeMap<AppId, BTreeMap<GateId, Gate>>,
}

impl GateBook {
    /// Drop the expired gates of `app`, then list the live ones by status.
    pub fn snapshot(&mut self, app: &AppId, now: Timestamp) -> GateMaps {
        let mut maps = GateMaps::default();
        let Some(gates) = self.gates.get_mut(app) else {
            return maps;
        };
        gates.retain(|_, gate| gate.expires > now);
        for (id, gate) in gates.iter() {
            let into = match &*gate.status.borrow() {
                GateStatus::Pending | GateStatus::Running => &mut maps.pending,
                GateStatus::Done(_) => &mut maps.approved,
                GateStatus::Denied(_) | GateStatus::Faulted => &mut maps.denied,
            };
            into.insert(*id, gate.expires);
        }
        maps
    }

    /// The watch of `gate` for `app`. A gate that is missing or expired at
    /// `now` is created pending, to expire `life` later. The sender is
    /// returned only for a created gate, so only its creator asks the
    /// approval channel.
    pub fn open(
        &mut self,
        app: &AppId,
        gate: GateId,
        now: Timestamp,
        life: Duration,
    ) -> (
        watch::Receiver<GateStatus>,
        Opened,
        Option<watch::Sender<GateStatus>>,
    ) {
        let gates = self.gates.entry(app.clone()).or_default();
        if let Some(found) = gates.get(&gate)
            && found.expires > now
        {
            return (found.status.subscribe(), Opened::Found, None);
        }
        let (sender, receiver) = watch::channel(GateStatus::Pending);
        let expires = now
            .checked_add(life)
            .unwrap_or(Timestamp::from_unix_millis(i64::MAX));
        gates.insert(
            gate,
            Gate {
                status: sender.clone(),
                expires,
            },
        );
        (receiver, Opened::Created, Some(sender))
    }

    /// Collect the kept result of `gate` and remove the gate. A result is
    /// collected once (`docs/design.md` 5.3).
    pub fn take_result(&mut self, app: &AppId, gate: GateId) -> Option<UpstreamResult> {
        let gates = self.gates.get_mut(app)?;
        let result = match &*gates.get(&gate)?.status.borrow() {
            GateStatus::Done(result) => result.clone(),
            GateStatus::Pending
            | GateStatus::Running
            | GateStatus::Denied(_)
            | GateStatus::Faulted => return None,
        };
        gates.remove(&gate);
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> AppId {
        AppId::try_new("app").unwrap()
    }

    const NOW: Timestamp = Timestamp::from_unix_millis(1_000_000);
    const GATE: GateId = GateId::from_bytes([7; 16]);

    #[test]
    fn a_created_gate_is_pending_and_a_second_open_finds_it() {
        let mut book = GateBook::default();
        let (rx, opened, sender) = book.open(&app(), GATE, NOW, GATE_LIFE);
        assert_eq!(opened, Opened::Created);
        assert!(sender.is_some());
        assert_eq!(*rx.borrow(), GateStatus::Pending);
        let (_, again, none) = book.open(&app(), GATE, NOW, GATE_LIFE);
        assert_eq!(again, Opened::Found);
        assert!(none.is_none());
        let maps = book.snapshot(&app(), NOW);
        assert_eq!(maps.pending.len(), 1);
        assert!(maps.approved.is_empty() && maps.denied.is_empty());
    }

    fn result() -> UpstreamResult {
        UpstreamResult {
            content: vec!["done".to_owned()],
            is_error: false,
        }
    }

    #[test]
    fn a_result_moves_the_gate_and_is_taken_once() {
        let mut book = GateBook::default();
        let (_, _, sender) = book.open(&app(), GATE, NOW, GATE_LIFE);
        let sender = sender.unwrap();
        sender.send_replace(GateStatus::Running);
        assert_eq!(book.snapshot(&app(), NOW).pending.len(), 1);
        assert_eq!(book.take_result(&app(), GATE), None);
        sender.send_replace(GateStatus::Done(result()));
        assert_eq!(book.snapshot(&app(), NOW).approved.len(), 1);
        assert_eq!(book.take_result(&app(), GATE), Some(result()));
        assert_eq!(book.take_result(&app(), GATE), None);
        assert_eq!(book.snapshot(&app(), NOW), GateMaps::default());
    }

    #[test]
    fn a_denial_and_a_fault_count_as_denied_and_are_not_taken() {
        let mut book = GateBook::default();
        let other = GateId::from_bytes([8; 16]);
        let (_, _, denied) = book.open(&app(), GATE, NOW, GATE_LIFE);
        let (_, _, faulted) = book.open(&app(), other, NOW, GATE_LIFE);
        denied
            .unwrap()
            .send_replace(GateStatus::Denied(DenialReason::new("no")));
        faulted.unwrap().send_replace(GateStatus::Faulted);
        assert_eq!(book.snapshot(&app(), NOW).denied.len(), 2);
        assert_eq!(book.take_result(&app(), GATE), None);
    }

    #[test]
    fn an_expired_gate_is_dropped_and_opened_anew() {
        let mut book = GateBook::default();
        let (_, _, sender) = book.open(&app(), GATE, NOW, GATE_LIFE);
        sender.unwrap().send_replace(GateStatus::Done(result()));
        let later = NOW.checked_add(GATE_LIFE).unwrap();
        assert_eq!(book.snapshot(&app(), later), GateMaps::default());
        let (_, opened, _) = book.open(&app(), GATE, later, GATE_LIFE);
        assert_eq!(opened, Opened::Created);
    }
}

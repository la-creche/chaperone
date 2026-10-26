//! The calls in flight of each app instance to each upstream
//! (`docs/design.md` 5.2). A call takes one slot before its decision and
//! gives it back after its final record. Each call reads the count of the
//! slots taken before its own, so two calls never read the same count.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chaperone_core::{AppId, PluginName};

/// The app instance and the upstream of one count.
type Key = (AppId, PluginName);

/// The running calls of each app instance to each upstream. Clones share
/// one count.
#[derive(Debug, Clone, Default)]
pub(crate) struct Inflight(Arc<Mutex<BTreeMap<Key, u32>>>);

/// A panic left the lock poisoned. The program does not reach inside a
/// poisoned lock, so the call fails (G2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Poisoned;

impl Inflight {
    /// Take one slot for a call of `app` to `upstream`. Return the slot and
    /// the count of the slots of the same pair taken before it.
    pub(crate) fn take(&self, app: &AppId, upstream: &PluginName) -> Result<(Slot, u32), Poisoned> {
        let mut running = self.0.lock().map_err(|_| Poisoned)?;
        let key = (app.clone(), upstream.clone());
        let count = running.entry(key.clone()).or_insert(0);
        let before = *count;
        *count = count.saturating_add(1);
        let slot = Slot {
            owner: self.clone(),
            key,
        };
        Ok((slot, before))
    }

    /// Give back one slot of `key`. A poisoned lock keeps the count, so the
    /// limit stays closed (G2).
    fn give_back(&self, key: &Key) {
        let Ok(mut running) = self.0.lock() else {
            return;
        };
        let Some(count) = running.get_mut(key) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            running.remove(key);
        }
    }
}

/// One taken slot. The slot goes back when the value drops.
#[derive(Debug)]
pub(crate) struct Slot {
    owner: Inflight,
    key: Key,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.owner.give_back(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(text: &str) -> AppId {
        AppId::try_new(text).unwrap()
    }

    fn upstream(text: &str) -> PluginName {
        PluginName::try_new(text).unwrap()
    }

    #[test]
    fn each_slot_counts_the_slots_before_it_until_it_drops() {
        let inflight = Inflight::default();
        let (first, before) = inflight
            .take(&app("research"), &upstream("attendance"))
            .unwrap();
        assert_eq!(before, 0);
        let (second, before) = inflight
            .take(&app("research"), &upstream("attendance"))
            .unwrap();
        assert_eq!(before, 1);
        drop(first);
        let (third, before) = inflight
            .take(&app("research"), &upstream("attendance"))
            .unwrap();
        assert_eq!(before, 1);
        drop((second, third));
        let (_fourth, before) = inflight
            .take(&app("research"), &upstream("attendance"))
            .unwrap();
        assert_eq!(before, 0);
    }

    #[test]
    fn each_app_and_upstream_pair_has_its_own_count() {
        let inflight = Inflight::default();
        let (_held, _) = inflight
            .take(&app("research"), &upstream("attendance"))
            .unwrap();
        let other_app = inflight
            .take(&app("librechat"), &upstream("attendance"))
            .unwrap();
        let other_upstream = inflight
            .take(&app("research"), &upstream("vikunja"))
            .unwrap();
        assert_eq!((other_app.1, other_upstream.1), (0, 0));
    }

    #[test]
    fn a_poisoned_lock_fails_the_take() {
        let inflight = Inflight::default();
        let held = inflight.clone();
        let panicked = std::thread::spawn(move || {
            let _guard = held.0.lock().unwrap();
            panic!("a panic while the lock is held");
        })
        .join();
        assert!(panicked.is_err());
        let taken = inflight.take(&app("research"), &upstream("attendance"));
        assert_eq!(taken.map(|(_, before)| before), Err(Poisoned));
    }
}

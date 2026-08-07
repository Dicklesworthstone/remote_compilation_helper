//! Foreground/optional/cleanup priority classes (bead I011; invariant
//! I18; plan §84).
//!
//! Three work classes wired through admission, queueing, and transfer
//! priority:
//!
//! - **Foreground** (a user is waiting) DOMINATES optional work: any
//!   ready foreground item dequeues before any optional one (I18);
//! - **Optional** (speculation, prewarm) runs in the gaps and is the
//!   first casualty under pressure;
//! - **Cleanup** is never starved: an aging escalator guarantees each
//!   cleanup item a bounded wait — after `cleanup_max_wait` ticks it
//!   jumps ahead of optional work even under a foreground storm, and
//!   a reserved dequeue slot (every `cleanup_slot_period` dequeues)
//!   drains cleanup even when foreground is CONTINUOUSLY saturated.

/// The three work classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum WorkClass {
    Foreground,
    Optional,
    Cleanup,
}

/// One queued work item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkItem {
    /// Class.
    pub class: WorkClass,
    /// Item label (tests/telemetry).
    pub label: String,
    /// Enqueue tick.
    pub enqueued_at: u64,
}

/// Class-priority queue with the cleanup anti-starvation escalator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassQueue {
    items: Vec<WorkItem>,
    /// Ticks after which a cleanup item escalates past optional work.
    pub cleanup_max_wait: u64,
    /// Every Nth dequeue is reserved for the oldest cleanup item.
    pub cleanup_slot_period: u64,
    dequeues: u64,
}

impl ClassQueue {
    /// New queue with the given anti-starvation parameters.
    #[must_use]
    pub fn new(cleanup_max_wait: u64, cleanup_slot_period: u64) -> Self {
        Self {
            items: Vec::new(),
            cleanup_max_wait,
            cleanup_slot_period: cleanup_slot_period.max(1),
            dequeues: 0,
        }
    }

    /// Enqueue an item.
    pub fn enqueue(&mut self, class: WorkClass, label: &str, now: u64) {
        self.items.push(WorkItem {
            class,
            label: label.to_owned(),
            enqueued_at: now,
        });
    }

    fn take(&mut self, pos: usize) -> WorkItem {
        self.dequeues += 1;
        self.items.remove(pos)
    }

    fn oldest_of(&self, class: WorkClass) -> Option<usize> {
        self.items
            .iter()
            .enumerate()
            .filter(|(_, i)| i.class == class)
            .min_by_key(|(_, i)| i.enqueued_at)
            .map(|(pos, _)| pos)
    }

    /// Dequeue the next item under the class rules.
    pub fn dequeue(&mut self, now: u64) -> Option<WorkItem> {
        // Reserved cleanup slot: every Nth dequeue drains the oldest
        // cleanup item even under continuous foreground saturation.
        if (self.dequeues + 1).is_multiple_of(self.cleanup_slot_period)
            && let Some(pos) = self.oldest_of(WorkClass::Cleanup)
        {
            return Some(self.take(pos));
        }
        // Aged cleanup escalates past OPTIONAL (not foreground).
        let aged_cleanup = self
            .oldest_of(WorkClass::Cleanup)
            .filter(|pos| now.saturating_sub(self.items[*pos].enqueued_at) > self.cleanup_max_wait);
        // Foreground dominates optional (I18), always.
        if let Some(pos) = self.oldest_of(WorkClass::Foreground) {
            return Some(self.take(pos));
        }
        if let Some(pos) = aged_cleanup {
            return Some(self.take(pos));
        }
        if let Some(pos) = self.oldest_of(WorkClass::Optional) {
            return Some(self.take(pos));
        }
        let pos = self.oldest_of(WorkClass::Cleanup)?;
        Some(self.take(pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreground_dominates_optional_always() {
        // I18: any ready foreground item beats any optional one,
        // regardless of enqueue order or age.
        let mut q = ClassQueue::new(100, 10);
        q.enqueue(WorkClass::Optional, "spec-old", 0);
        q.enqueue(WorkClass::Optional, "spec-2", 1);
        q.enqueue(WorkClass::Foreground, "user-build", 50);
        assert_eq!(q.dequeue(51).unwrap().label, "user-build");
        assert_eq!(q.dequeue(52).unwrap().label, "spec-old");
    }

    #[test]
    fn cleanup_is_never_starved_under_a_foreground_storm() {
        // THE acceptance: a continuous foreground storm; the cleanup
        // item still drains within the reserved-slot bound.
        let mut q = ClassQueue::new(100, 10);
        q.enqueue(WorkClass::Cleanup, "sandbox-cleanup", 0);
        // Storm: foreground arrives faster than it drains, forever.
        let mut cleanup_position = None;
        for tick in 0..200_u64 {
            q.enqueue(WorkClass::Foreground, &format!("fg-{tick}"), tick);
            q.enqueue(WorkClass::Foreground, &format!("fg2-{tick}"), tick);
            let item = q.dequeue(tick).unwrap();
            if item.class == WorkClass::Cleanup {
                cleanup_position = Some(tick);
                break;
            }
        }
        let drained_at = cleanup_position.expect("cleanup must drain under storm");
        assert!(
            drained_at < 10,
            "the reserved slot bounds cleanup wait to one slot period \
             (drained at dequeue {drained_at})"
        );
    }

    #[test]
    fn aged_cleanup_escalates_past_optional_but_not_foreground() {
        let mut q = ClassQueue::new(100, 1_000_000); // slot effectively off
        q.enqueue(WorkClass::Cleanup, "old-cleanup", 0);
        q.enqueue(WorkClass::Optional, "spec", 10);
        q.enqueue(WorkClass::Foreground, "user", 10);
        // At tick 200 the cleanup item is aged past cleanup_max_wait:
        // foreground still wins, but cleanup beats optional.
        assert_eq!(q.dequeue(200).unwrap().label, "user");
        assert_eq!(q.dequeue(200).unwrap().label, "old-cleanup");
        assert_eq!(q.dequeue(200).unwrap().label, "spec");
    }

    #[test]
    fn young_cleanup_yields_to_optional() {
        // Below the age threshold and off-slot, optional runs first —
        // cleanup is background work, not a queue jumper.
        let mut q = ClassQueue::new(100, 1_000_000);
        q.enqueue(WorkClass::Cleanup, "fresh-cleanup", 0);
        q.enqueue(WorkClass::Optional, "spec", 0);
        assert_eq!(q.dequeue(5).unwrap().label, "spec");
        assert_eq!(q.dequeue(6).unwrap().label, "fresh-cleanup");
    }
}

//! Weighted fairness + hard starvation bounds (bead I010; plan §84;
//! risk R22).
//!
//! Multi-tenant scheduling across the plan's dimensions (class,
//! agent/user, project, CI-vs-interactive, long-vs-short) as weighted
//! fair queueing over VIRTUAL FINISH TIMES — a tenant's next item
//! finishes at `virtual_start + cost / weight`, so heavier weights
//! drain proportionally faster while nobody is excluded. Two
//! overrides sit above the fair order:
//!
//! - **deadline/critical-path**: an item whose deadline is imminent
//!   preempts the fair order and still consumes its tenant's virtual
//!   time. It never preempts the starvation override;
//! - **hard starvation bound**: any item waiting longer than
//!   `starvation_bound` ticks dequeues NEXT regardless of weights —
//!   the R22 anti-injustice property. This is precedence over newer
//!   work, not a wall-time promise when backlog exceeds capacity.
//!
//! Cleanup/cancellation reserved capacity lives in I011/J008; this
//! queue schedules the WORK dimension.

// Fixed-point virtual time retains fractional cost/weight for small jobs.
// u128 leaves 32 bits of headroom above a scaled maximum u64 cost; saturating
// accumulation keeps even extreme histories from wrapping to the front.
const VIRTUAL_FRACTION_BITS: u32 = 32;

/// One tenant's identity across the fairness dimensions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TenantKey {
    /// Agent/user identity.
    pub agent: String,
    /// Repository/project identity.
    pub project: String,
    /// CI (true) vs interactive (false).
    pub ci: bool,
}

/// One schedulable item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairItem {
    /// Owning tenant.
    pub tenant: TenantKey,
    /// Label.
    pub label: String,
    /// Estimated cost (ms — long vs short jobs).
    pub cost: u64,
    /// Enqueue tick.
    pub enqueued_at: u64,
    /// Optional deadline tick.
    pub deadline: Option<u64>,
    /// Computed fixed-point virtual finish time, at the enqueue-time weight.
    virtual_finish: u128,
}

/// The weighted fair queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairQueue {
    items: Vec<FairItem>,
    /// Per-tenant weights (missing = 1).
    weights: Vec<(TenantKey, u64)>,
    /// Per-tenant virtual time.
    virtual_time: Vec<(TenantKey, u128)>,
    /// Per-tenant last STAMPED virtual finish (pending items included)
    /// so successive enqueues stack their virtual finishes.
    last_stamped: Vec<(TenantKey, u128)>,
    /// The hard starvation bound in ticks.
    pub starvation_bound: u64,
    /// Deadline lookahead: items due within this window preempt.
    pub deadline_window: u64,
}

impl FairQueue {
    /// New queue.
    #[must_use]
    pub fn new(starvation_bound: u64, deadline_window: u64) -> Self {
        Self {
            items: Vec::new(),
            weights: Vec::new(),
            virtual_time: Vec::new(),
            last_stamped: Vec::new(),
            starvation_bound,
            deadline_window,
        }
    }

    /// Set a tenant's weight (heavier drains proportionally faster).
    /// Applies to future enqueues; pending items retain their admission-time
    /// charge. Zero is normalized to one, including when replacing a weight.
    pub fn set_weight(&mut self, tenant: TenantKey, weight: u64) {
        match self.weights.iter_mut().find(|(t, _)| *t == tenant) {
            Some((_, current)) => *current = weight.max(1),
            None => self.weights.push((tenant, weight.max(1))),
        }
    }

    fn weight_of(&self, tenant: &TenantKey) -> u64 {
        self.weights
            .iter()
            .find(|(t, _)| t == tenant)
            .map_or(1, |(_, w)| *w)
    }

    fn virtual_time_of(&self, tenant: &TenantKey) -> u128 {
        self.virtual_time
            .iter()
            .find(|(t, _)| t == tenant)
            .map_or(0, |(_, v)| *v)
    }

    fn advance_virtual_time(&mut self, tenant: &TenantKey, to: u128) {
        match self.virtual_time.iter_mut().find(|(t, _)| t == tenant) {
            Some((_, v)) => *v = to,
            None => self.virtual_time.push((tenant.clone(), to)),
        }
    }

    /// Enqueue an item; its virtual finish is stamped now.
    /// Zero estimates incur a minimum cost of one for scheduling; the original
    /// reported cost is retained. Fractional charges round up, never to zero.
    pub fn enqueue(
        &mut self,
        tenant: TenantKey,
        label: &str,
        cost: u64,
        now: u64,
        deadline: Option<u64>,
    ) {
        let stamped = self
            .last_stamped
            .iter()
            .find(|(t, _)| *t == tenant)
            .map_or(0, |(_, v)| *v);
        let start = self.virtual_time_of(&tenant).max(stamped);
        let scaled_cost = u128::from(cost.max(1)) << VIRTUAL_FRACTION_BITS;
        let charge = scaled_cost.div_ceil(u128::from(self.weight_of(&tenant)));
        let virtual_finish = start.saturating_add(charge);
        match self.last_stamped.iter_mut().find(|(t, _)| *t == tenant) {
            Some((_, v)) => *v = virtual_finish,
            None => self.last_stamped.push((tenant.clone(), virtual_finish)),
        }
        self.items.push(FairItem {
            tenant,
            label: label.to_owned(),
            cost,
            enqueued_at: now,
            deadline,
            virtual_finish,
        });
    }

    /// Dequeue under the override + fairness rules.
    pub fn dequeue(&mut self, now: u64) -> Option<FairItem> {
        if self.items.is_empty() {
            return None;
        }
        // 1. Hard starvation bound: the oldest over-bound item wins.
        let starved = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, i)| now.saturating_sub(i.enqueued_at) > self.starvation_bound)
            .min_by_key(|(_, i)| i.enqueued_at)
            .map(|(pos, _)| pos);
        // 2. Deadline/critical-path override within the window.
        let urgent = starved.or_else(|| {
            self.items
                .iter()
                .enumerate()
                .filter(|(_, i)| {
                    i.deadline
                        .is_some_and(|d| d.saturating_sub(now) <= self.deadline_window)
                })
                .min_by_key(|(_, i)| i.deadline)
                .map(|(pos, _)| pos)
        });
        // 3. Weighted fair order: smallest virtual finish.
        let pos = urgent.unwrap_or_else(|| {
            self.items
                .iter()
                .enumerate()
                .min_by_key(|(_, i)| (i.virtual_finish, i.enqueued_at))
                .map(|(p, _)| p)
                .expect("nonempty")
        });
        let item = self.items.remove(pos);
        // Consume the charge fixed at admission, even for override winners.
        // Recomputing cost at the current weight would reprice pending work.
        // An older item served after an urgent one must not rewind the clock.
        let new_vt = self
            .virtual_time_of(&item.tenant)
            .max(item.virtual_finish);
        self.advance_virtual_time(&item.tenant, new_vt);
        Some(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(agent: &str, ci: bool) -> TenantKey {
        TenantKey {
            agent: agent.into(),
            project: "proj".into(),
            ci,
        }
    }

    #[test]
    fn weights_drain_proportionally() {
        // Interactive (weight 3) vs CI (weight 1): over 8 dequeues the
        // interactive tenant gets ~3x the slots.
        let mut q = FairQueue::new(1_000_000, 0);
        q.set_weight(tenant("dev", false), 3);
        q.set_weight(tenant("ci", true), 1);
        for i in 0..12 {
            q.enqueue(tenant("dev", false), &format!("dev-{i}"), 100, 0, None);
            q.enqueue(tenant("ci", true), &format!("ci-{i}"), 100, 0, None);
        }
        let first8: Vec<FairItem> = (0..8).map(|_| q.dequeue(1).unwrap()).collect();
        let dev_slots = first8.iter().filter(|i| i.tenant.agent == "dev").count();
        assert_eq!(dev_slots, 6, "weight 3:1 gives ~3x the early slots");
    }

    #[test]
    fn weight_updates_replace_policy_instead_of_accumulating_ignored_entries() {
        let mut q = FairQueue::new(1_000_000, 0);
        let dev = tenant("dev", false);
        q.set_weight(dev.clone(), 2);
        q.set_weight(dev.clone(), 9);
        assert_eq!(q.weight_of(&dev), 9);
        assert_eq!(q.weights.len(), 1);
        q.enqueue(dev.clone(), "updated-weight", 9, 0, None);
        q.enqueue(tenant("other", false), "other", 2, 0, None);
        assert_eq!(q.dequeue(0).unwrap().label, "updated-weight");
        q.set_weight(dev.clone(), 0);
        assert_eq!(q.weight_of(&dev), 1);
        assert_eq!(q.weights.len(), 1);
    }

    #[test]
    fn fractional_costs_keep_cheap_work_proportional_instead_of_free() {
        let mut q = FairQueue::new(1_000_000, 0);
        q.set_weight(tenant("heavy", false), 3);
        for i in 0..12 {
            q.enqueue(tenant("heavy", false), &format!("heavy-{i}"), 1, 0, None);
            q.enqueue(tenant("light", false), &format!("light-{i}"), 1, 0, None);
        }
        let heavy = (0..8)
            .filter(|_| q.dequeue(0).unwrap().tenant.agent == "heavy")
            .count();
        assert_eq!(heavy, 6, "cost 1 must still honor the 3:1 weight ratio");
    }

    #[test]
    fn zero_estimates_and_maximum_weights_still_pay_a_positive_charge() {
        let mut q = FairQueue::new(1_000_000, 0);
        let dev = tenant("dev", false);
        q.set_weight(dev.clone(), u64::MAX);
        q.enqueue(dev.clone(), "zero-estimate", 0, 0, None);
        q.enqueue(dev, "small-estimate", 1, 0, None);
        let first = q.dequeue(0).unwrap();
        let second = q.dequeue(0).unwrap();
        assert_eq!(first.cost, 0, "preserve the caller's reported estimate");
        assert!(first.virtual_finish > 0);
        assert!(second.virtual_finish > first.virtual_finish);
    }

    #[test]
    fn large_costs_do_not_wrap_to_the_front_of_the_queue() {
        let mut q = FairQueue::new(u64::MAX, 0);
        let busy = tenant("busy", false);
        q.enqueue(busy.clone(), "first", u64::MAX, 0, None);
        q.enqueue(busy, "tail", 1, 0, None);
        q.enqueue(tenant("other", false), "other", u64::MAX, 0, None);
        assert_eq!(q.dequeue(0).unwrap().label, "first");
        assert_eq!(q.dequeue(0).unwrap().label, "other");
        assert_eq!(q.dequeue(0).unwrap().label, "tail");
        assert!(q.dequeue(0).is_none());
    }

    #[test]
    fn changed_weights_do_not_reprice_already_pending_work() {
        let mut q = FairQueue::new(1_000_000, 0);
        let dev = tenant("dev", false);
        q.set_weight(dev.clone(), 8);
        q.enqueue(dev.clone(), "pending", 8, 0, None);
        let stamped = q.items[0].virtual_finish;
        q.set_weight(dev.clone(), 1);
        q.enqueue(tenant("other", false), "other", 3, 0, None);
        assert_eq!(q.dequeue(0).unwrap().label, "pending");
        assert_eq!(q.virtual_time_of(&dev), stamped);
        q.enqueue(dev, "new-weight", 1, 0, None);
        assert_eq!(q.dequeue(0).unwrap().label, "new-weight");
        assert_eq!(q.dequeue(0).unwrap().label, "other");
    }

    #[test]
    fn urgent_out_of_order_service_does_not_rewind_the_tenant_clock() {
        let mut q = FairQueue::new(1_000_000, 10);
        let dev = tenant("dev", false);
        q.enqueue(dev.clone(), "ordinary", 2, 0, None);
        q.enqueue(dev.clone(), "urgent", 3, 0, Some(1));
        let urgent = q.dequeue(0).unwrap();
        assert_eq!(urgent.label, "urgent");
        assert_eq!(q.dequeue(0).unwrap().label, "ordinary");
        assert_eq!(q.virtual_time_of(&dev), urgent.virtual_finish);
        q.enqueue(dev, "next", 1, 0, None);
        assert!(q.dequeue(0).unwrap().virtual_finish > urgent.virtual_finish);
    }

    #[test]
    fn saturated_virtual_time_remains_monotonic() {
        let mut q = FairQueue::new(u64::MAX, 0);
        let dev = tenant("dev", false);
        q.advance_virtual_time(&dev, u128::MAX - 1);
        q.enqueue(dev.clone(), "first", u64::MAX, 0, None);
        q.enqueue(dev.clone(), "second", 1, 0, None);
        for label in ["first", "second"] {
            let item = q.dequeue(0).unwrap();
            assert_eq!(item.label, label);
            assert_eq!(item.virtual_finish, u128::MAX);
            assert_eq!(q.virtual_time_of(&dev), u128::MAX);
        }
    }

    #[test]
    fn starvation_bound_holds_under_adversarial_mix() {
        // THE R22 property: one weight-1 victim item among a flood
        // from a weight-100 adversary who keeps enqueueing cheap work.
        // The victim MUST dequeue within the starvation bound.
        let mut q = FairQueue::new(50, 0);
        q.set_weight(tenant("adversary", true), 100);
        q.set_weight(tenant("victim", false), 1);
        q.enqueue(tenant("victim", false), "victim-job", 10_000, 0, None);
        let mut victim_dequeued_at = None;
        for tick in 0..200_u64 {
            // The adversary floods cheap items every tick.
            q.enqueue(
                tenant("adversary", true),
                &format!("a-{tick}"),
                1,
                tick,
                None,
            );
            q.enqueue(
                tenant("adversary", true),
                &format!("b-{tick}"),
                1,
                tick,
                None,
            );
            let item = q.dequeue(tick).unwrap();
            if item.tenant.agent == "victim" {
                victim_dequeued_at = Some(tick);
                break;
            }
        }
        let at = victim_dequeued_at.expect("victim must not starve");
        assert!(
            at <= 51,
            "hard bound: the victim dequeues within starvation_bound+1 (at {at})"
        );
    }

    #[test]
    fn deadline_override_preempts_but_still_pays_virtual_time() {
        let mut q = FairQueue::new(1_000_000, 10);
        q.set_weight(tenant("bulk", true), 1);
        q.set_weight(tenant("deadline", false), 1);
        q.enqueue(tenant("bulk", true), "cheap-1", 1, 0, None);
        q.enqueue(tenant("deadline", false), "due-soon", 1_000, 0, Some(5));
        // The deadline item preempts the cheaper fair-order winner.
        assert_eq!(q.dequeue(0).unwrap().label, "due-soon");
        // …but its tenant PAID virtual time: the next fair contest goes
        // to bulk (deadline tenant's clock advanced by its full cost).
        q.enqueue(tenant("deadline", false), "regular", 10, 1, None);
        assert_eq!(q.dequeue(1).unwrap().label, "cheap-1");
    }

    #[test]
    fn dimensions_are_first_class_in_the_tenant_key() {
        // agent/project/CI are the key: same agent in CI vs interactive
        // is two tenants with independent fairness accounts.
        let a = tenant("dev", false);
        let b = tenant("dev", true);
        assert_ne!(a, b);
        let TenantKey {
            agent: _,
            project: _,
            ci: _,
        } = a;
    }
}

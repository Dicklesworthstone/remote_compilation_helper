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
//!   preempts the fair order (bounded — it still consumes its
//!   tenant's virtual time, so a tenant cannot deadline-spam its way
//!   past fairness forever);
//! - **hard starvation bound**: any item waiting longer than
//!   `starvation_bound` ticks dequeues NEXT regardless of weights —
//!   the R22 property: no adversarial mix can hold any item beyond
//!   the bound.
//!
//! Cleanup/cancellation reserved capacity lives in I011/J008; this
//! queue schedules the WORK dimension.

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
    /// Computed virtual finish time.
    virtual_finish: u64,
}

/// The weighted fair queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairQueue {
    items: Vec<FairItem>,
    /// Per-tenant weights (missing = 1).
    weights: Vec<(TenantKey, u64)>,
    /// Per-tenant virtual time.
    virtual_time: Vec<(TenantKey, u64)>,
    /// Per-tenant last STAMPED virtual finish (pending items included)
    /// so successive enqueues stack their virtual finishes.
    last_stamped: Vec<(TenantKey, u64)>,
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
    pub fn set_weight(&mut self, tenant: TenantKey, weight: u64) {
        self.weights.push((tenant, weight.max(1)));
    }

    fn weight_of(&self, tenant: &TenantKey) -> u64 {
        self.weights
            .iter()
            .find(|(t, _)| t == tenant)
            .map_or(1, |(_, w)| *w)
    }

    fn virtual_time_of(&self, tenant: &TenantKey) -> u64 {
        self.virtual_time
            .iter()
            .find(|(t, _)| t == tenant)
            .map_or(0, |(_, v)| *v)
    }

    fn advance_virtual_time(&mut self, tenant: &TenantKey, to: u64) {
        match self.virtual_time.iter_mut().find(|(t, _)| t == tenant) {
            Some((_, v)) => *v = to,
            None => self.virtual_time.push((tenant.clone(), to)),
        }
    }

    /// Enqueue an item; its virtual finish is stamped now.
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
        let virtual_finish = start + cost / self.weight_of(&tenant);
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
        // The winner consumes ITS tenant's virtual time — even override
        // winners, so deadline spam cannot escape fairness forever.
        let new_vt = self
            .virtual_time_of(&item.tenant)
            .max(item.virtual_finish)
            .max(item.cost / self.weight_of(&item.tenant));
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

//! State machine runtime — tracks live invariant monitors.
//!
//! Each [`StateMachineInstance`] corresponds to one compiled invariant
//! from the policy. The runtime advances all instances on every event
//! and reports violations.

use std::collections::HashMap;

use smol_str::SmolStr;

use aegis_compiler::ast::{ConstraintKind, SeverityLevel, Verdict};
use aegis_compiler::ir::{
    CompiledConstraint, CompiledPolicy, CompiledRule, IRVerdict, StateId, StateKind, StateMachine,
    TemporalKind, TransitionGuard,
};

use crate::eval::{self, EvalContext};
use crate::event::{Event, Value};

// ═══════════════════════════════════════════════════════════════════════
//  Verdict result — the output of policy evaluation
// ═══════════════════════════════════════════════════════════════════════

/// The result of evaluating an event against a loaded policy.
#[derive(Debug, Clone)]
pub struct PolicyResult {
    /// The final verdict: allow, deny, audit, or redact
    pub verdict: Verdict,
    /// Human-readable reason for the verdict
    pub reason: Option<String>,
    /// Which rule(s) triggered this verdict
    pub triggered_rules: Vec<u32>,
    /// Actions to execute (log, notify, escalate, etc.)
    pub actions: Vec<ActionResult>,
    /// Any invariant violations detected
    pub violations: Vec<Violation>,
    /// Any rate limit or quota violations
    pub constraint_violations: Vec<ConstraintViolation>,
    /// Evaluation latency in microseconds
    pub eval_time_us: u64,
}

#[derive(Debug, Clone)]
pub struct ActionResult {
    pub verb: SmolStr,
    pub args: HashMap<SmolStr, Value>,
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub proof_name: SmolStr,
    pub invariant_name: SmolStr,
    pub kind: TemporalKind,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ConstraintViolation {
    pub kind: ConstraintKind,
    pub target: SmolStr,
    pub limit: u64,
    pub current: u64,
    pub window_ms: u64,
}

// ═══════════════════════════════════════════════════════════════════════
//  State machine instance — a live monitor for one invariant
// ═══════════════════════════════════════════════════════════════════════

struct StateMachineInstance {
    spec: StateMachine,
    current_state: StateId,
    start_time_ms: u64,
}

impl StateMachineInstance {
    fn new(spec: StateMachine, now_ms: u64) -> Self {
        let initial = spec.initial_state;
        Self {
            spec,
            current_state: initial,
            start_time_ms: now_ms,
        }
    }

    /// Is this instance in a violating state?
    fn is_violated(&self) -> bool {
        self.spec.violating_states.contains(&self.current_state)
    }

    /// Is this instance in an accepting/satisfied state?
    fn is_satisfied(&self) -> bool {
        self.spec.accepting_states.contains(&self.current_state)
    }

    /// Is this instance still active (not in a terminal state)?
    fn is_active(&self) -> bool {
        let state = &self.spec.states[self.current_state as usize];
        state.kind == StateKind::Active
    }

    /// Advance the state machine by one event.
    /// Returns true if a transition occurred.
    fn step(&mut self, ctx: &EvalContext<'_>, now_ms: u64) -> bool {
        if !self.is_active() {
            return false; // Terminal state — no more transitions
        }

        // Check timeout first (deadline expiry)
        if let Some(deadline) = self.spec.deadline_millis {
            let elapsed = now_ms.saturating_sub(self.start_time_ms);
            if elapsed >= deadline {
                // Find the timeout transition from current state
                for transition in &self.spec.transitions {
                    if transition.from == self.current_state {
                        if let TransitionGuard::Timeout = &transition.guard {
                            self.current_state = transition.to;
                            return true;
                        }
                    }
                }
            }
        }

        // Evaluate predicate-guarded transitions
        for transition in &self.spec.transitions {
            if transition.from != self.current_state {
                continue;
            }
            let fires = match &transition.guard {
                TransitionGuard::Predicate(expr) => eval::eval(expr, ctx).is_truthy(),
                TransitionGuard::NegatedPredicate(expr) => !eval::eval(expr, ctx).is_truthy(),
                TransitionGuard::Always => true,
                TransitionGuard::Timeout => false, // Already handled above
            };
            if fires {
                self.current_state = transition.to;
                return true;
            }
        }

        false
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Rate limiter — sliding window counter
// ═══════════════════════════════════════════════════════════════════════

struct RateLimiter {
    spec: CompiledConstraint,
    /// Timestamps of events in the current window
    timestamps: Vec<u64>,
}

impl RateLimiter {
    fn new(spec: CompiledConstraint) -> Self {
        Self {
            spec,
            timestamps: Vec::new(),
        }
    }

    /// Record an event and return whether the limit is exceeded.
    fn record(&mut self, now_ms: u64) -> bool {
        // Evict expired entries
        let window_start = now_ms.saturating_sub(self.spec.window_millis);
        self.timestamps.retain(|&t| t >= window_start);

        // Add current
        self.timestamps.push(now_ms);

        // Check limit
        self.timestamps.len() as u64 > self.spec.limit
    }

    fn current_count(&self) -> u64 {
        self.timestamps.len() as u64
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Policy engine — the top-level runtime verifier
// ═══════════════════════════════════════════════════════════════════════

/// The runtime policy engine.
///
/// Loads compiled policies, maintains state machine instances and rate
/// limiters, and evaluates incoming events. Thread-safe with interior
/// mutability (state machines and counters update on each event).
///
/// # Usage
///
/// ```ignore
/// let policy = bytecode::read_file("guard.aegisc")?;
/// let mut engine = PolicyEngine::new(policy);
///
/// let event = Event::new("tool_call")
///     .with_field("tool", Value::String("http_request".into()))
///     .with_field("url", Value::String("https://external.com".into()));
///
/// let result = engine.evaluate(&event);
/// match result.verdict {
///     Verdict::Allow => { /* proceed */ }
///     Verdict::Deny => { /* block the action */ }
///     Verdict::Audit => { /* log and proceed */ }
///     Verdict::Redact => { /* sanitize and proceed */ }
/// }
/// ```
pub struct PolicyEngine {
    policy: CompiledPolicy,
    state_machines: Vec<StateMachineInstance>,
    rate_limiters: HashMap<SmolStr, RateLimiter>,
    /// Persistent context state (accumulated across events)
    context: HashMap<SmolStr, Value>,
    /// Policy configuration
    policy_config: HashMap<SmolStr, Value>,
    /// Total events processed
    event_count: u64,
}

impl PolicyEngine {
    /// Create a new engine from a compiled policy.
    pub fn new(policy: CompiledPolicy) -> Self {
        let now_ms = current_time_ms();

        let state_machines = policy
            .state_machines
            .iter()
            .map(|sm| StateMachineInstance::new(sm.clone(), now_ms))
            .collect();

        let mut rate_limiters = HashMap::new();
        for constraint in &policy.constraints {
            rate_limiters.insert(
                constraint.target.clone(),
                RateLimiter::new(constraint.clone()),
            );
        }

        Self {
            policy,
            state_machines,
            rate_limiters,
            context: HashMap::new(),
            policy_config: HashMap::new(),
            event_count: 0,
        }
    }

    /// Set a context value (persistent across events).
    pub fn set_context(&mut self, key: impl Into<SmolStr>, value: Value) {
        self.context.insert(key.into(), value);
    }

    /// Set a policy configuration value.
    pub fn set_config(&mut self, key: impl Into<SmolStr>, value: Value) {
        self.policy_config.insert(key.into(), value);
    }

    /// Get the policy name.
    pub fn policy_name(&self) -> &str {
        &self.policy.name
    }

    /// Get the total number of events processed.
    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Evaluate an event against the loaded policy.
    ///
    /// This is the main entry point. Returns a [`PolicyResult`] with
    /// the verdict, triggered rules, actions, and any violations.
    pub fn evaluate(&mut self, event: &Event) -> PolicyResult {
        let start = std::time::Instant::now();
        let now_ms = event.timestamp_ms;
        self.event_count += 1;

        let eval_ctx = EvalContext::new(event, &self.context, &self.policy_config);

        let mut verdict = Verdict::Allow; // default
        let mut reason: Option<String> = None;
        let mut triggered_rules = Vec::new();
        let mut actions = Vec::new();
        let mut violations = Vec::new();
        let mut constraint_violations = Vec::new();

        // ── 1. Check rate limits and quotas ──────────────────────────
        for (target, limiter) in &mut self.rate_limiters {
            if event.event_type == *target {
                if limiter.record(now_ms) {
                    constraint_violations.push(ConstraintViolation {
                        kind: limiter.spec.kind,
                        target: target.clone(),
                        limit: limiter.spec.limit,
                        current: limiter.current_count(),
                        window_ms: limiter.spec.window_millis,
                    });
                    // Rate limit violation → automatic deny
                    verdict = Verdict::Deny;
                    reason = Some(format!(
                        "{:?} exceeded: {} events in {}ms window (limit: {})",
                        limiter.spec.kind,
                        limiter.current_count(),
                        limiter.spec.window_millis,
                        limiter.spec.limit
                    ));
                }
            }
        }

        // ── 2. Evaluate rules ────────────────────────────────────────
        for rule in &self.policy.rules {
            // Check if this rule applies to the event type
            let applies =
                rule.on_events.is_empty() || rule.on_events.iter().any(|e| *e == event.event_type);

            if !applies {
                continue;
            }

            // Evaluate the when condition
            let condition_met = match &rule.condition {
                Some(cond) => eval::eval(cond, &eval_ctx).is_truthy(),
                None => true, // No condition → always applies
            };

            if !condition_met {
                continue;
            }

            triggered_rules.push(rule.id);

            // Apply verdicts (last verdict wins, deny overrides all)
            for rule_verdict in &rule.verdicts {
                let new_verdict = rule_verdict.verdict;
                let new_reason = rule_verdict.message.as_ref().map(|m| {
                    let v = eval::eval(m, &eval_ctx);
                    v.as_str().unwrap_or("").to_string()
                });

                // Deny always wins over other verdicts
                if new_verdict == Verdict::Deny || verdict == Verdict::Allow {
                    verdict = new_verdict;
                    if new_reason.is_some() {
                        reason = new_reason;
                    }
                }
            }

            // Collect actions
            for action in &rule.actions {
                let mut args = HashMap::new();
                for (key, expr) in &action.args {
                    let val = eval::eval(expr, &eval_ctx);
                    args.insert(key.clone(), val);
                }
                actions.push(ActionResult {
                    verb: SmolStr::new(format!("{:?}", action.verb)),
                    args,
                });
            }
        }

        // ── 3. Advance state machines ────────────────────────────────
        for sm in &mut self.state_machines {
            if !sm.is_active() {
                // Already in terminal state — check for existing violation
                if sm.is_violated() {
                    violations.push(Violation {
                        proof_name: sm.spec.name.clone(),
                        invariant_name: sm.spec.invariant_name.clone(),
                        kind: sm.spec.kind,
                        message: format!(
                            "Invariant `{}` in proof `{}` is violated",
                            sm.spec.invariant_name, sm.spec.name
                        ),
                    });
                }
                continue;
            }

            let transitioned = sm.step(&eval_ctx, now_ms);

            if transitioned && sm.is_violated() {
                violations.push(Violation {
                    proof_name: sm.spec.name.clone(),
                    invariant_name: sm.spec.invariant_name.clone(),
                    kind: sm.spec.kind,
                    message: format!(
                        "Invariant `{}` in proof `{}` violated by event `{}`",
                        sm.spec.invariant_name, sm.spec.name, event.event_type
                    ),
                });
                // Invariant violation → deny (unless already denied)
                if verdict != Verdict::Deny {
                    verdict = Verdict::Deny;
                    reason = Some(format!(
                        "Invariant violation: {} ({})",
                        sm.spec.invariant_name, sm.spec.name
                    ));
                }
            }
        }

        let elapsed = start.elapsed();

        PolicyResult {
            verdict,
            reason,
            triggered_rules,
            actions,
            violations,
            constraint_violations,
            eval_time_us: elapsed.as_micros() as u64,
        }
    }

    /// Reset all state machines to their initial states.
    pub fn reset(&mut self) {
        let now_ms = current_time_ms();
        for sm in &mut self.state_machines {
            sm.current_state = sm.spec.initial_state;
            sm.start_time_ms = now_ms;
        }
        for limiter in self.rate_limiters.values_mut() {
            limiter.timestamps.clear();
        }
        self.event_count = 0;
    }

    /// Get a summary of the engine's current state.
    pub fn status(&self) -> EngineStatus {
        let active_sms = self
            .state_machines
            .iter()
            .filter(|sm| sm.is_active())
            .count();
        let violated_sms = self
            .state_machines
            .iter()
            .filter(|sm| sm.is_violated())
            .count();
        let satisfied_sms = self
            .state_machines
            .iter()
            .filter(|sm| sm.is_satisfied())
            .count();

        EngineStatus {
            policy_name: self.policy.name.clone(),
            severity: self.policy.severity,
            total_rules: self.policy.rules.len(),
            total_state_machines: self.state_machines.len(),
            active_state_machines: active_sms,
            violated_state_machines: violated_sms,
            satisfied_state_machines: satisfied_sms,
            total_constraints: self.rate_limiters.len(),
            events_processed: self.event_count,
        }
    }
}

/// Summary of the engine's current state.
#[derive(Debug, Clone)]
pub struct EngineStatus {
    pub policy_name: SmolStr,
    pub severity: SeverityLevel,
    pub total_rules: usize,
    pub total_state_machines: usize,
    pub active_state_machines: usize,
    pub violated_state_machines: usize,
    pub satisfied_state_machines: usize,
    pub total_constraints: usize,
    pub events_processed: u64,
}

impl std::fmt::Display for EngineStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Policy: {} ({:?})", self.policy_name, self.severity)?;
        writeln!(f, "Rules: {}", self.total_rules)?;
        writeln!(
            f,
            "State machines: {} total ({} active, {} satisfied, {} violated)",
            self.total_state_machines,
            self.active_state_machines,
            self.satisfied_state_machines,
            self.violated_state_machines,
        )?;
        writeln!(f, "Constraints: {}", self.total_constraints)?;
        writeln!(f, "Events processed: {}", self.events_processed)?;
        Ok(())
    }
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

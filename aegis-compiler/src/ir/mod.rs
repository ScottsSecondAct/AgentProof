use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::ast::{
    ActionVerb, BinaryOp, ConstraintKind, Literal, PredicateKind, QuantifierKind, SeverityLevel,
    UnaryOp, Verdict,
};

// ═══════════════════════════════════════════════════════════════════════
//  Top-level compiled policy
// ═══════════════════════════════════════════════════════════════════════

/// A fully compiled, flattened policy ready for runtime consumption.
///
/// All inheritance is resolved, imports inlined, and temporal invariants
/// compiled to state machines. This is the serialization boundary — the
/// Rust runtime deserializes this from the `.aegisc` bytecode format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPolicy {
    pub name: SmolStr,
    pub severity: SeverityLevel,
    pub scopes: Vec<SmolStr>,
    pub rules: Vec<CompiledRule>,
    pub constraints: Vec<CompiledConstraint>,
    pub state_machines: Vec<StateMachine>,
    pub metadata: PolicyMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub annotations: Vec<(SmolStr, SmolStr)>,
    pub source_hash: u64,
    pub compiler_version: SmolStr,
}

// ═══════════════════════════════════════════════════════════════════════
//  Compiled rules — event-triggered decision logic
// ═══════════════════════════════════════════════════════════════════════

/// A rule compiled into a condition → verdict chain.
///
/// At runtime, the verifier evaluates the condition against each
/// incoming event. If the condition matches, the verdicts and actions
/// are executed in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledRule {
    pub id: u32,
    pub on_events: Vec<SmolStr>,
    pub condition: Option<IRExpr>,
    pub verdicts: Vec<IRVerdict>,
    pub actions: Vec<IRAction>,
    pub severity: Option<SeverityLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRVerdict {
    pub verdict: Verdict,
    pub message: Option<Box<IRExpr>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRAction {
    pub verb: ActionVerb,
    pub args: Vec<(SmolStr, IRExpr)>,
}

// ═══════════════════════════════════════════════════════════════════════
//  Compiled constraints
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledConstraint {
    pub kind: ConstraintKind,
    pub target: SmolStr,
    pub limit: u64,
    pub window_millis: u64,
}

// ═══════════════════════════════════════════════════════════════════════
//  State machines — compiled temporal invariants
//
//  Each temporal invariant (always, eventually, until, etc.) compiles
//  down to an explicit state machine. The runtime maintains one instance
//  per active state machine and transitions on every relevant event.
//
//  Example:
//    invariant NoHTTP {
//        always(none(context.tool_calls, c => c.url.starts_with("http")))
//    }
//
//  Compiles to a 2-state machine:
//    State 0 (Satisfied): on every tool_call event, evaluate the
//      predicate. If predicate holds → stay in State 0.
//      If predicate fails → transition to State 1.
//    State 1 (Violated): absorbing state, invariant is broken.
//
//  For `eventually(φ) within T`:
//    State 0 (Waiting): φ not yet observed. On each event, check φ.
//      If φ → transition to State 1. If timer T expires → State 2.
//    State 1 (Satisfied): absorbing, invariant holds.
//    State 2 (Violated): deadline passed without φ.
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMachine {
    pub id: u32,
    pub name: SmolStr,
    pub invariant_name: SmolStr,
    pub kind: TemporalKind,
    pub states: Vec<State>,
    pub transitions: Vec<Transition>,
    pub initial_state: StateId,
    pub accepting_states: Vec<StateId>,
    pub violating_states: Vec<StateId>,
    pub deadline_millis: Option<u64>,
}

pub type StateId = u32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub id: StateId,
    pub label: SmolStr,
    pub kind: StateKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateKind {
    /// Normal operational state
    Active,
    /// Invariant is satisfied (absorbing for `eventually`)
    Satisfied,
    /// Invariant is violated (absorbing for `always`, `never`)
    Violated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    pub from: StateId,
    pub to: StateId,
    pub guard: TransitionGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitionGuard {
    /// Transition fires when the predicate evaluates to true
    Predicate(IRExpr),
    /// Transition fires when the predicate evaluates to false
    NegatedPredicate(IRExpr),
    /// Transition fires when the deadline expires
    Timeout,
    /// Unconditional (epsilon transition)
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemporalKind {
    /// □φ — must hold in every state
    Always,
    /// ◇φ — must hold in some future state
    Eventually,
    /// □¬φ — must never hold
    Never,
    /// φ U ψ — φ holds until ψ becomes true
    Until,
    /// Xφ — holds in the next state
    Next,
}

// ═══════════════════════════════════════════════════════════════════════
//  IR expressions — a flat, type-erased expression tree
//
//  These map closely to the AST expressions but are simplified:
//  - No lambdas (inlined at quantifier sites)
//  - No qualified names (resolved to field paths)
//  - No type annotations (types are erased after checking)
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IRExpr {
    Literal(Literal),

    /// Reference to a runtime value: event.field, context.path
    Ref(RefPath),

    /// Binary operation
    Binary {
        op: BinaryOp,
        left: Box<IRExpr>,
        right: Box<IRExpr>,
    },

    /// Unary operation
    Unary {
        op: UnaryOp,
        operand: Box<IRExpr>,
    },

    /// Built-in predicate: contains, matches, starts_with, ends_with
    Predicate {
        kind: PredicateKind,
        subject: Box<IRExpr>,
        argument: Box<IRExpr>,
    },

    /// Quantifier with inlined predicate body
    Quantifier {
        kind: QuantifierKind,
        collection: Box<IRExpr>,
        /// The parameter name bound in the predicate
        param: SmolStr,
        /// The predicate body with `param` as a free variable
        body: Box<IRExpr>,
    },

    /// Count with optional filter
    Count {
        collection: Box<IRExpr>,
        param: Option<SmolStr>,
        filter: Option<Box<IRExpr>>,
    },

    /// Function call (user-defined or built-in)
    Call {
        function: SmolStr,
        args: Vec<IRExpr>,
    },

    /// Method call on a value
    MethodCall {
        object: Box<IRExpr>,
        method: SmolStr,
        args: Vec<IRExpr>,
    },

    /// Compiled decision tree from pattern matching
    DecisionTree(Box<DecisionNode>),

    /// A list literal
    List(Vec<IRExpr>),
}

/// A reference to a runtime value, resolved from qualified names.
///
/// `event.endpoint.url` → RefPath { root: Event, fields: ["endpoint", "url"] }
/// `context.config.max_budget` → RefPath { root: Context, fields: ["config", "max_budget"] }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefPath {
    pub root: RefRoot,
    pub fields: Vec<SmolStr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefRoot {
    /// The current event being evaluated
    Event,
    /// The policy execution context (state, history, config)
    Context,
    /// A local binding (let-bound variable, function parameter)
    Local(u32),
    /// The enclosing policy's configuration
    Policy,
}

// ═══════════════════════════════════════════════════════════════════════
//  Decision trees — compiled pattern matches
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecisionNode {
    /// Test a value and branch
    Switch {
        subject: Box<IRExpr>,
        cases: Vec<DecisionCase>,
        default: Option<Box<DecisionNode>>,
    },
    /// Leaf: produce a result
    Leaf(Box<IRExpr>),
    /// Leaf: produce a verdict
    VerdictLeaf(Box<IRVerdict>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionCase {
    pub test: CaseTest,
    pub body: DecisionNode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CaseTest {
    /// Exact value match
    Literal(Literal),
    /// Type/constructor match
    Constructor(SmolStr),
    /// Guard expression (evaluated at runtime)
    Guard(IRExpr),
}

// ═══════════════════════════════════════════════════════════════════════
//  State machine builder — lowers temporal AST to explicit automata
// ═══════════════════════════════════════════════════════════════════════

pub struct StateMachineBuilder {
    pub(crate) next_id: u32,
}

impl Default for StateMachineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl StateMachineBuilder {
    pub fn new() -> Self {
        Self { next_id: 0 }
    }

    /// Compile a temporal `always(φ)` invariant to a state machine.
    ///
    /// States: Satisfied (φ holds) → Violated (φ broke)
    /// The runtime checks φ on every relevant event.
    pub fn compile_always(
        &mut self,
        name: SmolStr,
        invariant_name: SmolStr,
        predicate: IRExpr,
        deadline: Option<u64>,
    ) -> StateMachine {
        let id = self.next_id();
        StateMachine {
            id,
            name,
            invariant_name,
            kind: TemporalKind::Always,
            states: vec![
                State {
                    id: 0,
                    label: SmolStr::new("satisfied"),
                    kind: StateKind::Active,
                },
                State {
                    id: 1,
                    label: SmolStr::new("violated"),
                    kind: StateKind::Violated,
                },
            ],
            transitions: vec![
                // Stay satisfied while predicate holds
                Transition {
                    from: 0,
                    to: 0,
                    guard: TransitionGuard::Predicate(predicate.clone()),
                },
                // Violate when predicate fails
                Transition {
                    from: 0,
                    to: 1,
                    guard: TransitionGuard::NegatedPredicate(predicate),
                },
            ],
            initial_state: 0,
            accepting_states: vec![0],
            violating_states: vec![1],
            deadline_millis: deadline,
        }
    }

    /// Compile a temporal `eventually(φ) within T` invariant.
    ///
    /// States: Waiting → Satisfied (φ observed) / Violated (timeout)
    pub fn compile_eventually(
        &mut self,
        name: SmolStr,
        invariant_name: SmolStr,
        predicate: IRExpr,
        deadline_millis: Option<u64>,
    ) -> StateMachine {
        let id = self.next_id();
        let mut transitions = vec![
            // Stay waiting while predicate doesn't hold
            Transition {
                from: 0,
                to: 0,
                guard: TransitionGuard::NegatedPredicate(predicate.clone()),
            },
            // Satisfy when predicate holds
            Transition {
                from: 0,
                to: 1,
                guard: TransitionGuard::Predicate(predicate),
            },
        ];

        let mut states = vec![
            State {
                id: 0,
                label: SmolStr::new("waiting"),
                kind: StateKind::Active,
            },
            State {
                id: 1,
                label: SmolStr::new("satisfied"),
                kind: StateKind::Satisfied,
            },
        ];

        // Add timeout violation if deadline specified
        if deadline_millis.is_some() {
            states.push(State {
                id: 2,
                label: SmolStr::new("violated_timeout"),
                kind: StateKind::Violated,
            });
            transitions.push(Transition {
                from: 0,
                to: 2,
                guard: TransitionGuard::Timeout,
            });
        }

        StateMachine {
            id,
            name,
            invariant_name,
            kind: TemporalKind::Eventually,
            states,
            transitions,
            initial_state: 0,
            accepting_states: vec![1],
            violating_states: if deadline_millis.is_some() {
                vec![2]
            } else {
                vec![]
            },
            deadline_millis,
        }
    }

    /// Compile `never(φ)` — syntactic sugar for `always(!φ)`.
    pub fn compile_never(
        &mut self,
        name: SmolStr,
        invariant_name: SmolStr,
        predicate: IRExpr,
    ) -> StateMachine {
        let negated = IRExpr::Unary {
            op: UnaryOp::Not,
            operand: Box::new(predicate),
        };
        self.compile_always(name, invariant_name, negated, None)
    }

    /// Compile `φ until ψ`:
    ///   State 0 (holding): φ must hold. On ψ → State 1. On ¬φ → State 2.
    ///   State 1 (released): ψ occurred, invariant satisfied.
    ///   State 2 (violated): φ broke before ψ.
    pub fn compile_until(
        &mut self,
        name: SmolStr,
        invariant_name: SmolStr,
        hold: IRExpr,
        release: IRExpr,
    ) -> StateMachine {
        let id = self.next_id();
        StateMachine {
            id,
            name,
            invariant_name,
            kind: TemporalKind::Until,
            states: vec![
                State {
                    id: 0,
                    label: SmolStr::new("holding"),
                    kind: StateKind::Active,
                },
                State {
                    id: 1,
                    label: SmolStr::new("released"),
                    kind: StateKind::Satisfied,
                },
                State {
                    id: 2,
                    label: SmolStr::new("violated"),
                    kind: StateKind::Violated,
                },
            ],
            transitions: vec![
                // Release condition met → satisfied
                Transition {
                    from: 0,
                    to: 1,
                    guard: TransitionGuard::Predicate(release),
                },
                // Hold condition still true → stay
                Transition {
                    from: 0,
                    to: 0,
                    guard: TransitionGuard::Predicate(hold.clone()),
                },
                // Hold condition broke → violated
                Transition {
                    from: 0,
                    to: 2,
                    guard: TransitionGuard::NegatedPredicate(hold),
                },
            ],
            initial_state: 0,
            accepting_states: vec![1],
            violating_states: vec![2],
            deadline_millis: None,
        }
    }

    /// Compile a standalone `next(φ)` invariant.
    ///
    /// Checks φ on the very next event after the machine is created, then
    /// reaches a terminal state (Satisfied or Violated) and stops monitoring.
    /// This is a one-shot check — use [`compile_always_implies_next`] for
    /// repeated sequencing constraints.
    ///
    /// ```text
    /// State 0 (initial) ──Always──▶ State 1 (checking)
    ///                                  │  Predicate(φ)  ──▶ State 2 (satisfied)
    ///                                  │  NegPredicate(φ) ──▶ State 3 (violated)
    /// ```
    pub fn compile_next(
        &mut self,
        name: SmolStr,
        invariant_name: SmolStr,
        predicate: IRExpr,
    ) -> StateMachine {
        let id = self.next_id();
        StateMachine {
            id,
            name,
            invariant_name,
            kind: TemporalKind::Next,
            states: vec![
                State {
                    id: 0,
                    label: SmolStr::new("initial"),
                    kind: StateKind::Active,
                },
                State {
                    id: 1,
                    label: SmolStr::new("checking"),
                    kind: StateKind::Active,
                },
                State {
                    id: 2,
                    label: SmolStr::new("satisfied"),
                    kind: StateKind::Satisfied,
                },
                State {
                    id: 3,
                    label: SmolStr::new("violated"),
                    kind: StateKind::Violated,
                },
            ],
            transitions: vec![
                Transition {
                    from: 0,
                    to: 1,
                    guard: TransitionGuard::Always,
                },
                Transition {
                    from: 1,
                    to: 2,
                    guard: TransitionGuard::Predicate(predicate.clone()),
                },
                Transition {
                    from: 1,
                    to: 3,
                    guard: TransitionGuard::NegatedPredicate(predicate),
                },
            ],
            initial_state: 0,
            accepting_states: vec![2],
            violating_states: vec![3],
            deadline_millis: None,
        }
    }

    /// Compile `always(next(ψ))` — φ must hold at every event starting from
    /// the second one.
    ///
    /// Semantically equivalent to `always(ψ)` with the first event skipped.
    /// Unlike the standalone `next(ψ)`, this machine loops back and keeps
    /// enforcing ψ on every subsequent event.
    ///
    /// ```text
    /// State 0 (initial) ──Always──▶ State 1 (checking)
    ///                                  │  Predicate(ψ) ──▶ self-loop
    ///                                  │  NegPredicate(ψ) ──▶ State 2 (violated)
    /// ```
    pub fn compile_always_next(
        &mut self,
        name: SmolStr,
        invariant_name: SmolStr,
        response: IRExpr,
    ) -> StateMachine {
        let id = self.next_id();
        StateMachine {
            id,
            name,
            invariant_name,
            kind: TemporalKind::Next,
            states: vec![
                State {
                    id: 0,
                    label: SmolStr::new("initial"),
                    kind: StateKind::Active,
                },
                State {
                    id: 1,
                    label: SmolStr::new("checking"),
                    kind: StateKind::Active,
                },
                State {
                    id: 2,
                    label: SmolStr::new("violated"),
                    kind: StateKind::Violated,
                },
            ],
            transitions: vec![
                // Skip the first event; begin checking from the second.
                Transition {
                    from: 0,
                    to: 1,
                    guard: TransitionGuard::Always,
                },
                // ψ holds — keep checking.
                Transition {
                    from: 1,
                    to: 1,
                    guard: TransitionGuard::Predicate(response.clone()),
                },
                // ψ fails — violated.
                Transition {
                    from: 1,
                    to: 2,
                    guard: TransitionGuard::NegatedPredicate(response),
                },
            ],
            initial_state: 0,
            accepting_states: vec![1],
            violating_states: vec![2],
            deadline_millis: None,
        }
    }

    /// Compile `always(trigger implies next(ψ))` — whenever `trigger` holds,
    /// the very next event must satisfy `ψ`.
    ///
    /// This is the primary use-case for `next()`: expressing sequencing
    /// constraints such as "after every login attempt, the next event must be
    /// an MFA verification."  The machine is reset to idle after each
    /// successful response, so the constraint applies to every occurrence of
    /// the trigger, not just the first.
    ///
    /// ```text
    /// State 0 (idle) ──NegPred(trigger)──▶ self-loop
    ///               ──Predicate(trigger)──▶ State 1 (armed)
    ///
    /// State 1 (armed) ──Predicate(ψ)──▶ State 0  (response ok, reset)
    ///                 ──NegPredicate(ψ)──▶ State 2 (violated)
    /// ```
    pub fn compile_always_implies_next(
        &mut self,
        name: SmolStr,
        invariant_name: SmolStr,
        trigger: IRExpr,
        response: IRExpr,
    ) -> StateMachine {
        let id = self.next_id();
        StateMachine {
            id,
            name,
            invariant_name,
            kind: TemporalKind::Next,
            states: vec![
                State {
                    id: 0,
                    label: SmolStr::new("idle"),
                    kind: StateKind::Active,
                },
                State {
                    id: 1,
                    label: SmolStr::new("armed"),
                    kind: StateKind::Active,
                },
                State {
                    id: 2,
                    label: SmolStr::new("violated"),
                    kind: StateKind::Violated,
                },
            ],
            transitions: vec![
                // Idle: no trigger — stay idle.
                Transition {
                    from: 0,
                    to: 0,
                    guard: TransitionGuard::NegatedPredicate(trigger.clone()),
                },
                // Idle: trigger fired — arm the machine.
                Transition {
                    from: 0,
                    to: 1,
                    guard: TransitionGuard::Predicate(trigger),
                },
                // Armed: response satisfied — reset to idle.
                Transition {
                    from: 1,
                    to: 0,
                    guard: TransitionGuard::Predicate(response.clone()),
                },
                // Armed: response failed — violated.
                Transition {
                    from: 1,
                    to: 2,
                    guard: TransitionGuard::NegatedPredicate(response),
                },
            ],
            initial_state: 0,
            accepting_states: vec![0],
            violating_states: vec![2],
            deadline_millis: None,
        }
    }

    fn next_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Literal, UnaryOp};
    use smol_str::SmolStr;

    fn lit_true() -> IRExpr {
        IRExpr::Literal(Literal::Bool(true))
    }

    fn lit_false() -> IRExpr {
        IRExpr::Literal(Literal::Bool(false))
    }

    fn name(s: &str) -> SmolStr {
        SmolStr::new(s)
    }

    // ── compile_always ───────────────────────────────────────────────────

    #[test]
    fn always_has_two_states() {
        let sm =
            StateMachineBuilder::new().compile_always(name("m"), name("inv"), lit_true(), None);
        assert_eq!(sm.states.len(), 2);
    }

    #[test]
    fn always_state_0_is_active() {
        let sm =
            StateMachineBuilder::new().compile_always(name("m"), name("inv"), lit_true(), None);
        assert_eq!(sm.states[0].kind, StateKind::Active);
        assert_eq!(sm.states[0].label.as_str(), "satisfied");
    }

    #[test]
    fn always_state_1_is_violated() {
        let sm =
            StateMachineBuilder::new().compile_always(name("m"), name("inv"), lit_true(), None);
        assert_eq!(sm.states[1].kind, StateKind::Violated);
        assert_eq!(sm.states[1].label.as_str(), "violated");
    }

    #[test]
    fn always_initial_state_is_0() {
        let sm =
            StateMachineBuilder::new().compile_always(name("m"), name("inv"), lit_true(), None);
        assert_eq!(sm.initial_state, 0);
    }

    #[test]
    fn always_accepting_states_is_0() {
        let sm =
            StateMachineBuilder::new().compile_always(name("m"), name("inv"), lit_true(), None);
        assert_eq!(sm.accepting_states, vec![0]);
    }

    #[test]
    fn always_violating_states_is_1() {
        let sm =
            StateMachineBuilder::new().compile_always(name("m"), name("inv"), lit_true(), None);
        assert_eq!(sm.violating_states, vec![1]);
    }

    #[test]
    fn always_kind_is_always() {
        let sm =
            StateMachineBuilder::new().compile_always(name("m"), name("inv"), lit_true(), None);
        assert_eq!(sm.kind, TemporalKind::Always);
    }

    #[test]
    fn always_has_two_transitions() {
        let sm =
            StateMachineBuilder::new().compile_always(name("m"), name("inv"), lit_true(), None);
        assert_eq!(sm.transitions.len(), 2);
    }

    #[test]
    fn always_first_transition_is_self_loop_on_predicate() {
        let sm =
            StateMachineBuilder::new().compile_always(name("m"), name("inv"), lit_true(), None);
        let t = &sm.transitions[0];
        assert_eq!(t.from, 0);
        assert_eq!(t.to, 0);
        assert!(matches!(t.guard, TransitionGuard::Predicate(_)));
    }

    #[test]
    fn always_second_transition_goes_to_violated_on_negated() {
        let sm =
            StateMachineBuilder::new().compile_always(name("m"), name("inv"), lit_true(), None);
        let t = &sm.transitions[1];
        assert_eq!(t.from, 0);
        assert_eq!(t.to, 1);
        assert!(matches!(t.guard, TransitionGuard::NegatedPredicate(_)));
    }

    #[test]
    fn always_with_deadline_stores_millis() {
        let sm = StateMachineBuilder::new().compile_always(
            name("m"),
            name("inv"),
            lit_true(),
            Some(5_000),
        );
        assert_eq!(sm.deadline_millis, Some(5_000));
    }

    #[test]
    fn always_without_deadline_is_none() {
        let sm =
            StateMachineBuilder::new().compile_always(name("m"), name("inv"), lit_true(), None);
        assert_eq!(sm.deadline_millis, None);
    }

    #[test]
    fn always_stores_name_and_invariant_name() {
        let sm = StateMachineBuilder::new().compile_always(
            name("MyMachine"),
            name("MyInvariant"),
            lit_true(),
            None,
        );
        assert_eq!(sm.name.as_str(), "MyMachine");
        assert_eq!(sm.invariant_name.as_str(), "MyInvariant");
    }

    // ── compile_eventually ───────────────────────────────────────────────

    #[test]
    fn eventually_without_deadline_has_two_states() {
        let sm =
            StateMachineBuilder::new().compile_eventually(name("m"), name("inv"), lit_true(), None);
        assert_eq!(sm.states.len(), 2);
    }

    #[test]
    fn eventually_with_deadline_has_three_states() {
        let sm = StateMachineBuilder::new().compile_eventually(
            name("m"),
            name("inv"),
            lit_true(),
            Some(60_000),
        );
        assert_eq!(sm.states.len(), 3);
    }

    #[test]
    fn eventually_state_0_is_waiting() {
        let sm =
            StateMachineBuilder::new().compile_eventually(name("m"), name("inv"), lit_true(), None);
        assert_eq!(sm.states[0].label.as_str(), "waiting");
        assert_eq!(sm.states[0].kind, StateKind::Active);
    }

    #[test]
    fn eventually_state_1_is_satisfied() {
        let sm =
            StateMachineBuilder::new().compile_eventually(name("m"), name("inv"), lit_true(), None);
        assert_eq!(sm.states[1].kind, StateKind::Satisfied);
    }

    #[test]
    fn eventually_with_deadline_state_2_is_violated() {
        let sm = StateMachineBuilder::new().compile_eventually(
            name("m"),
            name("inv"),
            lit_true(),
            Some(1_000),
        );
        assert_eq!(sm.states[2].kind, StateKind::Violated);
        assert_eq!(sm.states[2].label.as_str(), "violated_timeout");
    }

    #[test]
    fn eventually_accepting_state_is_1() {
        let sm =
            StateMachineBuilder::new().compile_eventually(name("m"), name("inv"), lit_true(), None);
        assert_eq!(sm.accepting_states, vec![1]);
    }

    #[test]
    fn eventually_without_deadline_has_no_violating_states() {
        let sm =
            StateMachineBuilder::new().compile_eventually(name("m"), name("inv"), lit_true(), None);
        assert!(sm.violating_states.is_empty());
    }

    #[test]
    fn eventually_with_deadline_violating_state_is_2() {
        let sm = StateMachineBuilder::new().compile_eventually(
            name("m"),
            name("inv"),
            lit_true(),
            Some(1_000),
        );
        assert_eq!(sm.violating_states, vec![2]);
    }

    #[test]
    fn eventually_with_deadline_has_timeout_transition() {
        let sm = StateMachineBuilder::new().compile_eventually(
            name("m"),
            name("inv"),
            lit_true(),
            Some(1_000),
        );
        let has_timeout = sm
            .transitions
            .iter()
            .any(|t| matches!(t.guard, TransitionGuard::Timeout));
        assert!(has_timeout);
    }

    #[test]
    fn eventually_timeout_transition_goes_from_0_to_2() {
        let sm = StateMachineBuilder::new().compile_eventually(
            name("m"),
            name("inv"),
            lit_true(),
            Some(1_000),
        );
        let timeout_t = sm
            .transitions
            .iter()
            .find(|t| matches!(t.guard, TransitionGuard::Timeout))
            .unwrap();
        assert_eq!(timeout_t.from, 0);
        assert_eq!(timeout_t.to, 2);
    }

    #[test]
    fn eventually_kind_is_eventually() {
        let sm =
            StateMachineBuilder::new().compile_eventually(name("m"), name("inv"), lit_true(), None);
        assert_eq!(sm.kind, TemporalKind::Eventually);
    }

    #[test]
    fn eventually_without_deadline_has_two_transitions() {
        let sm =
            StateMachineBuilder::new().compile_eventually(name("m"), name("inv"), lit_true(), None);
        assert_eq!(sm.transitions.len(), 2);
    }

    #[test]
    fn eventually_with_deadline_has_three_transitions() {
        let sm = StateMachineBuilder::new().compile_eventually(
            name("m"),
            name("inv"),
            lit_true(),
            Some(1_000),
        );
        assert_eq!(sm.transitions.len(), 3);
    }

    // ── compile_never ────────────────────────────────────────────────────

    #[test]
    fn never_delegates_to_always_with_negation() {
        let sm = StateMachineBuilder::new().compile_never(name("m"), name("inv"), lit_true());
        // never(φ) = always(!φ): same structural shape as always
        assert_eq!(sm.kind, TemporalKind::Always);
        assert_eq!(sm.states.len(), 2);
        assert_eq!(sm.violating_states, vec![1]);
    }

    #[test]
    fn never_predicate_is_wrapped_in_unary_not() {
        let sm = StateMachineBuilder::new().compile_never(name("m"), name("inv"), lit_true());
        // The self-loop transition should guard on a negated predicate (¬φ = !true),
        // meaning the inner predicate fed to compile_always is Unary::Not(φ).
        let self_loop = &sm.transitions[0]; // Predicate guard = !φ stays satisfied
        if let TransitionGuard::Predicate(IRExpr::Unary { op, .. }) = &self_loop.guard {
            assert_eq!(*op, UnaryOp::Not);
        } else {
            panic!(
                "expected Predicate(Unary {{ Not, .. }}), got {:?}",
                self_loop.guard
            );
        }
    }

    #[test]
    fn never_has_no_deadline() {
        let sm = StateMachineBuilder::new().compile_never(name("m"), name("inv"), lit_true());
        assert_eq!(sm.deadline_millis, None);
    }

    // ── compile_until ────────────────────────────────────────────────────

    #[test]
    fn until_has_three_states() {
        let sm = StateMachineBuilder::new().compile_until(
            name("m"),
            name("inv"),
            lit_true(),
            lit_false(),
        );
        assert_eq!(sm.states.len(), 3);
    }

    #[test]
    fn until_state_0_is_holding() {
        let sm = StateMachineBuilder::new().compile_until(
            name("m"),
            name("inv"),
            lit_true(),
            lit_false(),
        );
        assert_eq!(sm.states[0].label.as_str(), "holding");
        assert_eq!(sm.states[0].kind, StateKind::Active);
    }

    #[test]
    fn until_state_1_is_released_satisfied() {
        let sm = StateMachineBuilder::new().compile_until(
            name("m"),
            name("inv"),
            lit_true(),
            lit_false(),
        );
        assert_eq!(sm.states[1].label.as_str(), "released");
        assert_eq!(sm.states[1].kind, StateKind::Satisfied);
    }

    #[test]
    fn until_state_2_is_violated() {
        let sm = StateMachineBuilder::new().compile_until(
            name("m"),
            name("inv"),
            lit_true(),
            lit_false(),
        );
        assert_eq!(sm.states[2].label.as_str(), "violated");
        assert_eq!(sm.states[2].kind, StateKind::Violated);
    }

    #[test]
    fn until_has_three_transitions() {
        let sm = StateMachineBuilder::new().compile_until(
            name("m"),
            name("inv"),
            lit_true(),
            lit_false(),
        );
        assert_eq!(sm.transitions.len(), 3);
    }

    #[test]
    fn until_release_transition_goes_0_to_1() {
        let sm = StateMachineBuilder::new().compile_until(
            name("m"),
            name("inv"),
            lit_true(),
            lit_false(),
        );
        let t = &sm.transitions[0]; // release: ψ holds → satisfied
        assert_eq!(t.from, 0);
        assert_eq!(t.to, 1);
        assert!(matches!(t.guard, TransitionGuard::Predicate(_)));
    }

    #[test]
    fn until_hold_transition_is_self_loop_0_to_0() {
        let sm = StateMachineBuilder::new().compile_until(
            name("m"),
            name("inv"),
            lit_true(),
            lit_false(),
        );
        let t = &sm.transitions[1]; // hold still true → stay
        assert_eq!(t.from, 0);
        assert_eq!(t.to, 0);
        assert!(matches!(t.guard, TransitionGuard::Predicate(_)));
    }

    #[test]
    fn until_hold_failure_goes_0_to_2() {
        let sm = StateMachineBuilder::new().compile_until(
            name("m"),
            name("inv"),
            lit_true(),
            lit_false(),
        );
        let t = &sm.transitions[2]; // hold broke → violated
        assert_eq!(t.from, 0);
        assert_eq!(t.to, 2);
        assert!(matches!(t.guard, TransitionGuard::NegatedPredicate(_)));
    }

    #[test]
    fn until_accepting_state_is_1() {
        let sm = StateMachineBuilder::new().compile_until(
            name("m"),
            name("inv"),
            lit_true(),
            lit_false(),
        );
        assert_eq!(sm.accepting_states, vec![1]);
    }

    #[test]
    fn until_violating_state_is_2() {
        let sm = StateMachineBuilder::new().compile_until(
            name("m"),
            name("inv"),
            lit_true(),
            lit_false(),
        );
        assert_eq!(sm.violating_states, vec![2]);
    }

    #[test]
    fn until_kind_is_until() {
        let sm = StateMachineBuilder::new().compile_until(
            name("m"),
            name("inv"),
            lit_true(),
            lit_false(),
        );
        assert_eq!(sm.kind, TemporalKind::Until);
    }

    #[test]
    fn until_has_no_deadline() {
        let sm = StateMachineBuilder::new().compile_until(
            name("m"),
            name("inv"),
            lit_true(),
            lit_false(),
        );
        assert_eq!(sm.deadline_millis, None);
    }

    // ── Sequential IDs ───────────────────────────────────────────────────

    #[test]
    fn sequential_build_assigns_ids_starting_at_0() {
        let mut b = StateMachineBuilder::new();
        let sm1 = b.compile_always(name("m1"), name("i1"), lit_true(), None);
        let sm2 = b.compile_always(name("m2"), name("i2"), lit_true(), None);
        assert_eq!(sm1.id, 0);
        assert_eq!(sm2.id, 1);
    }

    #[test]
    fn ids_are_unique_across_different_compile_methods() {
        let mut b = StateMachineBuilder::new();
        let sm1 = b.compile_always(name("m1"), name("i1"), lit_true(), None);
        let sm2 = b.compile_eventually(name("m2"), name("i2"), lit_true(), None);
        let sm3 = b.compile_never(name("m3"), name("i3"), lit_true());
        let sm4 = b.compile_until(name("m4"), name("i4"), lit_true(), lit_false());
        let ids = [sm1.id, sm2.id, sm3.id, sm4.id];
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 4);
    }

    #[test]
    fn fresh_builder_starts_id_at_0() {
        let mut b = StateMachineBuilder::new();
        let sm = b.compile_always(name("m"), name("i"), lit_true(), None);
        assert_eq!(sm.id, 0);
    }

    // ── compile_next ─────────────────────────────────────────────────────

    #[test]
    fn next_has_four_states() {
        let sm = StateMachineBuilder::new().compile_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.states.len(), 4);
    }

    #[test]
    fn next_kind_is_next() {
        let sm = StateMachineBuilder::new().compile_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.kind, TemporalKind::Next);
    }

    #[test]
    fn next_initial_state_is_0() {
        let sm = StateMachineBuilder::new().compile_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.initial_state, 0);
    }

    #[test]
    fn next_state_0_is_initial_active() {
        let sm = StateMachineBuilder::new().compile_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.states[0].label.as_str(), "initial");
        assert_eq!(sm.states[0].kind, StateKind::Active);
    }

    #[test]
    fn next_state_1_is_checking_active() {
        let sm = StateMachineBuilder::new().compile_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.states[1].label.as_str(), "checking");
        assert_eq!(sm.states[1].kind, StateKind::Active);
    }

    #[test]
    fn next_state_2_is_satisfied() {
        let sm = StateMachineBuilder::new().compile_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.states[2].kind, StateKind::Satisfied);
        assert_eq!(sm.states[2].label.as_str(), "satisfied");
    }

    #[test]
    fn next_state_3_is_violated() {
        let sm = StateMachineBuilder::new().compile_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.states[3].kind, StateKind::Violated);
        assert_eq!(sm.states[3].label.as_str(), "violated");
    }

    #[test]
    fn next_accepting_states_is_2() {
        let sm = StateMachineBuilder::new().compile_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.accepting_states, vec![2]);
    }

    #[test]
    fn next_violating_states_is_3() {
        let sm = StateMachineBuilder::new().compile_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.violating_states, vec![3]);
    }

    #[test]
    fn next_has_three_transitions() {
        let sm = StateMachineBuilder::new().compile_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.transitions.len(), 3);
    }

    #[test]
    fn next_first_transition_is_always_0_to_1() {
        let sm = StateMachineBuilder::new().compile_next(name("m"), name("inv"), lit_true());
        let t = &sm.transitions[0];
        assert_eq!(t.from, 0);
        assert_eq!(t.to, 1);
        assert!(matches!(t.guard, TransitionGuard::Always));
    }

    #[test]
    fn next_second_transition_predicate_1_to_2() {
        let sm = StateMachineBuilder::new().compile_next(name("m"), name("inv"), lit_true());
        let t = &sm.transitions[1];
        assert_eq!(t.from, 1);
        assert_eq!(t.to, 2);
        assert!(matches!(t.guard, TransitionGuard::Predicate(_)));
    }

    #[test]
    fn next_third_transition_negated_predicate_1_to_3() {
        let sm = StateMachineBuilder::new().compile_next(name("m"), name("inv"), lit_true());
        let t = &sm.transitions[2];
        assert_eq!(t.from, 1);
        assert_eq!(t.to, 3);
        assert!(matches!(t.guard, TransitionGuard::NegatedPredicate(_)));
    }

    #[test]
    fn next_has_no_deadline() {
        let sm = StateMachineBuilder::new().compile_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.deadline_millis, None);
    }

    // ── compile_always_next ──────────────────────────────────────────────

    #[test]
    fn always_next_has_three_states() {
        let sm = StateMachineBuilder::new().compile_always_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.states.len(), 3);
    }

    #[test]
    fn always_next_kind_is_next() {
        let sm = StateMachineBuilder::new().compile_always_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.kind, TemporalKind::Next);
    }

    #[test]
    fn always_next_initial_state_is_0() {
        let sm = StateMachineBuilder::new().compile_always_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.initial_state, 0);
    }

    #[test]
    fn always_next_state_0_is_initial() {
        let sm = StateMachineBuilder::new().compile_always_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.states[0].label.as_str(), "initial");
        assert_eq!(sm.states[0].kind, StateKind::Active);
    }

    #[test]
    fn always_next_state_1_is_checking() {
        let sm = StateMachineBuilder::new().compile_always_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.states[1].label.as_str(), "checking");
        assert_eq!(sm.states[1].kind, StateKind::Active);
    }

    #[test]
    fn always_next_state_2_is_violated() {
        let sm = StateMachineBuilder::new().compile_always_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.states[2].kind, StateKind::Violated);
        assert_eq!(sm.states[2].label.as_str(), "violated");
    }

    #[test]
    fn always_next_accepting_states_is_1() {
        let sm = StateMachineBuilder::new().compile_always_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.accepting_states, vec![1]);
    }

    #[test]
    fn always_next_violating_states_is_2() {
        let sm = StateMachineBuilder::new().compile_always_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.violating_states, vec![2]);
    }

    #[test]
    fn always_next_has_three_transitions() {
        let sm = StateMachineBuilder::new().compile_always_next(name("m"), name("inv"), lit_true());
        assert_eq!(sm.transitions.len(), 3);
    }

    #[test]
    fn always_next_first_transition_is_always_0_to_1() {
        let sm = StateMachineBuilder::new().compile_always_next(name("m"), name("inv"), lit_true());
        let t = &sm.transitions[0];
        assert_eq!(t.from, 0);
        assert_eq!(t.to, 1);
        assert!(matches!(t.guard, TransitionGuard::Always));
    }

    #[test]
    fn always_next_self_loop_is_1_to_1_on_predicate() {
        let sm = StateMachineBuilder::new().compile_always_next(name("m"), name("inv"), lit_true());
        let t = &sm.transitions[1];
        assert_eq!(t.from, 1);
        assert_eq!(t.to, 1);
        assert!(matches!(t.guard, TransitionGuard::Predicate(_)));
    }

    #[test]
    fn always_next_violation_transition_is_1_to_2() {
        let sm = StateMachineBuilder::new().compile_always_next(name("m"), name("inv"), lit_true());
        let t = &sm.transitions[2];
        assert_eq!(t.from, 1);
        assert_eq!(t.to, 2);
        assert!(matches!(t.guard, TransitionGuard::NegatedPredicate(_)));
    }

    // ── compile_always_implies_next ──────────────────────────────────────

    #[test]
    fn always_implies_next_has_three_states() {
        let sm = StateMachineBuilder::new().compile_always_implies_next(
            name("m"), name("inv"), lit_true(), lit_false(),
        );
        assert_eq!(sm.states.len(), 3);
    }

    #[test]
    fn always_implies_next_kind_is_next() {
        let sm = StateMachineBuilder::new().compile_always_implies_next(
            name("m"), name("inv"), lit_true(), lit_false(),
        );
        assert_eq!(sm.kind, TemporalKind::Next);
    }

    #[test]
    fn always_implies_next_initial_state_is_0() {
        let sm = StateMachineBuilder::new().compile_always_implies_next(
            name("m"), name("inv"), lit_true(), lit_false(),
        );
        assert_eq!(sm.initial_state, 0);
    }

    #[test]
    fn always_implies_next_state_0_is_idle() {
        let sm = StateMachineBuilder::new().compile_always_implies_next(
            name("m"), name("inv"), lit_true(), lit_false(),
        );
        assert_eq!(sm.states[0].label.as_str(), "idle");
        assert_eq!(sm.states[0].kind, StateKind::Active);
    }

    #[test]
    fn always_implies_next_state_1_is_armed() {
        let sm = StateMachineBuilder::new().compile_always_implies_next(
            name("m"), name("inv"), lit_true(), lit_false(),
        );
        assert_eq!(sm.states[1].label.as_str(), "armed");
        assert_eq!(sm.states[1].kind, StateKind::Active);
    }

    #[test]
    fn always_implies_next_state_2_is_violated() {
        let sm = StateMachineBuilder::new().compile_always_implies_next(
            name("m"), name("inv"), lit_true(), lit_false(),
        );
        assert_eq!(sm.states[2].kind, StateKind::Violated);
        assert_eq!(sm.states[2].label.as_str(), "violated");
    }

    #[test]
    fn always_implies_next_accepting_states_is_0() {
        let sm = StateMachineBuilder::new().compile_always_implies_next(
            name("m"), name("inv"), lit_true(), lit_false(),
        );
        assert_eq!(sm.accepting_states, vec![0]);
    }

    #[test]
    fn always_implies_next_violating_states_is_2() {
        let sm = StateMachineBuilder::new().compile_always_implies_next(
            name("m"), name("inv"), lit_true(), lit_false(),
        );
        assert_eq!(sm.violating_states, vec![2]);
    }

    #[test]
    fn always_implies_next_has_four_transitions() {
        let sm = StateMachineBuilder::new().compile_always_implies_next(
            name("m"), name("inv"), lit_true(), lit_false(),
        );
        assert_eq!(sm.transitions.len(), 4);
    }

    #[test]
    fn always_implies_next_idle_self_loop_on_negated_trigger() {
        let sm = StateMachineBuilder::new().compile_always_implies_next(
            name("m"), name("inv"), lit_true(), lit_false(),
        );
        let t = &sm.transitions[0]; // no trigger → stay idle
        assert_eq!(t.from, 0);
        assert_eq!(t.to, 0);
        assert!(matches!(t.guard, TransitionGuard::NegatedPredicate(_)));
    }

    #[test]
    fn always_implies_next_armed_on_trigger() {
        let sm = StateMachineBuilder::new().compile_always_implies_next(
            name("m"), name("inv"), lit_true(), lit_false(),
        );
        let t = &sm.transitions[1]; // trigger → arm
        assert_eq!(t.from, 0);
        assert_eq!(t.to, 1);
        assert!(matches!(t.guard, TransitionGuard::Predicate(_)));
    }

    #[test]
    fn always_implies_next_reset_to_idle_on_response() {
        let sm = StateMachineBuilder::new().compile_always_implies_next(
            name("m"), name("inv"), lit_true(), lit_false(),
        );
        let t = &sm.transitions[2]; // response ok → reset
        assert_eq!(t.from, 1);
        assert_eq!(t.to, 0);
        assert!(matches!(t.guard, TransitionGuard::Predicate(_)));
    }

    #[test]
    fn always_implies_next_violated_on_wrong_response() {
        let sm = StateMachineBuilder::new().compile_always_implies_next(
            name("m"), name("inv"), lit_true(), lit_false(),
        );
        let t = &sm.transitions[3]; // bad response → violated
        assert_eq!(t.from, 1);
        assert_eq!(t.to, 2);
        assert!(matches!(t.guard, TransitionGuard::NegatedPredicate(_)));
    }

    #[test]
    fn next_methods_produce_sequential_ids() {
        let mut b = StateMachineBuilder::new();
        let sm1 = b.compile_next(name("m1"), name("i1"), lit_true());
        let sm2 = b.compile_always_next(name("m2"), name("i2"), lit_true());
        let sm3 = b.compile_always_implies_next(name("m3"), name("i3"), lit_true(), lit_false());
        assert_eq!(sm1.id, 0);
        assert_eq!(sm2.id, 1);
        assert_eq!(sm3.id, 2);
    }
}

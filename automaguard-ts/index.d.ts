/**
 * AutomaGuard TypeScript SDK
 *
 * Compile-time policy enforcement for Node.js AI agents via a Rust native
 * addon (napi-rs). Policies are compiled to `.aegisc` bytecode by the
 * `aegisc` compiler; this SDK loads the bytecode and evaluates events in
 * under 1 ms with no policy parsing at runtime.
 *
 * @example
 * ```typescript
 * import { PolicyEngine, EnforcementError } from 'automaguard';
 *
 * const engine = PolicyEngine.fromFile('guard.aegisc');
 * const result = engine.evaluate('tool_call', { tool_name: 'send_email' });
 * if (result.verdict === 'deny') throw new EnforcementError(result);
 * ```
 */
interface NativePolicyEngine {
    evaluate(eventType: string, fields?: unknown): PolicyResult;
    setContext(key: string, value: unknown): void;
    setConfig(key: string, value: unknown): void;
    reset(): void;
    status(): EngineStatus;
    readonly policyName: string;
    readonly eventCount: number;
}
interface NativeBinding {
    PolicyEngine: {
        fromFile(path: string): NativePolicyEngine;
        fromBytes(data: Buffer): NativePolicyEngine;
    };
}
/**
 * Override the native binding — for unit testing only.
 * @internal
 */
export declare function __setNativeBinding(binding: NativeBinding): void;
/** An invariant violation detected during event evaluation. */
export interface Violation {
    /** Name of the proof block that owns this invariant. */
    proof: string;
    /** Name of the violated invariant. */
    invariant: string;
    /** Temporal operator kind (`Always`, `Eventually`, `Until`, `Never`). */
    kind: string;
    /** Human-readable violation message. */
    message: string;
}
/** A rate-limit or quota constraint violation. */
export interface ConstraintViolation {
    /** Constraint kind (`RateLimit`, `Quota`). */
    kind: string;
    /** The event type the constraint applies to. */
    target: string;
    /** Configured event limit. */
    limit: number;
    /** Current count within the sliding window. */
    current: number;
    /** Sliding window size in milliseconds. */
    window_ms: number;
}
/** An action emitted by a matched rule. */
export interface RuleAction {
    /** The action verb (e.g. `"log"`, `"notify"`, `"escalate"`). */
    verb: string;
    /**
     * JSON-serialised action arguments.
     * Use `JSON.parse(action.args_json)` to access the structured value.
     */
    args_json: string;
}
/** The four possible outcomes of policy evaluation. */
export type Verdict = 'allow' | 'deny' | 'audit' | 'redact';
/** The full result of evaluating one agent event against the loaded policy. */
export interface PolicyResult {
    /** Final verdict. */
    verdict: Verdict;
    /** Human-readable denial reason, or `null` if none. */
    reason: string | null;
    /** IDs of the rules that matched this event. */
    triggered_rules: number[];
    /** Invariant violations detected during evaluation. */
    violations: Violation[];
    /** Rate-limit or quota violations. */
    constraint_violations: ConstraintViolation[];
    /** Actions emitted by matched rules. */
    actions: RuleAction[];
    /** Evaluation latency in microseconds. */
    latency_us: number;
}
/** A snapshot of the engine's current operational state. */
export interface EngineStatus {
    policy_name: string;
    severity: string;
    total_rules: number;
    total_state_machines: number;
    active_state_machines: number;
    violated_state_machines: number;
    satisfied_state_machines: number;
    total_constraints: number;
    events_processed: number;
}
/**
 * Thrown when a policy returns a `deny` verdict.
 *
 * The full `PolicyResult` is attached so callers can inspect triggered rules,
 * violations, and the denial reason.
 */
export declare class EnforcementError extends Error {
    /** The full policy evaluation result that triggered this error. */
    readonly result: PolicyResult;
    constructor(result: PolicyResult);
}
/**
 * AutomaGuard policy engine.
 *
 * Load a compiled `.aegisc` policy **once** at agent startup, then call
 * `evaluate()` on each agent event. Evaluation is synchronous and typically
 * completes in under 1 ms. The engine is safe to share across async calls —
 * internal state is protected by a Mutex on the Rust side.
 *
 * @example
 * ```typescript
 * const engine = PolicyEngine.fromFile('guard.aegisc');
 *
 * // In your tool-calling loop:
 * const result = engine.evaluate('tool_call', {
 *   tool_name: 'send_email',
 *   arguments: { to: 'user@example.com' },
 * });
 * if (result.verdict === 'deny') throw new EnforcementError(result);
 * ```
 */
export declare class PolicyEngine {
    private readonly _native;
    private constructor();
    /**
     * Load a policy engine from a compiled `.aegisc` file path.
     *
     * @param path - Absolute or relative path to the `.aegisc` file.
     * @throws If the file does not exist or is not a valid compiled policy.
     */
    static fromFile(path: string): PolicyEngine;
    /**
     * Load a policy engine from raw `.aegisc` bytes (e.g. embedded via webpack).
     *
     * @param data - A Node.js `Buffer` containing the compiled policy bytes.
     * @throws If the buffer is not a valid compiled policy.
     */
    static fromBytes(data: Buffer): PolicyEngine;
    /**
     * Evaluate a single agent event against the loaded policy.
     *
     * @param eventType - Event type string (e.g. `"tool_call"`, `"data_access"`).
     * @param fields    - Arbitrary event fields. Omit or pass `undefined` for
     *                    events with no fields.
     * @returns A {@link PolicyResult} with the verdict, triggered rules, and any
     *          violations.
     */
    evaluate(eventType: string, fields?: Record<string, unknown>): PolicyResult;
    /**
     * Set a persistent context value accessible in policy expressions as
     * `context.<key>`. Values accumulate across events for the lifetime of
     * this engine instance.
     */
    setContext(key: string, value: unknown): void;
    /**
     * Set a policy configuration value accessible in policy expressions as
     * `config.<key>`.
     */
    setConfig(key: string, value: unknown): void;
    /** The policy name declared in the `.aegisc` file (`policy <Name> { }`). */
    get policyName(): string;
    /** Total events evaluated since creation or the last `reset()`. */
    get eventCount(): number;
    /**
     * Reset all state machines and rate-limit counters to their initial states.
     *
     * Call this at the start of a new agent session to isolate per-session
     * temporal invariants and rate limits.
     */
    reset(): void;
    /** Return a snapshot of the engine's current operational state. */
    status(): EngineStatus;
}
export {};
//# sourceMappingURL=index.d.ts.map
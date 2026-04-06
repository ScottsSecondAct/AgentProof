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

// ── Native binary loader ──────────────────────────────────────────────────────

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

// Lazily initialised so that requiring this module in test environments does
// not immediately try to load a platform binary.
let _nativeBinding: NativeBinding | null = null;

function getNative(): NativeBinding {
  if (_nativeBinding) return _nativeBinding;
  _nativeBinding = loadNative();
  return _nativeBinding;
}

function loadNative(): NativeBinding {
  const platformKey = `${process.platform}-${process.arch}`;

  const packageNames: Record<string, string> = {
    'linux-x64': 'automaguard-linux-x64-gnu',
    'darwin-arm64': 'automaguard-darwin-arm64',
    'darwin-x64': 'automaguard-darwin-x64',
    'win32-x64': 'automaguard-win32-x64-msvc',
  };

  const fileNames: Record<string, string> = {
    'linux-x64': 'automaguard-ts.linux-x64-gnu.node',
    'darwin-arm64': 'automaguard-ts.darwin-arm64.node',
    'darwin-x64': 'automaguard-ts.darwin-x64.node',
    'win32-x64': 'automaguard-ts.win32-x64-msvc.node',
  };

  if (!(platformKey in packageNames)) {
    throw new Error(
      `AutomaGuard: unsupported platform "${platformKey}". ` +
        `Supported: ${Object.keys(packageNames).join(', ')}`
    );
  }

  // 1. Try the prebuilt npm optional-dependency package.
  try {
    return require(packageNames[platformKey]) as NativeBinding;
  } catch {
    // fall through
  }

  // 2. Fall back to a local build (development / CI).
  const localFile = `${__dirname}/../${fileNames[platformKey]}`;
  try {
    return require(localFile) as NativeBinding;
  } catch (err) {
    throw new Error(
      `AutomaGuard: failed to load native binary for "${platformKey}". ` +
        `Install the prebuilt package "${packageNames[platformKey]}", or ` +
        `run \`npm run build\` to compile from source. ` +
        `Original error: ${err}`
    );
  }
}

/**
 * Override the native binding — for unit testing only.
 * @internal
 */
export function __setNativeBinding(binding: NativeBinding): void {
  _nativeBinding = binding;
}

// ── Public types ──────────────────────────────────────────────────────────────

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

// ── EnforcementError ──────────────────────────────────────────────────────────

/**
 * Thrown when a policy returns a `deny` verdict.
 *
 * The full `PolicyResult` is attached so callers can inspect triggered rules,
 * violations, and the denial reason.
 */
export class EnforcementError extends Error {
  /** The full policy evaluation result that triggered this error. */
  readonly result: PolicyResult;

  constructor(result: PolicyResult) {
    super(result.reason ?? `Policy denied: ${result.verdict}`);
    this.name = 'EnforcementError';
    this.result = result;
    // Maintain proper prototype chain in compiled ES5 output.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ── PolicyEngine ──────────────────────────────────────────────────────────────

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
export class PolicyEngine {
  private readonly _native: NativePolicyEngine;

  private constructor(native: NativePolicyEngine) {
    this._native = native;
  }

  /**
   * Load a policy engine from a compiled `.aegisc` file path.
   *
   * @param path - Absolute or relative path to the `.aegisc` file.
   * @throws If the file does not exist or is not a valid compiled policy.
   */
  static fromFile(path: string): PolicyEngine {
    return new PolicyEngine(getNative().PolicyEngine.fromFile(path));
  }

  /**
   * Load a policy engine from raw `.aegisc` bytes (e.g. embedded via webpack).
   *
   * @param data - A Node.js `Buffer` containing the compiled policy bytes.
   * @throws If the buffer is not a valid compiled policy.
   */
  static fromBytes(data: Buffer): PolicyEngine {
    return new PolicyEngine(getNative().PolicyEngine.fromBytes(data));
  }

  /**
   * Evaluate a single agent event against the loaded policy.
   *
   * @param eventType - Event type string (e.g. `"tool_call"`, `"data_access"`).
   * @param fields    - Arbitrary event fields. Omit or pass `undefined` for
   *                    events with no fields.
   * @returns A {@link PolicyResult} with the verdict, triggered rules, and any
   *          violations.
   */
  evaluate(eventType: string, fields?: Record<string, unknown>): PolicyResult {
    return this._native.evaluate(eventType, fields);
  }

  /**
   * Set a persistent context value accessible in policy expressions as
   * `context.<key>`. Values accumulate across events for the lifetime of
   * this engine instance.
   */
  setContext(key: string, value: unknown): void {
    this._native.setContext(key, value);
  }

  /**
   * Set a policy configuration value accessible in policy expressions as
   * `config.<key>`.
   */
  setConfig(key: string, value: unknown): void {
    this._native.setConfig(key, value);
  }

  /** The policy name declared in the `.aegisc` file (`policy <Name> { }`). */
  get policyName(): string {
    return this._native.policyName;
  }

  /** Total events evaluated since creation or the last `reset()`. */
  get eventCount(): number {
    return this._native.eventCount;
  }

  /**
   * Reset all state machines and rate-limit counters to their initial states.
   *
   * Call this at the start of a new agent session to isolate per-session
   * temporal invariants and rate limits.
   */
  reset(): void {
    this._native.reset();
  }

  /** Return a snapshot of the engine's current operational state. */
  status(): EngineStatus {
    return this._native.status();
  }
}

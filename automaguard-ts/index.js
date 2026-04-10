"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolicyEngine = exports.EnforcementError = void 0;
exports.__setNativeBinding = __setNativeBinding;
// Lazily initialised so that requiring this module in test environments does
// not immediately try to load a platform binary.
let _nativeBinding = null;
function getNative() {
    if (_nativeBinding)
        return _nativeBinding;
    _nativeBinding = loadNative();
    return _nativeBinding;
}
function loadNative() {
    const platformKey = `${process.platform}-${process.arch}`;
    const packageNames = {
        'linux-x64': 'automaguard-linux-x64-gnu',
        'darwin-arm64': 'automaguard-darwin-arm64',
        'darwin-x64': 'automaguard-darwin-x64',
        'win32-x64': 'automaguard-win32-x64-msvc',
    };
    const fileNames = {
        'linux-x64': 'automaguard-ts.linux-x64-gnu.node',
        'darwin-arm64': 'automaguard-ts.darwin-arm64.node',
        'darwin-x64': 'automaguard-ts.darwin-x64.node',
        'win32-x64': 'automaguard-ts.win32-x64-msvc.node',
    };
    if (!(platformKey in packageNames)) {
        throw new Error(`AutomaGuard: unsupported platform "${platformKey}". ` +
            `Supported: ${Object.keys(packageNames).join(', ')}`);
    }
    // 1. Try the prebuilt npm optional-dependency package.
    try {
        return require(packageNames[platformKey]);
    }
    catch {
        // fall through
    }
    // 2. Fall back to a local build (development / CI).
    // Note: this file compiles from js/index.ts → index.js (package root),
    // so __dirname at runtime is the package root, not the js/ subdirectory.
    const localFile = `${__dirname}/${fileNames[platformKey]}`;
    try {
        return require(localFile);
    }
    catch (err) {
        throw new Error(`AutomaGuard: failed to load native binary for "${platformKey}". ` +
            `Install the prebuilt package "${packageNames[platformKey]}", or ` +
            `run \`npm run build\` to compile from source. ` +
            `Original error: ${err}`);
    }
}
/**
 * Override the native binding — for unit testing only.
 * @internal
 */
function __setNativeBinding(binding) {
    _nativeBinding = binding;
}
// ── EnforcementError ──────────────────────────────────────────────────────────
/**
 * Thrown when a policy returns a `deny` verdict.
 *
 * The full `PolicyResult` is attached so callers can inspect triggered rules,
 * violations, and the denial reason.
 */
class EnforcementError extends Error {
    constructor(result) {
        super(result.reason ?? `Policy denied: ${result.verdict}`);
        this.name = 'EnforcementError';
        this.result = result;
        // Maintain proper prototype chain in compiled ES5 output.
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
exports.EnforcementError = EnforcementError;
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
class PolicyEngine {
    constructor(native) {
        this._native = native;
    }
    /**
     * Load a policy engine from a compiled `.aegisc` file path.
     *
     * @param path - Absolute or relative path to the `.aegisc` file.
     * @throws If the file does not exist or is not a valid compiled policy.
     */
    static fromFile(path) {
        return new PolicyEngine(getNative().PolicyEngine.fromFile(path));
    }
    /**
     * Load a policy engine from raw `.aegisc` bytes (e.g. embedded via webpack).
     *
     * @param data - A Node.js `Buffer` containing the compiled policy bytes.
     * @throws If the buffer is not a valid compiled policy.
     */
    static fromBytes(data) {
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
    evaluate(eventType, fields) {
        return this._native.evaluate(eventType, fields);
    }
    /**
     * Set a persistent context value accessible in policy expressions as
     * `context.<key>`. Values accumulate across events for the lifetime of
     * this engine instance.
     */
    setContext(key, value) {
        this._native.setContext(key, value);
    }
    /**
     * Set a policy configuration value accessible in policy expressions as
     * `config.<key>`.
     */
    setConfig(key, value) {
        this._native.setConfig(key, value);
    }
    /** The policy name declared in the `.aegisc` file (`policy <Name> { }`). */
    get policyName() {
        return this._native.policyName;
    }
    /** Total events evaluated since creation or the last `reset()`. */
    get eventCount() {
        return this._native.eventCount;
    }
    /**
     * Reset all state machines and rate-limit counters to their initial states.
     *
     * Call this at the start of a new agent session to isolate per-session
     * temporal invariants and rate limits.
     */
    reset() {
        this._native.reset();
    }
    /** Return a snapshot of the engine's current operational state. */
    status() {
        return this._native.status();
    }
}
exports.PolicyEngine = PolicyEngine;
//# sourceMappingURL=index.js.map
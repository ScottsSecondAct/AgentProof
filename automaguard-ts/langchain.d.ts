/**
 * AutomaGuard LangChain.js integration.
 *
 * Attach `AutomaGuardCallbackHandler` to any LangChain `AgentExecutor` or
 * chain to enforce a compiled `.aegisc` policy on every tool invocation.
 * Denied calls throw `EnforcementError` by default; this can be overridden
 * via the `onDeny` option.
 *
 * @example
 * ```typescript
 * import { AutomaGuardCallbackHandler } from 'automaguard/langchain';
 * import { AgentExecutor } from 'langchain/agents';
 *
 * const handler = new AutomaGuardCallbackHandler({ policy: 'guard.aegisc' });
 * const executor = new AgentExecutor({ agent, tools, callbacks: [handler] });
 * ```
 */
import { PolicyEngine, type PolicyResult } from './index';
interface SerializedTool {
    name?: string;
    [key: string]: unknown;
}
export interface AutomaGuardCallbackHandlerOptions {
    /**
     * Path to the compiled `.aegisc` policy file.
     */
    policy: string;
    /**
     * Called when `evaluate()` returns a `deny` verdict.
     * Defaults to throwing {@link EnforcementError}.
     */
    onDeny?: (result: PolicyResult, toolName: string) => void;
    /**
     * Called when `evaluate()` returns an `audit` verdict (allowed but logged).
     * Defaults to a no-op; override to send to your audit sink.
     */
    onAudit?: (result: PolicyResult, toolName: string) => void;
}
/**
 * LangChain.js callback handler that enforces AutomaGuard policies on tool
 * calls.
 *
 * Hooks three lifecycle methods:
 * - `handleToolStart` — evaluates the incoming tool invocation as a
 *   `tool_call` event. Denied calls throw before the tool runs.
 * - `handleToolEnd` — evaluates the tool result as a `tool_result` event.
 *   Useful for policies that inspect output (e.g. PII in response).
 * - `handleToolError` — fires a `tool_error` event so the policy can track
 *   failed tool invocations (e.g. for rate-limit purposes).
 */
export declare class AutomaGuardCallbackHandler {
    readonly name = "AutomaGuardCallbackHandler";
    private readonly engine;
    private readonly onDeny;
    private readonly onAudit;
    constructor(options: AutomaGuardCallbackHandlerOptions);
    /**
     * Evaluate the tool invocation before the tool runs.
     *
     * LangChain calls this with the serialised tool descriptor and the
     * raw input string (typically a JSON object).
     */
    handleToolStart(tool: SerializedTool, input: string, _runId: string, _parentRunId?: string, _tags?: string[], _metadata?: Record<string, unknown>, _name?: string): void;
    /**
     * Evaluate the tool result after the tool completes.
     *
     * Useful for policies that inspect tool output (e.g. redacting PII in
     * a database query response before it reaches the LLM context).
     */
    handleToolEnd(output: string, _runId: string, _parentRunId?: string, _tags?: string[]): void;
    /**
     * Fire a `tool_error` event so the policy can track failed invocations.
     */
    handleToolError(_err: Error, _runId: string, _parentRunId?: string, _tags?: string[]): void;
    /**
     * The underlying `PolicyEngine` instance. Exposed for advanced use cases
     * such as setting context values before evaluation.
     */
    get policyEngine(): PolicyEngine;
}
export {};
//# sourceMappingURL=langchain.d.ts.map
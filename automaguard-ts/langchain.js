"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.AutomaGuardCallbackHandler = void 0;
const index_1 = require("./index");
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
class AutomaGuardCallbackHandler {
    constructor(options) {
        this.name = 'AutomaGuardCallbackHandler';
        this.engine = index_1.PolicyEngine.fromFile(options.policy);
        this.onDeny =
            options.onDeny ??
                ((result) => {
                    throw new index_1.EnforcementError(result);
                });
        this.onAudit = options.onAudit ?? (() => { });
    }
    /**
     * Evaluate the tool invocation before the tool runs.
     *
     * LangChain calls this with the serialised tool descriptor and the
     * raw input string (typically a JSON object).
     */
    handleToolStart(tool, input, _runId, _parentRunId, _tags, _metadata, _name) {
        const toolName = tool.name ?? 'unknown';
        let parsedInput = input;
        try {
            parsedInput = JSON.parse(input);
        }
        catch {
            // Keep as string if the input is not valid JSON.
        }
        const result = this.engine.evaluate('tool_call', {
            tool_name: toolName,
            arguments: parsedInput,
        });
        if (result.verdict === 'deny') {
            this.onDeny(result, toolName);
        }
        else if (result.verdict === 'audit') {
            this.onAudit(result, toolName);
        }
    }
    /**
     * Evaluate the tool result after the tool completes.
     *
     * Useful for policies that inspect tool output (e.g. redacting PII in
     * a database query response before it reaches the LLM context).
     */
    handleToolEnd(output, _runId, _parentRunId, _tags) {
        let parsedOutput = output;
        try {
            parsedOutput = JSON.parse(output);
        }
        catch {
            // Keep as string if the output is not valid JSON.
        }
        const result = this.engine.evaluate('tool_result', {
            output: parsedOutput,
        });
        if (result.verdict === 'deny') {
            this.onDeny(result, 'tool_result');
        }
        else if (result.verdict === 'audit') {
            this.onAudit(result, 'tool_result');
        }
    }
    /**
     * Fire a `tool_error` event so the policy can track failed invocations.
     */
    handleToolError(_err, _runId, _parentRunId, _tags) {
        this.engine.evaluate('tool_error', {});
    }
    /**
     * The underlying `PolicyEngine` instance. Exposed for advanced use cases
     * such as setting context values before evaluation.
     */
    get policyEngine() {
        return this.engine;
    }
}
exports.AutomaGuardCallbackHandler = AutomaGuardCallbackHandler;
//# sourceMappingURL=langchain.js.map
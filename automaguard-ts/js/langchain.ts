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

import { PolicyEngine, EnforcementError, type PolicyResult } from './index';

// Minimal LangChain type stubs — the real types from @langchain/core are
// structurally compatible; we avoid a hard dependency on the package.

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
export class AutomaGuardCallbackHandler {
  readonly name = 'AutomaGuardCallbackHandler';

  private readonly engine: PolicyEngine;
  private readonly onDeny: (result: PolicyResult, toolName: string) => void;
  private readonly onAudit: (result: PolicyResult, toolName: string) => void;

  constructor(options: AutomaGuardCallbackHandlerOptions) {
    this.engine = PolicyEngine.fromFile(options.policy);
    this.onDeny =
      options.onDeny ??
      ((result) => {
        throw new EnforcementError(result);
      });
    this.onAudit = options.onAudit ?? (() => {});
  }

  /**
   * Evaluate the tool invocation before the tool runs.
   *
   * LangChain calls this with the serialised tool descriptor and the
   * raw input string (typically a JSON object).
   */
  handleToolStart(
    tool: SerializedTool,
    input: string,
    _runId: string,
    _parentRunId?: string,
    _tags?: string[],
    _metadata?: Record<string, unknown>,
    _name?: string
  ): void {
    const toolName = tool.name ?? 'unknown';

    let parsedInput: unknown = input;
    try {
      parsedInput = JSON.parse(input);
    } catch {
      // Keep as string if the input is not valid JSON.
    }

    const result = this.engine.evaluate('tool_call', {
      tool_name: toolName,
      arguments: parsedInput,
    });

    if (result.verdict === 'deny') {
      this.onDeny(result, toolName);
    } else if (result.verdict === 'audit') {
      this.onAudit(result, toolName);
    }
  }

  /**
   * Evaluate the tool result after the tool completes.
   *
   * Useful for policies that inspect tool output (e.g. redacting PII in
   * a database query response before it reaches the LLM context).
   */
  handleToolEnd(
    output: string,
    _runId: string,
    _parentRunId?: string,
    _tags?: string[]
  ): void {
    let parsedOutput: unknown = output;
    try {
      parsedOutput = JSON.parse(output);
    } catch {
      // Keep as string if the output is not valid JSON.
    }

    const result = this.engine.evaluate('tool_result', {
      output: parsedOutput,
    });

    if (result.verdict === 'deny') {
      this.onDeny(result, 'tool_result');
    } else if (result.verdict === 'audit') {
      this.onAudit(result, 'tool_result');
    }
  }

  /**
   * Fire a `tool_error` event so the policy can track failed invocations.
   */
  handleToolError(
    _err: Error,
    _runId: string,
    _parentRunId?: string,
    _tags?: string[]
  ): void {
    this.engine.evaluate('tool_error', {});
  }

  /**
   * The underlying `PolicyEngine` instance. Exposed for advanced use cases
   * such as setting context values before evaluation.
   */
  get policyEngine(): PolicyEngine {
    return this.engine;
  }
}

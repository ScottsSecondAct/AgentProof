/**
 * AutomaGuard OpenAI Node.js integration.
 *
 * Wrap an `OpenAI` client instance so that tool calls in assistant messages
 * are evaluated against the policy before the calling code sees them.
 * Denied tool calls throw `EnforcementError` from inside `create()`.
 *
 * @example
 * ```typescript
 * import { enforce } from 'automaguard/openai';
 * import OpenAI from 'openai';
 *
 * const client = enforce(new OpenAI(), { policy: 'guard.aegisc' });
 * // client.chat.completions.create() is now policy-enforced.
 * ```
 */

import { PolicyEngine, EnforcementError, type PolicyResult } from './index';

// ── Minimal OpenAI type stubs ─────────────────────────────────────────────────
// These are structurally compatible with the real openai package types.
// We keep them minimal to avoid importing openai as a hard dependency.

interface ToolCallFunction {
  name?: string;
  arguments?: string;
}

interface ToolCall {
  id?: string;
  type?: string;
  function?: ToolCallFunction;
}

interface ChatMessage {
  role: string;
  content: string | null;
  tool_calls?: ToolCall[];
}

interface ChatChoice {
  message: ChatMessage;
  finish_reason?: string;
  index?: number;
}

interface ChatCompletion {
  id?: string;
  choices: ChatChoice[];
  [key: string]: unknown;
}

interface CompletionsNamespace {
  create(...args: unknown[]): Promise<ChatCompletion>;
  [key: string]: unknown;
}

interface ChatNamespace {
  completions: CompletionsNamespace;
  [key: string]: unknown;
}

interface OpenAIClient {
  chat: ChatNamespace;
  [key: string]: unknown;
}

// ── Public API ────────────────────────────────────────────────────────────────

export interface EnforceOptions {
  /**
   * Path to the compiled `.aegisc` policy file.
   */
  policy: string;
  /**
   * Called when a tool call is denied.
   * Defaults to throwing {@link EnforcementError}.
   */
  onDeny?: (result: PolicyResult, call: ToolCall) => void;
  /**
   * Called when a tool call is audited (allowed but logged).
   * Defaults to a no-op.
   */
  onAudit?: (result: PolicyResult, call: ToolCall) => void;
}

/**
 * Wrap an OpenAI client to enforce AutomaGuard policies on tool calls.
 *
 * Returns a `Proxy` of the client with the identical interface. Every call to
 * `client.chat.completions.create()` is intercepted; tool calls found in
 * the assistant message are evaluated as `tool_call` events before the
 * response is returned to the caller.
 *
 * The proxy is transparent — all properties and methods not related to
 * `chat.completions.create` are forwarded to the original client unchanged.
 *
 * @param client  - An `OpenAI` client instance.
 * @param options - Enforcement options.
 * @returns A proxied client with the identical TypeScript interface.
 */
export function enforce<T extends OpenAIClient>(client: T, options: EnforceOptions): T {
  const engine = PolicyEngine.fromFile(options.policy);
  const onDeny =
    options.onDeny ??
    ((result: PolicyResult) => {
      throw new EnforcementError(result);
    });
  const onAudit = options.onAudit ?? (() => {});

  const originalCreate = client.chat.completions.create.bind(
    client.chat.completions
  );

  const guardedCreate = async (...args: unknown[]): Promise<ChatCompletion> => {
    const completion = await originalCreate(...args);
    evaluateToolCalls(engine, completion, onDeny, onAudit);
    return completion;
  };

  return new Proxy(client, {
    get(target: T, prop: string | symbol) {
      if (prop === 'chat') {
        return new Proxy(target.chat, {
          get(chatTarget: ChatNamespace, chatProp: string | symbol) {
            if (chatProp === 'completions') {
              return new Proxy(chatTarget.completions, {
                get(
                  completionsTarget: CompletionsNamespace,
                  completionsProp: string | symbol
                ) {
                  if (completionsProp === 'create') return guardedCreate;
                  return Reflect.get(completionsTarget, completionsProp);
                },
              });
            }
            return Reflect.get(chatTarget, chatProp);
          },
        });
      }
      return Reflect.get(target, prop as keyof T);
    },
  });
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function evaluateToolCalls(
  engine: PolicyEngine,
  completion: ChatCompletion,
  onDeny: (result: PolicyResult, call: ToolCall) => void,
  onAudit: (result: PolicyResult, call: ToolCall) => void
): void {
  for (const choice of completion.choices) {
    const toolCalls = choice.message.tool_calls;
    if (!toolCalls || toolCalls.length === 0) continue;

    for (const call of toolCalls) {
      const fnName = call.function?.name ?? 'unknown';

      let parsedArgs: unknown = {};
      if (call.function?.arguments) {
        try {
          parsedArgs = JSON.parse(call.function.arguments);
        } catch {
          // Keep as string if arguments are not valid JSON.
          parsedArgs = call.function.arguments;
        }
      }

      const result = engine.evaluate('tool_call', {
        tool_name: fnName,
        tool_call_id: call.id,
        arguments: parsedArgs,
      });

      if (result.verdict === 'deny') {
        onDeny(result, call);
      } else if (result.verdict === 'audit') {
        onAudit(result, call);
      }
    }
  }
}

/**
 * AutomaGuard Vercel AI SDK integration.
 *
 * Wrap a Vercel AI language model to enforce AutomaGuard policies on tool
 * calls emitted by `generateText` and `streamText`. Denied tool calls throw
 * `EnforcementError` before the tool is executed.
 *
 * @example
 * ```typescript
 * import { withGuard } from 'automaguard/vercel-ai';
 * import { openai } from '@ai-sdk/openai';
 * import { generateText } from 'ai';
 *
 * const model = withGuard(openai('gpt-4o'), { policy: 'guard.aegisc' });
 * const { text } = await generateText({ model, tools: { ... }, prompt: '...' });
 * ```
 */

import { PolicyEngine, EnforcementError, type PolicyResult } from './index';

// ── Minimal Vercel AI SDK type stubs ──────────────────────────────────────────
// Structurally compatible with @ai-sdk/provider LanguageModelV1.

interface ToolCallPart {
  type: 'tool-call';
  toolCallId: string;
  toolName: string;
  args: Record<string, unknown>;
}

interface GenerateResult {
  toolCalls?: ToolCallPart[];
  [key: string]: unknown;
}

interface StreamChunk {
  type?: string;
  [key: string]: unknown;
}

interface StreamResult {
  stream: AsyncIterable<StreamChunk>;
  [key: string]: unknown;
}

interface LanguageModelV1 {
  doGenerate(options: unknown): Promise<GenerateResult>;
  doStream(options: unknown): Promise<StreamResult>;
  [key: string]: unknown;
}

// ── Public API ────────────────────────────────────────────────────────────────

export interface WithGuardOptions {
  /**
   * Path to the compiled `.aegisc` policy file.
   */
  policy: string;
  /**
   * Called when a tool call is denied.
   * Defaults to throwing {@link EnforcementError}.
   */
  onDeny?: (result: PolicyResult, toolName: string) => void;
  /**
   * Called when a tool call is audited (allowed but logged).
   * Defaults to a no-op.
   */
  onAudit?: (result: PolicyResult, toolName: string) => void;
}

/**
 * Wrap a Vercel AI SDK language model to enforce AutomaGuard policies on tool
 * calls.
 *
 * The returned model has the identical `LanguageModelV1` interface and can be
 * passed to `generateText`, `streamText`, and other Vercel AI helpers.
 *
 * For `doGenerate`, tool calls in the response are evaluated **after** the
 * model responds but **before** the result is returned to the caller.
 *
 * For `doStream`, each `tool-call` chunk is evaluated as it arrives in the
 * stream. Denied calls throw immediately, aborting the stream.
 *
 * @param model   - A Vercel AI language model instance.
 * @param options - Enforcement options.
 * @returns A proxied model with the identical interface.
 */
export function withGuard<T extends LanguageModelV1>(
  model: T,
  options: WithGuardOptions
): T {
  const engine = PolicyEngine.fromFile(options.policy);
  const onDeny =
    options.onDeny ??
    ((result: PolicyResult) => {
      throw new EnforcementError(result);
    });
  const onAudit = options.onAudit ?? (() => {});

  function checkToolCall(call: ToolCallPart): void {
    const result = engine.evaluate('tool_call', {
      tool_name: call.toolName,
      tool_call_id: call.toolCallId,
      arguments: call.args,
    });
    if (result.verdict === 'deny') {
      onDeny(result, call.toolName);
    } else if (result.verdict === 'audit') {
      onAudit(result, call.toolName);
    }
  }

  return new Proxy(model, {
    get(target: T, prop: string | symbol) {
      if (prop === 'doGenerate') {
        return async (opts: unknown): Promise<GenerateResult> => {
          const response = await target.doGenerate(opts);
          if (response.toolCalls) {
            for (const call of response.toolCalls) {
              checkToolCall(call);
            }
          }
          return response;
        };
      }

      if (prop === 'doStream') {
        return async (opts: unknown): Promise<StreamResult> => {
          const response = await target.doStream(opts);

          // Wrap the stream to intercept tool-call chunks as they arrive.
          const originalStream = response.stream;
          const guardedStream: AsyncIterable<StreamChunk> = {
            [Symbol.asyncIterator]() {
              const iter = originalStream[Symbol.asyncIterator]();
              return {
                async next() {
                  const item = await iter.next();
                  if (!item.done) {
                    const chunk = item.value;
                    if (chunk.type === 'tool-call') {
                      checkToolCall(chunk as unknown as ToolCallPart);
                    }
                  }
                  return item;
                },
                async return(value?: unknown) {
                  if (iter.return) return iter.return(value);
                  return { done: true as const, value };
                },
                async throw(err?: unknown) {
                  if (iter.throw) return iter.throw(err);
                  return Promise.reject(err);
                },
              };
            },
          };

          return { ...response, stream: guardedStream };
        };
      }

      return Reflect.get(target, prop);
    },
  });
}

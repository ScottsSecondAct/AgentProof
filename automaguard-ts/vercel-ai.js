"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.withGuard = withGuard;
const index_1 = require("./index");
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
function withGuard(model, options) {
    const engine = index_1.PolicyEngine.fromFile(options.policy);
    const onDeny = options.onDeny ??
        ((result) => {
            throw new index_1.EnforcementError(result);
        });
    const onAudit = options.onAudit ?? (() => { });
    function checkToolCall(call) {
        const result = engine.evaluate('tool_call', {
            tool_name: call.toolName,
            tool_call_id: call.toolCallId,
            arguments: call.args,
        });
        if (result.verdict === 'deny') {
            onDeny(result, call.toolName);
        }
        else if (result.verdict === 'audit') {
            onAudit(result, call.toolName);
        }
    }
    return new Proxy(model, {
        get(target, prop) {
            if (prop === 'doGenerate') {
                return async (opts) => {
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
                return async (opts) => {
                    const response = await target.doStream(opts);
                    // Wrap the stream to intercept tool-call chunks as they arrive.
                    const originalStream = response.stream;
                    const guardedStream = {
                        [Symbol.asyncIterator]() {
                            const iter = originalStream[Symbol.asyncIterator]();
                            return {
                                async next() {
                                    const item = await iter.next();
                                    if (!item.done) {
                                        const chunk = item.value;
                                        if (chunk.type === 'tool-call') {
                                            checkToolCall(chunk);
                                        }
                                    }
                                    return item;
                                },
                                async return(value) {
                                    if (iter.return)
                                        return iter.return(value);
                                    return { done: true, value };
                                },
                                async throw(err) {
                                    if (iter.throw)
                                        return iter.throw(err);
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
//# sourceMappingURL=vercel-ai.js.map
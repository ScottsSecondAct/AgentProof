"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.enforce = enforce;
const index_1 = require("./index");
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
function enforce(client, options) {
    const engine = index_1.PolicyEngine.fromFile(options.policy);
    const onDeny = options.onDeny ??
        ((result) => {
            throw new index_1.EnforcementError(result);
        });
    const onAudit = options.onAudit ?? (() => { });
    const originalCreate = client.chat.completions.create.bind(client.chat.completions);
    const guardedCreate = async (...args) => {
        const completion = await originalCreate(...args);
        evaluateToolCalls(engine, completion, onDeny, onAudit);
        return completion;
    };
    return new Proxy(client, {
        get(target, prop) {
            if (prop === 'chat') {
                return new Proxy(target.chat, {
                    get(chatTarget, chatProp) {
                        if (chatProp === 'completions') {
                            return new Proxy(chatTarget.completions, {
                                get(completionsTarget, completionsProp) {
                                    if (completionsProp === 'create')
                                        return guardedCreate;
                                    return Reflect.get(completionsTarget, completionsProp);
                                },
                            });
                        }
                        return Reflect.get(chatTarget, chatProp);
                    },
                });
            }
            return Reflect.get(target, prop);
        },
    });
}
// ── Internal helpers ──────────────────────────────────────────────────────────
function evaluateToolCalls(engine, completion, onDeny, onAudit) {
    for (const choice of completion.choices) {
        const toolCalls = choice.message.tool_calls;
        if (!toolCalls || toolCalls.length === 0)
            continue;
        for (const call of toolCalls) {
            const fnName = call.function?.name ?? 'unknown';
            let parsedArgs = {};
            if (call.function?.arguments) {
                try {
                    parsedArgs = JSON.parse(call.function.arguments);
                }
                catch {
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
            }
            else if (result.verdict === 'audit') {
                onAudit(result, call);
            }
        }
    }
}
//# sourceMappingURL=openai.js.map
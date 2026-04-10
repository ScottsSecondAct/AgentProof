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
import { type PolicyResult } from './index';
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
export declare function enforce<T extends OpenAIClient>(client: T, options: EnforceOptions): T;
export {};
//# sourceMappingURL=openai.d.ts.map
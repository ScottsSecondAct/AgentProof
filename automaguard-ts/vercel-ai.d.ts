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
import { type PolicyResult } from './index';
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
export declare function withGuard<T extends LanguageModelV1>(model: T, options: WithGuardOptions): T;
export {};
//# sourceMappingURL=vercel-ai.d.ts.map
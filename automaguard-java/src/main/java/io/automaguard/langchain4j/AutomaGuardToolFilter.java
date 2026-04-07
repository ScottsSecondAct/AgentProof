package io.automaguard.langchain4j;

import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.service.tool.ToolExecutor;
import dev.langchain4j.service.tool.ToolProvider;
import dev.langchain4j.service.tool.ToolProviderRequest;
import dev.langchain4j.service.tool.ToolProviderResult;
import io.automaguard.EnforcementException;
import io.automaguard.PolicyEngine;
import io.automaguard.PolicyResult;
import io.automaguard.Verdict;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * LangChain4j {@link ToolProvider} that enforces an AutomaGuard policy on
 * every tool execution.
 *
 * <p>Register with {@code AiServices.builder().toolProvider(…)}:</p>
 *
 * <pre>{@code
 * var filter = new AutomaGuardToolFilter("guard.aegisc");
 *
 * var assistant = AiServices.builder(Assistant.class)
 *     .chatLanguageModel(model)
 *     .toolProvider(filter.wrapping(DefaultToolProvider.from(new MyTools())))
 *     .build();
 * }</pre>
 *
 * <p>Each tool execution request is evaluated as a {@code tool_call} event
 * before the tool runs.  A {@link Verdict#DENY} verdict throws
 * {@link EnforcementException} before the tool body executes.</p>
 */
public final class AutomaGuardToolFilter {

    private final PolicyEngine engine;
    private final boolean ownsEngine;
    private final BiConsumer<PolicyResult, String> onAudit;

    /**
     * Create a filter that loads a policy from a {@code .aegisc} file.
     *
     * @param policyPath path to the compiled policy file
     * @throws IOException if the file cannot be read or parsed
     */
    public AutomaGuardToolFilter(String policyPath) throws IOException {
        this(policyPath, null);
    }

    /**
     * Create a filter with a custom audit callback.
     *
     * @param policyPath path to the compiled policy file
     * @param onAudit    called for each {@link Verdict#AUDIT} verdict;
     *                   receives the result and the tool name.
     * @throws IOException if the file cannot be read or parsed
     */
    public AutomaGuardToolFilter(String policyPath, BiConsumer<PolicyResult, String> onAudit)
            throws IOException {
        this.engine = PolicyEngine.fromFile(policyPath);
        this.ownsEngine = true;
        this.onAudit = onAudit;
    }

    /**
     * Create a filter from a pre-constructed {@link PolicyEngine}.
     *
     * <p>The filter does <em>not</em> take ownership of the engine.</p>
     *
     * @param engine  pre-loaded policy engine
     * @param onAudit optional audit callback; may be {@code null}
     */
    public AutomaGuardToolFilter(PolicyEngine engine, BiConsumer<PolicyResult, String> onAudit) {
        this.engine = engine;
        this.ownsEngine = false;
        this.onAudit = onAudit;
    }

    // ── ToolProvider wrapping ─────────────────────────────────────────────────

    /**
     * Wrap a delegate {@link ToolProvider} so that every tool call is guarded
     * by the AutomaGuard policy.
     *
     * <p>The returned {@link ToolProvider} passes the tool specifications
     * through unchanged and wraps each {@link ToolExecutor} with a guard that
     * evaluates the policy before execution.</p>
     *
     * @param delegate the underlying tool provider to wrap
     * @return a guarded {@link ToolProvider}
     */
    public ToolProvider wrapping(ToolProvider delegate) {
        return request -> {
            ToolProviderResult result = delegate.provideTools(request);
            if (result == null) return null;

            Map<ToolSpecification, ToolExecutor> guarded =
                    new LinkedHashMap<>(result.tools().size());

            for (Map.Entry<ToolSpecification, ToolExecutor> entry : result.tools().entrySet()) {
                guarded.put(entry.getKey(), guardedExecutor(entry.getKey(), entry.getValue()));
            }

            return ToolProviderResult.builder().tools(guarded).build();
        };
    }

    // ── Executor guard ────────────────────────────────────────────────────────

    private ToolExecutor guardedExecutor(ToolSpecification spec, ToolExecutor delegate) {
        return (ToolExecutionRequest req, Object memoryId) -> {
            enforcePreExecution(spec.name(), req.arguments());
            return delegate.execute(req, memoryId);
        };
    }

    private void enforcePreExecution(String toolName, String argumentsJson) {
        PolicyResult result = engine.evaluate("tool_call", Map.of(
                "tool_name", toolName,
                "arguments", argumentsJson != null ? argumentsJson : ""
        ));

        if (result.isDenied()) {
            throw new EnforcementException(result);
        }
        if (result.isAudited() && onAudit != null) {
            onAudit.accept(result, toolName);
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /**
     * Close the underlying {@link PolicyEngine} if this filter owns it.
     * Safe to call multiple times.
     */
    public void close() {
        if (ownsEngine) {
            engine.close();
        }
    }
}

package io.automaguard.springai;

import io.automaguard.EnforcementException;
import io.automaguard.PolicyEngine;
import io.automaguard.PolicyResult;
import io.automaguard.Verdict;
import org.springframework.ai.chat.client.advisor.api.AdvisedRequest;
import org.springframework.ai.chat.client.advisor.api.AdvisedResponse;
import org.springframework.ai.chat.client.advisor.api.CallAroundAdvisor;
import org.springframework.ai.chat.client.advisor.api.CallAroundAdvisorChain;
import org.springframework.ai.model.function.FunctionCallback;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * Spring AI {@link CallAroundAdvisor} that enforces an AutomaGuard policy on
 * every tool (function) call made by the model.
 *
 * <p>Register via {@code ChatClient.builder().defaultAdvisors(new AutomaGuardAdvisor(...))}:</p>
 *
 * <pre>{@code
 * var advisor = new AutomaGuardAdvisor("guard.aegisc");
 *
 * var client = ChatClient.builder(chatModel)
 *     .defaultAdvisors(advisor)
 *     .build();
 * }</pre>
 *
 * <p>The advisor intercepts tool calls in {@code adviseRequest} by wrapping
 * each registered {@link FunctionCallback} with a guarded version.  The guard
 * evaluates a {@code tool_call} event against the loaded policy before allowing
 * the function body to run.  A {@link Verdict#DENY} verdict throws
 * {@link EnforcementException} before the tool executes.</p>
 */
public final class AutomaGuardAdvisor implements CallAroundAdvisor {

    private static final String NAME = "AutomaGuardAdvisor";

    private final PolicyEngine engine;
    private final boolean ownsEngine;
    private final BiConsumer<PolicyResult, String> onAudit;

    /**
     * Create an advisor that loads a policy from a {@code .aegisc} file.
     *
     * @param policyPath path to the compiled policy file
     * @throws IOException if the file cannot be read or parsed
     */
    public AutomaGuardAdvisor(String policyPath) throws IOException {
        this(policyPath, null);
    }

    /**
     * Create an advisor with a custom audit callback.
     *
     * @param policyPath path to the compiled policy file
     * @param onAudit    called for each {@link Verdict#AUDIT} verdict;
     *                   receives the result and the tool name.
     *                   Pass {@code null} to use the default no-op.
     * @throws IOException if the file cannot be read or parsed
     */
    public AutomaGuardAdvisor(String policyPath, BiConsumer<PolicyResult, String> onAudit)
            throws IOException {
        this.engine = PolicyEngine.fromFile(policyPath);
        this.ownsEngine = true;
        this.onAudit = onAudit;
    }

    /**
     * Create an advisor from a pre-constructed {@link PolicyEngine}.
     *
     * <p>The advisor does <em>not</em> take ownership of the engine — the
     * caller is responsible for closing it.</p>
     *
     * @param engine  pre-loaded engine
     * @param onAudit optional audit callback; may be {@code null}
     */
    public AutomaGuardAdvisor(PolicyEngine engine, BiConsumer<PolicyResult, String> onAudit) {
        this.engine = engine;
        this.ownsEngine = false;
        this.onAudit = onAudit;
    }

    // ── CallAroundAdvisor ─────────────────────────────────────────────────────

    @Override
    public String getName() { return NAME; }

    @Override
    public int getOrder() { return 0; }

    /**
     * Intercept the request by wrapping each {@link FunctionCallback} with a
     * guarded version that evaluates the policy before executing the function.
     */
    @Override
    public AdvisedResponse aroundCall(AdvisedRequest request, CallAroundAdvisorChain chain) {
        AdvisedRequest guarded = wrapToolCallbacks(request);
        return chain.nextAroundCall(guarded);
    }

    // ── Tool callback wrapping ────────────────────────────────────────────────

    private AdvisedRequest wrapToolCallbacks(AdvisedRequest request) {
        List<FunctionCallback> callbacks = request.functionCallbacks();
        if (callbacks == null || callbacks.isEmpty()) {
            return request;
        }

        List<FunctionCallback> guarded = new ArrayList<>(callbacks.size());
        for (FunctionCallback cb : callbacks) {
            guarded.add(guardedCallback(cb));
        }

        return AdvisedRequest.from(request).functionCallbacks(guarded).build();
    }

    private FunctionCallback guardedCallback(FunctionCallback original) {
        return new FunctionCallback() {
            @Override
            public String getName() { return original.getName(); }

            @Override
            public String getDescription() { return original.getDescription(); }

            @Override
            public String getInputTypeSchema() { return original.getInputTypeSchema(); }

            @Override
            public String call(String functionInput) {
                evaluateToolCall(original.getName(), functionInput);
                return original.call(functionInput);
            }
        };
    }

    private void evaluateToolCall(String toolName, String argumentsJson) {
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
     * Close the underlying {@link PolicyEngine} if this advisor owns it.
     * Safe to call multiple times.
     */
    public void close() {
        if (ownsEngine) {
            engine.close();
        }
    }
}

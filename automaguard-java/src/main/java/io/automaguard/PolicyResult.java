package io.automaguard;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Collections;
import java.util.List;

/**
 * The full result of evaluating one agent event against a loaded policy.
 *
 * <p>Obtain via {@link PolicyEngine#evaluate(String, java.util.Map)}.</p>
 *
 * <p>The convenience predicates ({@link #isAllowed()}, {@link #isDenied()},
 * {@link #isAudited()}, {@link #isRedacted()}) let callers avoid a verbose
 * {@code switch} on {@link #getVerdict()}.</p>
 */
public final class PolicyResult {

    static final ObjectMapper MAPPER = new ObjectMapper();

    private final Verdict               verdict;
    private final String                reason;
    private final List<Integer>         triggeredRules;
    private final List<Violation>       violations;
    private final List<ConstraintViolation> constraintViolations;
    private final long                  latencyMicroseconds;

    public PolicyResult(
            @JsonProperty("verdict")               Verdict                   verdict,
            @JsonProperty("reason")                String                    reason,
            @JsonProperty("triggered_rules")       List<Integer>             triggeredRules,
            @JsonProperty("violations")            List<Violation>           violations,
            @JsonProperty("constraint_violations") List<ConstraintViolation> constraintViolations,
            @JsonProperty("latency_us")            long                      latencyMicroseconds) {
        this.verdict              = verdict != null ? verdict : Verdict.ALLOW;
        this.reason               = reason;
        this.triggeredRules       = triggeredRules       != null ? Collections.unmodifiableList(triggeredRules)       : List.of();
        this.violations           = violations           != null ? Collections.unmodifiableList(violations)           : List.of();
        this.constraintViolations = constraintViolations != null ? Collections.unmodifiableList(constraintViolations) : List.of();
        this.latencyMicroseconds  = latencyMicroseconds;
    }

    // ── Factory ───────────────────────────────────────────────────────────────

    /**
     * Deserialise a {@code PolicyResult} from the JSON string returned by the
     * native JNI bridge.
     */
    static PolicyResult fromJson(String json) {
        try {
            return MAPPER.readValue(json, PolicyResult.class);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to parse PolicyResult JSON: " + json, e);
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /** The final policy verdict for this event. */
    public Verdict getVerdict() { return verdict; }

    /**
     * Human-readable denial reason, or {@code null} if none was supplied by
     * the matched rule.
     */
    public String getReason() { return reason; }

    /** IDs of the rules that matched this event. */
    public List<Integer> getTriggeredRules() { return triggeredRules; }

    /** Temporal invariant violations detected during evaluation. */
    public List<Violation> getViolations() { return violations; }

    /** Rate-limit or quota constraint violations. */
    public List<ConstraintViolation> getConstraintViolations() { return constraintViolations; }

    /** Evaluation latency in microseconds. */
    public long getLatencyMicroseconds() { return latencyMicroseconds; }

    // ── Convenience predicates ────────────────────────────────────────────────

    /** {@code true} when the verdict is {@link Verdict#ALLOW}. */
    public boolean isAllowed() { return verdict == Verdict.ALLOW; }

    /** {@code true} when the verdict is {@link Verdict#DENY}. */
    public boolean isDenied() { return verdict == Verdict.DENY; }

    /** {@code true} when the verdict is {@link Verdict#AUDIT}. */
    public boolean isAudited() { return verdict == Verdict.AUDIT; }

    /** {@code true} when the verdict is {@link Verdict#REDACT}. */
    public boolean isRedacted() { return verdict == Verdict.REDACT; }

    @Override
    public String toString() {
        return "PolicyResult{verdict=" + verdict + ", reason=" + reason + "}";
    }
}

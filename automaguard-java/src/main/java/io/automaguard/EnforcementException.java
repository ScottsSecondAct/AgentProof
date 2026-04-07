package io.automaguard;

/**
 * Thrown when policy evaluation returns a {@link Verdict#DENY} verdict.
 *
 * <p>The full {@link PolicyResult} is attached so callers can inspect
 * triggered rules, invariant violations, and the denial reason without
 * consulting a separate log stream.</p>
 *
 * <pre>{@code
 * try {
 *     String result = client.prompt(prompt).call().content();
 * } catch (EnforcementException ex) {
 *     System.err.println("Blocked: " + ex.getMessage());
 *     ex.getResult().getViolations().forEach(v ->
 *         System.err.println("  Invariant: " + v));
 * }
 * }</pre>
 */
public final class EnforcementException extends RuntimeException {

    private final PolicyResult result;

    /**
     * Construct from a {@link PolicyResult} with a {@link Verdict#DENY} verdict.
     * The exception message is the denial reason, or a generic fallback if none
     * was provided.
     */
    public EnforcementException(PolicyResult result) {
        super(result.getReason() != null
                ? result.getReason()
                : "Policy denied: " + result.getVerdict());
        this.result = result;
    }

    /**
     * Construct with a custom message alongside the full result.
     */
    public EnforcementException(String message, PolicyResult result) {
        super(message);
        this.result = result;
    }

    /** The full evaluation result that triggered this exception. */
    public PolicyResult getResult() { return result; }
}

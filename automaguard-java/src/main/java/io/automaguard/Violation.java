package io.automaguard;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A temporal invariant violation detected during event evaluation.
 *
 * <p>Violations are included in a {@link PolicyResult} whenever a compiled
 * state machine reaches a violated terminal state (e.g. the {@code NoPIIExfiltration}
 * invariant is triggered).</p>
 */
public final class Violation {

    private final String proof;
    private final String invariant;
    private final String message;

    public Violation(
            @JsonProperty("proof")     String proof,
            @JsonProperty("invariant") String invariant,
            @JsonProperty("message")   String message) {
        this.proof     = proof     != null ? proof     : "";
        this.invariant = invariant != null ? invariant : "";
        this.message   = message   != null ? message   : "";
    }

    /** Name of the {@code proof} block that owns this invariant. */
    public String getProof() { return proof; }

    /** Name of the violated invariant. */
    public String getInvariant() { return invariant; }

    /** Human-readable description of why the invariant was violated. */
    public String getMessage() { return message; }

    @Override
    public String toString() {
        return proof + "/" + invariant + ": " + message;
    }
}

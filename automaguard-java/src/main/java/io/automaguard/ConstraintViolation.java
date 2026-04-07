package io.automaguard;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A rate-limit or quota constraint violation detected during event evaluation.
 */
public final class ConstraintViolation {

    private final String kind;
    private final String target;
    private final long   limit;
    private final long   current;
    private final long   windowMs;

    public ConstraintViolation(
            @JsonProperty("kind")      String kind,
            @JsonProperty("target")    String target,
            @JsonProperty("limit")     long   limit,
            @JsonProperty("current")   long   current,
            @JsonProperty("window_ms") long   windowMs) {
        this.kind     = kind   != null ? kind   : "";
        this.target   = target != null ? target : "";
        this.limit    = limit;
        this.current  = current;
        this.windowMs = windowMs;
    }

    /** Constraint kind — e.g. {@code "RateLimit"} or {@code "Quota"}. */
    public String getKind() { return kind; }

    /** The event type the constraint applies to. */
    public String getTarget() { return target; }

    /** Configured event limit within the window. */
    public long getLimit() { return limit; }

    /** Current event count within the sliding window. */
    public long getCurrent() { return current; }

    /** Sliding window duration in milliseconds. */
    public long getWindowMs() { return windowMs; }

    @Override
    public String toString() {
        return kind + " on '" + target + "': " + current + "/" + limit
                + " in " + windowMs + "ms window";
    }
}

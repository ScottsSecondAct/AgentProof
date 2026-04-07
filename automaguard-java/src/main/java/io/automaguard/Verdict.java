package io.automaguard;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The four possible outcomes of policy evaluation.
 *
 * <ul>
 *   <li>{@link #ALLOW}  — the event is allowed to proceed.</li>
 *   <li>{@link #DENY}   — the event is blocked; the action must not be executed.</li>
 *   <li>{@link #AUDIT}  — the event is allowed but flagged for audit logging.</li>
 *   <li>{@link #REDACT} — the event is allowed but the response must be sanitised.</li>
 * </ul>
 */
public enum Verdict {
    ALLOW("allow"),
    DENY("deny"),
    AUDIT("audit"),
    REDACT("redact");

    private final String jsonValue;

    Verdict(String jsonValue) {
        this.jsonValue = jsonValue;
    }

    @JsonValue
    public String toJsonValue() {
        return jsonValue;
    }

    @JsonCreator
    public static Verdict fromJsonValue(String value) {
        if (value == null) {
            throw new IllegalArgumentException("verdict must not be null");
        }
        return switch (value) {
            case "allow"  -> ALLOW;
            case "deny"   -> DENY;
            case "audit"  -> AUDIT;
            case "redact" -> REDACT;
            default -> throw new IllegalArgumentException("Unknown verdict: '" + value + "'");
        };
    }
}

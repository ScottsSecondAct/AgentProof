package io.automaguard;

import java.util.List;

/** Shared test fixtures — pre-built {@link PolicyResult} instances. */
final class Fixtures {

    static final PolicyResult ALLOW_RESULT = new PolicyResult(
            Verdict.ALLOW, null, List.of(), List.of(), List.of(), 3L);

    static final PolicyResult DENY_RESULT = new PolicyResult(
            Verdict.DENY, "Tool \"exec\" is not allowed",
            List.of(0), List.of(), List.of(), 4L);

    static final PolicyResult AUDIT_RESULT = new PolicyResult(
            Verdict.AUDIT, "Flagged for audit",
            List.of(1), List.of(), List.of(), 2L);

    static final PolicyResult REDACT_RESULT = new PolicyResult(
            Verdict.REDACT, "PII detected in output",
            List.of(2), List.of(), List.of(), 5L);

    static final PolicyResult VIOLATION_RESULT = new PolicyResult(
            Verdict.DENY, "NoPIIExfiltration violated",
            List.of(0),
            List.of(new Violation("ExfiltrationGuard", "NoPIIExfiltration",
                    "PII data was followed by an external request")),
            List.of(), 6L);

    static final PolicyResult RATE_LIMIT_RESULT = new PolicyResult(
            Verdict.DENY, "Rate limit exceeded",
            List.of(),
            List.of(),
            List.of(new ConstraintViolation("RateLimit", "data_access", 20L, 21L, 60000L)),
            7L);

    private Fixtures() {}
}

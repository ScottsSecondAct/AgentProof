package io.automaguard;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests JSON deserialization of {@link PolicyResult} from the shape returned
 * by the native JNI bridge.
 */
class PolicyResultTest {

    @Test
    void fromJson_allowVerdict() {
        String json = """
                {"verdict":"allow","reason":null,"triggered_rules":[],"violations":[],
                 "constraint_violations":[],"latency_us":3}
                """;
        PolicyResult r = PolicyResult.fromJson(json);
        assertThat(r.getVerdict()).isEqualTo(Verdict.ALLOW);
        assertThat(r.getReason()).isNull();
        assertThat(r.getTriggeredRules()).isEmpty();
        assertThat(r.getLatencyMicroseconds()).isEqualTo(3L);
    }

    @Test
    void fromJson_denyWithReason() {
        String json = """
                {"verdict":"deny","reason":"DDL operations are prohibited",
                 "triggered_rules":[0],"violations":[],"constraint_violations":[],
                 "latency_us":4}
                """;
        PolicyResult r = PolicyResult.fromJson(json);
        assertThat(r.getVerdict()).isEqualTo(Verdict.DENY);
        assertThat(r.getReason()).isEqualTo("DDL operations are prohibited");
        assertThat(r.getTriggeredRules()).containsExactly(0);
        assertThat(r.isDenied()).isTrue();
    }

    @Test
    void fromJson_auditVerdict() {
        String json = """
                {"verdict":"audit","reason":"PII record accessed",
                 "triggered_rules":[1],"violations":[],"constraint_violations":[],
                 "latency_us":2}
                """;
        PolicyResult r = PolicyResult.fromJson(json);
        assertThat(r.isAudited()).isTrue();
        assertThat(r.getReason()).isEqualTo("PII record accessed");
    }

    @Test
    void fromJson_redactVerdict() {
        PolicyResult r = PolicyResult.fromJson(
                """
                {"verdict":"redact","reason":"PII in output","triggered_rules":[2],
                 "violations":[],"constraint_violations":[],"latency_us":5}
                """);
        assertThat(r.isRedacted()).isTrue();
    }

    @Test
    void fromJson_withViolations() {
        String json = """
                {"verdict":"deny","reason":"NoPIIExfiltration violated",
                 "triggered_rules":[0],
                 "violations":[
                   {"proof":"ExfiltrationGuard","invariant":"NoPIIExfiltration",
                    "message":"PII accessed then external request sent"}
                 ],
                 "constraint_violations":[],"latency_us":6}
                """;
        PolicyResult r = PolicyResult.fromJson(json);
        assertThat(r.getViolations()).hasSize(1);
        Violation v = r.getViolations().get(0);
        assertThat(v.getProof()).isEqualTo("ExfiltrationGuard");
        assertThat(v.getInvariant()).isEqualTo("NoPIIExfiltration");
        assertThat(v.getMessage()).isEqualTo("PII accessed then external request sent");
    }

    @Test
    void fromJson_withConstraintViolation() {
        String json = """
                {"verdict":"deny","reason":"Rate limit exceeded","triggered_rules":[],
                 "violations":[],
                 "constraint_violations":[
                   {"kind":"RateLimit","target":"data_access","limit":20,
                    "current":21,"window_ms":60000}
                 ],
                 "latency_us":7}
                """;
        PolicyResult r = PolicyResult.fromJson(json);
        assertThat(r.getConstraintViolations()).hasSize(1);
        ConstraintViolation cv = r.getConstraintViolations().get(0);
        assertThat(cv.getKind()).isEqualTo("RateLimit");
        assertThat(cv.getTarget()).isEqualTo("data_access");
        assertThat(cv.getLimit()).isEqualTo(20L);
        assertThat(cv.getCurrent()).isEqualTo(21L);
        assertThat(cv.getWindowMs()).isEqualTo(60_000L);
    }

    @Test
    void fromJson_unknownVerdictThrows() {
        String json = """
                {"verdict":"block","reason":null,"triggered_rules":[],
                 "violations":[],"constraint_violations":[],"latency_us":1}
                """;
        assertThatThrownBy(() -> PolicyResult.fromJson(json))
                .isInstanceOf(Exception.class);
    }

    @Test
    void fromJson_invalidJsonThrows() {
        assertThatThrownBy(() -> PolicyResult.fromJson("{not valid json"))
                .isInstanceOf(Exception.class);
    }

    @Test
    void violationToString_includesProofAndInvariant() {
        var v = new Violation("ExfiltrationGuard", "NoPIIExfiltration", "test message");
        assertThat(v.toString())
                .contains("ExfiltrationGuard")
                .contains("NoPIIExfiltration")
                .contains("test message");
    }

    @Test
    void constraintViolationToString_includesKindAndTarget() {
        var cv = new ConstraintViolation("RateLimit", "data_access", 20, 21, 60000);
        assertThat(cv.toString())
                .contains("RateLimit")
                .contains("data_access");
    }
}

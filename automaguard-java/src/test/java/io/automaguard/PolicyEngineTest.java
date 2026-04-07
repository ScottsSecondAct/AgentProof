package io.automaguard;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.*;

class PolicyEngineTest {

    // ── getPolicyName ─────────────────────────────────────────────────────────

    @Test
    void policyName_returnsBridgePolicyName() {
        var fake = new FakeNativeBridge();
        fake.policyNameValue = "CustomerDataGuard";
        var engine = new PolicyEngine(fake, 1L);

        assertThat(engine.getPolicyName()).isEqualTo("CustomerDataGuard");
    }

    // ── evaluate ──────────────────────────────────────────────────────────────

    @Test
    void evaluate_returnsResultFromBridge() {
        var fake = new FakeNativeBridge();
        fake.nextResult = Fixtures.DENY_RESULT;
        var engine = new PolicyEngine(fake, 1L);

        PolicyResult result = engine.evaluate("tool_call", Map.of("tool_name", "exec"));

        assertThat(result.getVerdict()).isEqualTo(Verdict.DENY);
        assertThat(result.getReason()).isEqualTo("Tool \"exec\" is not allowed");
    }

    @Test
    void evaluate_forwardsEventTypeAndFieldsJson() {
        var fake = new FakeNativeBridge();
        var engine = new PolicyEngine(fake, 1L);

        engine.evaluate("data_access", Map.of("classification", "PII", "record_id", "42"));

        assertThat(fake.evaluateCalls).hasSize(1);
        assertThat(fake.evaluateCalls.get(0)[0]).isEqualTo("data_access");
        assertThat(fake.evaluateCalls.get(0)[1]).contains("classification");
        assertThat(fake.evaluateCalls.get(0)[1]).contains("PII");
    }

    @Test
    void evaluate_withNoFields_passesNullJson() {
        var fake = new FakeNativeBridge();
        var engine = new PolicyEngine(fake, 1L);

        engine.evaluate("session_start", null);

        assertThat(fake.evaluateCalls).hasSize(1);
        assertThat(fake.evaluateCalls.get(0)[1]).isNull();
    }

    @Test
    void evaluate_withEmptyFields_passesNullJson() {
        var fake = new FakeNativeBridge();
        var engine = new PolicyEngine(fake, 1L);

        engine.evaluate("session_start", Map.of());

        assertThat(fake.evaluateCalls.get(0)[1]).isNull();
    }

    @Test
    void evaluate_incrementsEventCount() {
        var fake = new FakeNativeBridge();
        var engine = new PolicyEngine(fake, 1L);

        engine.evaluate("tool_call");
        engine.evaluate("tool_call");

        assertThat(engine.getEventCount()).isEqualTo(2);
    }

    // ── reset ─────────────────────────────────────────────────────────────────

    @Test
    void reset_callsBridgeResetAndClearsEventCount() {
        var fake = new FakeNativeBridge();
        var engine = new PolicyEngine(fake, 1L);

        engine.evaluate("tool_call");
        engine.reset();

        assertThat(fake.resetCallCount).isEqualTo(1);
        assertThat(engine.getEventCount()).isEqualTo(0);
    }

    // ── close ─────────────────────────────────────────────────────────────────

    @Test
    void close_freesBridgeHandle() {
        var fake = new FakeNativeBridge();
        var engine = new PolicyEngine(fake, 1L);

        engine.close();

        assertThat(fake.freed).isTrue();
    }

    @Test
    void close_isIdempotent() {
        var fake = new FakeNativeBridge();
        var engine = new PolicyEngine(fake, 1L);

        engine.close();
        engine.close(); // must not throw

        assertThat(fake.freed).isTrue();
    }

    @Test
    void evaluate_afterClose_throwsIllegalState() {
        var fake = new FakeNativeBridge();
        var engine = new PolicyEngine(fake, 1L);
        engine.close();

        assertThatThrownBy(() -> engine.evaluate("tool_call"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("closed");
    }

    // ── convenience predicates ────────────────────────────────────────────────

    @Test
    void allowResult_predicates() {
        var fake = new FakeNativeBridge();
        fake.nextResult = Fixtures.ALLOW_RESULT;
        var engine = new PolicyEngine(fake, 1L);

        PolicyResult r = engine.evaluate("tool_call");

        assertThat(r.isAllowed()).isTrue();
        assertThat(r.isDenied()).isFalse();
        assertThat(r.isAudited()).isFalse();
        assertThat(r.isRedacted()).isFalse();
    }

    @Test
    void denyResult_predicates() {
        var fake = new FakeNativeBridge();
        fake.nextResult = Fixtures.DENY_RESULT;
        var engine = new PolicyEngine(fake, 1L);

        PolicyResult r = engine.evaluate("tool_call");

        assertThat(r.isDenied()).isTrue();
        assertThat(r.isAllowed()).isFalse();
    }

    @Test
    void auditResult_triggeredRulesPopulated() {
        var fake = new FakeNativeBridge();
        fake.nextResult = Fixtures.AUDIT_RESULT;
        var engine = new PolicyEngine(fake, 1L);

        PolicyResult r = engine.evaluate("data_access");

        assertThat(r.isAudited()).isTrue();
        assertThat(r.getTriggeredRules()).containsExactly(1);
    }

    @Test
    void violationResult_violationsPopulated() {
        var fake = new FakeNativeBridge();
        fake.nextResult = Fixtures.VIOLATION_RESULT;
        var engine = new PolicyEngine(fake, 1L);

        PolicyResult r = engine.evaluate("external_request");

        assertThat(r.isDenied()).isTrue();
        assertThat(r.getViolations()).hasSize(1);
        assertThat(r.getViolations().get(0).getProof()).isEqualTo("ExfiltrationGuard");
        assertThat(r.getViolations().get(0).getInvariant()).isEqualTo("NoPIIExfiltration");
    }

    @Test
    void rateLimitResult_constraintViolationsPopulated() {
        var fake = new FakeNativeBridge();
        fake.nextResult = Fixtures.RATE_LIMIT_RESULT;
        var engine = new PolicyEngine(fake, 1L);

        PolicyResult r = engine.evaluate("data_access");

        assertThat(r.isDenied()).isTrue();
        assertThat(r.getConstraintViolations()).hasSize(1);
        assertThat(r.getConstraintViolations().get(0).getTarget()).isEqualTo("data_access");
        assertThat(r.getConstraintViolations().get(0).getLimit()).isEqualTo(20L);
        assertThat(r.getConstraintViolations().get(0).getCurrent()).isEqualTo(21L);
    }

    // ── try-with-resources ────────────────────────────────────────────────────

    @Test
    void tryWithResources_closesEngine() {
        var fake = new FakeNativeBridge();
        try (var engine = new PolicyEngine(fake, 1L)) {
            engine.evaluate("tool_call");
        }
        assertThat(fake.freed).isTrue();
    }
}

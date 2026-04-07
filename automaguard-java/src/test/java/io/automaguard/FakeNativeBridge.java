package io.automaguard;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

/**
 * In-memory test double for {@link NativeBridge}.
 *
 * <p>Lets unit tests drive verdict outcomes and inspect call records without
 * loading the native {@code aegis_jni} binary.</p>
 */
final class FakeNativeBridge implements NativeBridge {

    private static final ObjectMapper MAPPER = PolicyResult.MAPPER;
    private static final long FAKE_HANDLE = 0xDEAD_BEEF_L;

    // ── Configurable responses ────────────────────────────────────────────────

    PolicyResult nextResult = Fixtures.ALLOW_RESULT;
    String policyNameValue = "TestPolicy";

    // ── Call records ──────────────────────────────────────────────────────────

    final List<String[]> evaluateCalls = new ArrayList<>();
    int resetCallCount = 0;
    boolean freed = false;

    // ── NativeBridge implementation ───────────────────────────────────────────

    @Override
    public long fromFile(String path) {
        return FAKE_HANDLE;
    }

    @Override
    public long fromBytes(byte[] data) {
        return FAKE_HANDLE;
    }

    @Override
    public String evaluate(long handle, String eventType, String fieldsJson) {
        evaluateCalls.add(new String[]{eventType, fieldsJson});
        try {
            return MAPPER.writeValueAsString(nextResult);
        } catch (Exception e) {
            throw new RuntimeException("FakeNativeBridge: failed to serialise result", e);
        }
    }

    @Override
    public String policyName(long handle) {
        return policyNameValue;
    }

    @Override
    public void reset(long handle) {
        resetCallCount++;
    }

    @Override
    public void free(long handle) {
        freed = true;
    }
}

package io.automaguard;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * AutomaGuard policy engine.
 *
 * <p>Load a compiled {@code .aegisc} policy <em>once</em> at agent startup,
 * then call {@link #evaluate(String, Map)} on each agent event.  Evaluation
 * is synchronous and typically completes in under 1 ms.  The engine is
 * thread-safe — the native Rust side is protected by a {@code Mutex}.</p>
 *
 * <p>Implements {@link AutoCloseable}; use in a try-with-resources block to
 * ensure the native engine handle is freed:</p>
 *
 * <pre>{@code
 * try (PolicyEngine engine = PolicyEngine.fromFile("guard.aegisc")) {
 *     PolicyResult result = engine.evaluate("tool_call", Map.of(
 *         "tool_name", "send_email",
 *         "arguments", Map.of("to", "user@example.com")
 *     ));
 *     if (result.isDenied()) {
 *         throw new EnforcementException(result);
 *     }
 * }
 * }</pre>
 */
public final class PolicyEngine implements AutoCloseable {

    private static final ObjectMapper MAPPER = PolicyResult.MAPPER;

    private final NativeBridge bridge;
    private final long handle;
    private final AtomicLong eventCount = new AtomicLong(0);
    private volatile boolean closed = false;

    /** Package-private constructor for production and testing. */
    PolicyEngine(NativeBridge bridge, long handle) {
        this.bridge = bridge;
        this.handle = handle;
    }

    // ── Factory methods ───────────────────────────────────────────────────────

    /**
     * Load a policy engine from a compiled {@code .aegisc} file.
     *
     * @param path absolute or relative path to the {@code .aegisc} file
     * @return a new {@code PolicyEngine}
     * @throws IOException if the file cannot be found or is not a valid policy
     */
    public static PolicyEngine fromFile(String path) throws IOException {
        if (path == null || path.isBlank()) {
            throw new IllegalArgumentException("path must not be null or blank");
        }
        NativeBridge bridge = new JniNativeBridge();
        long handle = bridge.fromFile(path);
        return new PolicyEngine(bridge, handle);
    }

    /**
     * Load a policy engine from raw {@code .aegisc} bytes (e.g. embedded as
     * a class-path resource).
     *
     * @param data compiled policy bytes
     * @return a new {@code PolicyEngine}
     * @throws IOException if the bytes cannot be parsed as a valid policy
     */
    public static PolicyEngine fromBytes(byte[] data) throws IOException {
        if (data == null) {
            throw new IllegalArgumentException("data must not be null");
        }
        NativeBridge bridge = new JniNativeBridge();
        long handle = bridge.fromBytes(data);
        return new PolicyEngine(bridge, handle);
    }

    // ── Properties ────────────────────────────────────────────────────────────

    /**
     * The policy name declared in the {@code .aegisc} file
     * ({@code policy <Name> \{…\}}).
     */
    public String getPolicyName() {
        ensureOpen();
        return bridge.policyName(handle);
    }

    /** Total events evaluated since creation or the last {@link #reset()}. */
    public long getEventCount() { return eventCount.get(); }

    // ── Core API ──────────────────────────────────────────────────────────────

    /**
     * Evaluate a single agent event against the loaded policy.
     *
     * @param eventType event type string (e.g. {@code "tool_call"},
     *                  {@code "data_access"}, {@code "external_request"})
     * @param fields    event field map; values must be JSON-serialisable.
     *                  Pass {@code null} or an empty map for events with no fields.
     * @return the {@link PolicyResult} containing verdict, triggered rules, and
     *         any violations
     */
    public PolicyResult evaluate(String eventType, Map<String, Object> fields) {
        if (eventType == null || eventType.isBlank()) {
            throw new IllegalArgumentException("eventType must not be null or blank");
        }
        ensureOpen();

        String fieldsJson = null;
        if (fields != null && !fields.isEmpty()) {
            try {
                fieldsJson = MAPPER.writeValueAsString(fields);
            } catch (Exception e) {
                throw new RuntimeException("Failed to serialise event fields to JSON", e);
            }
        }

        String resultJson = bridge.evaluate(handle, eventType, fieldsJson);
        eventCount.incrementAndGet();
        return PolicyResult.fromJson(resultJson);
    }

    /**
     * Evaluate an event with no additional fields.
     *
     * @param eventType event type string
     * @return the {@link PolicyResult}
     */
    public PolicyResult evaluate(String eventType) {
        return evaluate(eventType, null);
    }

    /**
     * Reset all state machines and rate-limit counters to their initial states.
     *
     * <p>Call this at the start of a new agent session to isolate per-session
     * temporal invariants and rate limits.</p>
     */
    public void reset() {
        ensureOpen();
        bridge.reset(handle);
        eventCount.set(0);
    }

    // ── AutoCloseable ─────────────────────────────────────────────────────────

    /**
     * Release the native engine handle.
     *
     * <p>After closing, any call to this instance will throw
     * {@link IllegalStateException}.  Closing is idempotent.</p>
     */
    @Override
    public void close() {
        if (!closed) {
            closed = true;
            bridge.free(handle);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("PolicyEngine has been closed");
        }
    }
}

package io.automaguard;

/**
 * Abstraction over the JNI boundary, injected into {@link PolicyEngine}.
 *
 * <p>The production implementation ({@link JniNativeBridge}) calls the native
 * Rust library.  Tests inject a {@code FakeNativeBridge} so that unit tests
 * run without the compiled native binary present.</p>
 *
 * <p>All methods return results on success and throw on error.  Callers must
 * never pass {@code 0} as a {@code handle} argument.</p>
 */
interface NativeBridge {

    /**
     * Load a compiled {@code .aegisc} policy from a file path.
     *
     * @param path absolute or relative path to the policy file
     * @return an opaque non-zero engine handle
     * @throws java.io.IOException if the file cannot be loaded
     */
    long fromFile(String path) throws java.io.IOException;

    /**
     * Load a compiled {@code .aegisc} policy from an in-memory byte array.
     *
     * @param data policy bytecode
     * @return an opaque non-zero engine handle
     * @throws java.io.IOException if the bytes cannot be parsed
     */
    long fromBytes(byte[] data) throws java.io.IOException;

    /**
     * Evaluate a single agent event against the loaded policy.
     *
     * @param handle     engine handle
     * @param eventType  event type string (e.g. {@code "tool_call"})
     * @param fieldsJson JSON object of field name → value pairs, or {@code null}
     * @return JSON string conforming to the {@link PolicyResult} schema
     */
    String evaluate(long handle, String eventType, String fieldsJson);

    /**
     * Return the policy name declared in the {@code .aegisc} file.
     *
     * @param handle engine handle
     * @return policy name
     */
    String policyName(long handle);

    /**
     * Reset all state machines and rate-limit counters to initial states.
     *
     * @param handle engine handle
     */
    void reset(long handle);

    /**
     * Free the engine handle.  Must be called exactly once per handle.
     *
     * @param handle engine handle
     */
    void free(long handle);
}

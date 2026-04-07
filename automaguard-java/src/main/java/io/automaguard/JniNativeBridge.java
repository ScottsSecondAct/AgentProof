package io.automaguard;

import java.io.IOException;

/**
 * Production {@link NativeBridge} implementation that calls the compiled Rust
 * {@code aegis_jni} library via JNI.
 *
 * <p>The class static initialiser triggers {@link NativeLoader#ensureLoaded()}
 * so that the native library is ready before any method is called.</p>
 */
final class JniNativeBridge implements NativeBridge {

    static {
        NativeLoader.ensureLoaded();
    }

    // ── NativeBridge implementation ───────────────────────────────────────────

    @Override
    public long fromFile(String path) throws IOException {
        long handle = nativeFromFile(path);
        if (handle == 0) {
            throw new IOException("Failed to load policy from '" + path + "'");
        }
        return handle;
    }

    @Override
    public long fromBytes(byte[] data) throws IOException {
        long handle = nativeFromBytes(data);
        if (handle == 0) {
            throw new IOException("Failed to load policy from bytes");
        }
        return handle;
    }

    @Override
    public String evaluate(long handle, String eventType, String fieldsJson) {
        String result = nativeEvaluate(handle, eventType, fieldsJson);
        if (result == null) {
            throw new RuntimeException("Native evaluate returned null for event type '" + eventType + "'");
        }
        return result;
    }

    @Override
    public String policyName(long handle) {
        return nativePolicyName(handle);
    }

    @Override
    public void reset(long handle) {
        nativeReset(handle);
    }

    @Override
    public void free(long handle) {
        if (handle != 0) {
            nativeFree(handle);
        }
    }

    // ── JNI declarations ─────────────────────────────────────────────────────

    private static native long   nativeFromFile(String path);
    private static native long   nativeFromBytes(byte[] data);
    private static native String nativeEvaluate(long handle, String eventType, String fieldsJson);
    private static native String nativePolicyName(long handle);
    private static native void   nativeReset(long handle);
    private static native void   nativeFree(long handle);
}

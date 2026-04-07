package io.automaguard;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Loads the {@code aegis_jni} native library from the JAR resources at startup.
 *
 * <p>The library is expected to be bundled under
 * {@code native/<os>/<arch>/libaegis_jni.{so,dylib}} (or {@code aegis_jni.dll}
 * on Windows) in the JAR.  If it cannot be found there, a fallback to
 * {@code java.library.path} is attempted.</p>
 *
 * <p>Call {@link #ensureLoaded()} once before any JNI call; subsequent
 * invocations are no-ops.</p>
 */
final class NativeLoader {

    private static volatile boolean loaded = false;
    private static final Object LOCK = new Object();

    /** Ensure the native library is loaded.  Safe to call concurrently. */
    static void ensureLoaded() {
        if (loaded) return;
        synchronized (LOCK) {
            if (loaded) return;
            doLoad();
            loaded = true;
        }
    }

    private static void doLoad() {
        // 1. Try loading from JAR resources first.
        try {
            loadFromJar();
            return;
        } catch (IOException | UnsatisfiedLinkError ignored) {
            // Fall through to java.library.path resolution.
        }
        // 2. Fallback: let the JVM search java.library.path.
        System.loadLibrary("aegis_jni");
    }

    private static void loadFromJar() throws IOException {
        String resourcePath = "/native/" + osName() + "/" + archName() + "/" + libFileName();
        try (InputStream in = NativeLoader.class.getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new IOException("Native library not found in JAR at " + resourcePath);
            }
            // Extract to a temp file; delete-on-exit ensures cleanup.
            Path tmp = Files.createTempFile("aegis_jni_", libExtension());
            tmp.toFile().deleteOnExit();
            try (OutputStream out = Files.newOutputStream(tmp)) {
                in.transferTo(out);
            }
            System.load(tmp.toAbsolutePath().toString());
        }
    }

    // ── Platform detection ────────────────────────────────────────────────────

    private static String osName() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("linux"))   return "linux";
        if (os.contains("mac"))     return "macos";
        if (os.contains("windows")) return "windows";
        throw new UnsatisfiedLinkError("Unsupported OS: " + os);
    }

    private static String archName() {
        String arch = System.getProperty("os.arch", "").toLowerCase();
        if (arch.equals("amd64") || arch.equals("x86_64")) return "x86_64";
        if (arch.equals("aarch64") || arch.equals("arm64")) return "aarch64";
        throw new UnsatisfiedLinkError("Unsupported architecture: " + arch);
    }

    private static String libFileName() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("windows")) return "aegis_jni.dll";
        if (os.contains("mac"))     return "libaegis_jni.dylib";
        return "libaegis_jni.so";
    }

    private static String libExtension() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("windows")) return ".dll";
        if (os.contains("mac"))     return ".dylib";
        return ".so";
    }

    private NativeLoader() {}
}

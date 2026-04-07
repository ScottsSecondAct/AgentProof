using System.Runtime.InteropServices;
using System.Text.Json;

namespace AutomaGuard;

/// <summary>
/// Production implementation of <see cref="INativeEngine"/> backed by P/Invoke
/// calls into the <c>aegis-ffi</c> C library.
/// </summary>
internal sealed class RealNativeEngine : INativeEngine
{
    private IntPtr _handle;
    private bool _disposed;

    /// <summary>Load a policy from a <c>.aegisc</c> file path.</summary>
    internal RealNativeEngine(string path)
    {
        NativeLibraryLoader.EnsureRegistered();
        _handle = NativeMethods.aegis_engine_from_file(path);
        if (_handle == IntPtr.Zero)
            throw new InvalidOperationException(
                $"Failed to load policy from '{path}': {NativeMethods.GetLastError()}");
    }

    /// <summary>Load a policy from raw <c>.aegisc</c> bytes.</summary>
    internal RealNativeEngine(byte[] bytes)
    {
        NativeLibraryLoader.EnsureRegistered();
        _handle = NativeMethods.aegis_engine_from_bytes(bytes, (nuint)bytes.Length);
        if (_handle == IntPtr.Zero)
            throw new InvalidOperationException(
                $"Failed to load policy from bytes: {NativeMethods.GetLastError()}");
    }

    // ── INativeEngine ─────────────────────────────────────────────────────────

    public string PolicyName
    {
        get
        {
            ThrowIfDisposed();
            IntPtr ptr = NativeMethods.aegis_engine_policy_name(_handle);
            return NativeMethods.ConsumeString(ptr, useResultFree: false);
        }
    }

    public PolicyResult Evaluate(string eventType, string? fieldsJson)
    {
        ThrowIfDisposed();

        IntPtr resultPtr = NativeMethods.aegis_engine_evaluate(_handle, eventType, fieldsJson);
        if (resultPtr == IntPtr.Zero)
            throw new InvalidOperationException(
                $"Evaluation failed: {NativeMethods.GetLastError()}");

        string json = NativeMethods.ConsumeString(resultPtr, useResultFree: true);
        return JsonSerializer.Deserialize<PolicyResult>(json, JsonOptions.Default)
               ?? throw new InvalidOperationException("Native engine returned empty result.");
    }

    public void SetContext(string key, string valueJson)
    {
        ThrowIfDisposed();
        NativeMethods.aegis_engine_set_context(_handle, key, valueJson);
    }

    public void SetConfig(string key, string valueJson)
    {
        ThrowIfDisposed();
        NativeMethods.aegis_engine_set_config(_handle, key, valueJson);
    }

    public void Reset()
    {
        ThrowIfDisposed();
        NativeMethods.aegis_engine_reset(_handle);
    }

    public EngineStatus Status()
    {
        ThrowIfDisposed();
        IntPtr ptr = NativeMethods.aegis_engine_status(_handle);
        if (ptr == IntPtr.Zero)
            throw new InvalidOperationException(
                $"Status query failed: {NativeMethods.GetLastError()}");

        string json = NativeMethods.ConsumeString(ptr, useResultFree: true);
        return JsonSerializer.Deserialize<EngineStatus>(json, JsonOptions.Default)
               ?? throw new InvalidOperationException("Native engine returned empty status.");
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (_handle != IntPtr.Zero)
        {
            NativeMethods.aegis_engine_free(_handle);
            _handle = IntPtr.Zero;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(PolicyEngine));
    }
}

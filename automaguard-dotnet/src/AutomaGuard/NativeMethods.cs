using System.Runtime.InteropServices;

namespace AutomaGuard;

/// <summary>
/// P/Invoke declarations for the <c>aegis-ffi</c> C library.
///
/// All functions use the C calling convention and UTF-8 string encoding.
/// Heap-allocated return values (char*) must be freed with
/// <see cref="aegis_result_free"/> or <see cref="aegis_string_free"/>.
/// </summary>
internal static partial class NativeMethods
{
    /// <summary>Native library name — platform suffix is resolved automatically.</summary>
    internal const string LibName = "aegis";

    // ── Engine lifecycle ──────────────────────────────────────────────────────

    /// <summary>
    /// Load a compiled policy from a <c>.aegisc</c> file path.
    /// Returns <see cref="IntPtr.Zero"/> on error; call <see cref="aegis_last_error"/> for the message.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr aegis_engine_from_file(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path);

    /// <summary>
    /// Load a compiled policy from an in-memory byte buffer.
    /// Returns <see cref="IntPtr.Zero"/> on error.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr aegis_engine_from_bytes(
        byte[] data,
        nuint len);

    /// <summary>Free an engine handle returned by a factory function.</summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void aegis_engine_free(IntPtr engine);

    // ── Event evaluation ──────────────────────────────────────────────────────

    /// <summary>
    /// Evaluate a single agent event.
    /// Returns a heap-allocated UTF-8 JSON string (<see cref="PolicyResult"/> shape).
    /// The caller must free the result with <see cref="aegis_result_free"/>.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr aegis_engine_evaluate(
        IntPtr engine,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string event_type,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? fields_json);

    /// <summary>Free a result string returned by <see cref="aegis_engine_evaluate"/>.</summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void aegis_result_free(IntPtr result);

    // ── Context and config ────────────────────────────────────────────────────

    /// <summary>
    /// Set a persistent context value accessible in policy expressions as
    /// <c>context.&lt;key&gt;</c>. <paramref name="value_json"/> is a UTF-8
    /// JSON-encoded value.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void aegis_engine_set_context(
        IntPtr engine,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string key,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string value_json);

    /// <summary>
    /// Set a policy configuration value accessible in policy expressions as
    /// <c>config.&lt;key&gt;</c>.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void aegis_engine_set_config(
        IntPtr engine,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string key,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string value_json);

    // ── State management ──────────────────────────────────────────────────────

    /// <summary>
    /// Reset all state machines and rate-limit counters to their initial states.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void aegis_engine_reset(IntPtr engine);

    // ── Metadata ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Return the policy name declared in the <c>.aegisc</c> file.
    /// The returned string is heap-allocated and must be freed with
    /// <see cref="aegis_string_free"/>.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr aegis_engine_policy_name(IntPtr engine);

    /// <summary>
    /// Return a JSON snapshot of the engine's operational status.
    /// Heap-allocated; free with <see cref="aegis_result_free"/>.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr aegis_engine_status(IntPtr engine);

    /// <summary>Free a string returned by <see cref="aegis_engine_policy_name"/>.</summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void aegis_string_free(IntPtr str);

    // ── Error handling ────────────────────────────────────────────────────────

    /// <summary>
    /// Return the last error message for this thread.
    /// The pointer is valid until the next call on this thread; do not free it.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr aegis_last_error();

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>Read the last error string from native memory.</summary>
    internal static string GetLastError()
    {
        IntPtr ptr = aegis_last_error();
        return ptr == IntPtr.Zero
            ? "Unknown native error"
            : Marshal.PtrToStringUTF8(ptr) ?? "Unknown native error";
    }

    /// <summary>
    /// Read a heap-allocated UTF-8 string from native memory and free it.
    /// </summary>
    internal static string ConsumeString(IntPtr ptr, bool useResultFree = true)
    {
        if (ptr == IntPtr.Zero)
            return string.Empty;

        string value = Marshal.PtrToStringUTF8(ptr) ?? string.Empty;

        if (useResultFree)
            aegis_result_free(ptr);
        else
            aegis_string_free(ptr);

        return value;
    }
}

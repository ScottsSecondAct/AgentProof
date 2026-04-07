using System.Text.Json;
using System.Threading;

namespace AutomaGuard;

/// <summary>
/// AutomaGuard policy engine.
///
/// Load a compiled <c>.aegisc</c> policy <b>once</b> at agent startup, then
/// call <see cref="Evaluate"/> on each agent event. Evaluation is synchronous
/// and typically completes in under 1 ms. The engine is thread-safe — the
/// native Rust side is protected by a <c>Mutex</c>.
///
/// <example>
/// <code>
/// using var engine = PolicyEngine.FromFile("guard.aegisc");
///
/// var result = engine.Evaluate("tool_call", new Dictionary&lt;string, object?&gt;
/// {
///     ["tool_name"] = "send_email",
///     ["arguments"] = new { to = "user@example.com" },
/// });
///
/// if (result.Verdict == Verdict.Deny)
///     throw new EnforcementException(result);
/// </code>
/// </example>
/// </summary>
public sealed class PolicyEngine : IDisposable
{
    private readonly INativeEngine _native;
    private long _eventCount;
    private bool _disposed;

    /// <summary>Internal constructor — accepts any <see cref="INativeEngine"/> (real or mock).</summary>
    internal PolicyEngine(INativeEngine native)
    {
        _native = native;
    }

    // ── Factory methods ───────────────────────────────────────────────────────

    /// <summary>
    /// Load a policy engine from a compiled <c>.aegisc</c> file.
    /// </summary>
    /// <param name="path">Absolute or relative path to the <c>.aegisc</c> file.</param>
    /// <exception cref="InvalidOperationException">
    /// The file does not exist or is not a valid compiled policy.
    /// </exception>
    public static PolicyEngine FromFile(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        return new PolicyEngine(new RealNativeEngine(path));
    }

    /// <summary>
    /// Load a policy engine from raw <c>.aegisc</c> bytes (e.g. embedded as
    /// an assembly resource).
    /// </summary>
    /// <param name="data">Compiled policy bytes.</param>
    /// <exception cref="InvalidOperationException">
    /// The buffer is not a valid compiled policy.
    /// </exception>
    public static PolicyEngine FromBytes(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return new PolicyEngine(new RealNativeEngine(data));
    }

    // ── Properties ────────────────────────────────────────────────────────────

    /// <summary>The policy name declared in the <c>.aegisc</c> file (<c>policy Name { }</c>).</summary>
    public string PolicyName
    {
        get
        {
            ThrowIfDisposed();
            return _native.PolicyName;
        }
    }

    /// <summary>Total events evaluated since creation or the last <see cref="Reset"/>.</summary>
    public long EventCount => Interlocked.Read(ref _eventCount);

    // ── Core API ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Evaluate a single agent event against the loaded policy.
    /// </summary>
    /// <param name="eventType">
    /// Event type string (e.g. <c>"tool_call"</c>, <c>"data_access"</c>).
    /// </param>
    /// <param name="fields">
    /// Arbitrary event fields. Pass <see langword="null"/> or omit for events
    /// with no fields. Values are serialised to JSON before being passed to
    /// the native engine.
    /// </param>
    /// <returns>
    /// A <see cref="PolicyResult"/> containing the verdict, triggered rules,
    /// and any violations.
    /// </returns>
    public PolicyResult Evaluate(
        string eventType,
        IReadOnlyDictionary<string, object?>? fields = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(eventType);
        ThrowIfDisposed();

        string? fieldsJson = fields is null or { Count: 0 }
            ? null
            : JsonSerializer.Serialize(fields, JsonOptions.Default);

        PolicyResult result = _native.Evaluate(eventType, fieldsJson);
        Interlocked.Increment(ref _eventCount);
        return result;
    }

    /// <summary>
    /// Set a persistent context value accessible in policy expressions as
    /// <c>context.&lt;key&gt;</c>. Values accumulate across events for the
    /// lifetime of this engine instance.
    /// </summary>
    /// <param name="key">Context key.</param>
    /// <param name="value">
    /// Value — any JSON-serialisable type (string, number, bool, object).
    /// </param>
    public void SetContext(string key, object? value)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        ThrowIfDisposed();
        string valueJson = JsonSerializer.Serialize(value, JsonOptions.Default);
        _native.SetContext(key, valueJson);
    }

    /// <summary>
    /// Set a policy configuration value accessible in policy expressions as
    /// <c>config.&lt;key&gt;</c>.
    /// </summary>
    /// <param name="key">Config key.</param>
    /// <param name="value">Value — any JSON-serialisable type.</param>
    public void SetConfig(string key, object? value)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        ThrowIfDisposed();
        string valueJson = JsonSerializer.Serialize(value, JsonOptions.Default);
        _native.SetConfig(key, valueJson);
    }

    /// <summary>
    /// Reset all state machines and rate-limit counters to their initial states.
    ///
    /// Call this at the start of a new agent session to isolate per-session
    /// temporal invariants and rate limits.
    /// </summary>
    public void Reset()
    {
        ThrowIfDisposed();
        _native.Reset();
        Interlocked.Exchange(ref _eventCount, 0);
    }

    /// <summary>Return a snapshot of the engine's current operational state.</summary>
    public EngineStatus Status()
    {
        ThrowIfDisposed();
        return _native.Status();
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    /// <summary>
    /// Release the native engine handle.
    ///
    /// After disposal any call to this instance will throw
    /// <see cref="ObjectDisposedException"/>.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _native.Dispose();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}

namespace AutomaGuard;

/// <summary>
/// Internal abstraction over the native <c>aegis-ffi</c> engine handle.
///
/// Exists so that the public <see cref="PolicyEngine"/> API can be unit-tested
/// without loading the native binary. In production, <see cref="RealNativeEngine"/>
/// provides the P/Invoke-backed implementation.
/// </summary>
internal interface INativeEngine : IDisposable
{
    /// <summary>The policy name declared in the <c>.aegisc</c> file.</summary>
    string PolicyName { get; }

    /// <summary>
    /// Evaluate a single agent event.
    /// </summary>
    /// <param name="eventType">Event type string (e.g. <c>tool_call</c>).</param>
    /// <param name="fieldsJson">
    /// JSON object of field name → value pairs, or <see langword="null"/> for
    /// events with no fields.
    /// </param>
    /// <returns>The deserialized <see cref="PolicyResult"/>.</returns>
    PolicyResult Evaluate(string eventType, string? fieldsJson);

    /// <summary>Set a persistent context value (JSON-encoded).</summary>
    void SetContext(string key, string valueJson);

    /// <summary>Set a policy configuration value (JSON-encoded).</summary>
    void SetConfig(string key, string valueJson);

    /// <summary>Reset all state machines and rate-limit counters.</summary>
    void Reset();

    /// <summary>Return a snapshot of the engine's operational state.</summary>
    EngineStatus Status();
}

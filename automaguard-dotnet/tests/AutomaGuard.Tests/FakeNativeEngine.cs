namespace AutomaGuard.Tests;

/// <summary>
/// In-memory test double for <see cref="INativeEngine"/>.
/// Lets unit tests drive verdict, violations, and error paths without loading
/// the native <c>aegis</c> binary.
/// </summary>
internal sealed class FakeNativeEngine : INativeEngine
{
    // Configurable responses
    public PolicyResult NextResult { get; set; } = Fixtures.AllowResult;
    public EngineStatus NextStatus { get; set; } = Fixtures.DefaultStatus;
    public string PolicyNameValue { get; set; } = "TestPolicy";

    // Call records
    public List<(string EventType, string? FieldsJson)> EvaluateCalls { get; } = [];
    public List<(string Key, string ValueJson)> SetContextCalls { get; } = [];
    public List<(string Key, string ValueJson)> SetConfigCalls { get; } = [];
    public int ResetCallCount { get; private set; }
    public int StatusCallCount { get; private set; }
    public bool Disposed { get; private set; }

    public string PolicyName => PolicyNameValue;

    public PolicyResult Evaluate(string eventType, string? fieldsJson)
    {
        EvaluateCalls.Add((eventType, fieldsJson));
        return NextResult;
    }

    public void SetContext(string key, string valueJson) =>
        SetContextCalls.Add((key, valueJson));

    public void SetConfig(string key, string valueJson) =>
        SetConfigCalls.Add((key, valueJson));

    public void Reset() => ResetCallCount++;

    public EngineStatus Status()
    {
        StatusCallCount++;
        return NextStatus;
    }

    public void Dispose() => Disposed = true;
}

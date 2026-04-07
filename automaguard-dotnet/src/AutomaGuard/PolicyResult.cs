using System.Text.Json;
using System.Text.Json.Serialization;

namespace AutomaGuard;

/// <summary>The four possible outcomes of policy evaluation.</summary>
[JsonConverter(typeof(VerdictJsonConverter))]
public enum Verdict
{
    /// <summary>The event is allowed to proceed.</summary>
    Allow,
    /// <summary>The event is denied; the action must not be executed.</summary>
    Deny,
    /// <summary>The event is allowed but flagged for audit logging.</summary>
    Audit,
    /// <summary>The event is allowed but the response must be redacted.</summary>
    Redact,
}

/// <summary>An invariant violation detected during event evaluation.</summary>
public sealed class Violation
{
    /// <summary>Name of the proof block that owns this invariant.</summary>
    [JsonPropertyName("proof")]
    public string Proof { get; init; } = string.Empty;

    /// <summary>Name of the violated invariant.</summary>
    [JsonPropertyName("invariant")]
    public string Invariant { get; init; } = string.Empty;

    /// <summary>Temporal operator kind (e.g. <c>Always</c>, <c>Eventually</c>, <c>Until</c>, <c>Never</c>).</summary>
    [JsonPropertyName("kind")]
    public string Kind { get; init; } = string.Empty;

    /// <summary>Human-readable violation message.</summary>
    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;
}

/// <summary>A rate-limit or quota constraint violation.</summary>
public sealed class ConstraintViolation
{
    /// <summary>Constraint kind (<c>RateLimit</c> or <c>Quota</c>).</summary>
    [JsonPropertyName("kind")]
    public string Kind { get; init; } = string.Empty;

    /// <summary>The event type the constraint applies to.</summary>
    [JsonPropertyName("target")]
    public string Target { get; init; } = string.Empty;

    /// <summary>Configured event limit.</summary>
    [JsonPropertyName("limit")]
    public long Limit { get; init; }

    /// <summary>Current count within the sliding window.</summary>
    [JsonPropertyName("current")]
    public long Current { get; init; }

    /// <summary>Sliding window size in milliseconds.</summary>
    [JsonPropertyName("window_ms")]
    public long WindowMs { get; init; }
}

/// <summary>An action emitted by a matched rule.</summary>
public sealed class RuleAction
{
    /// <summary>The action verb (e.g. <c>log</c>, <c>notify</c>, <c>escalate</c>).</summary>
    [JsonPropertyName("verb")]
    public string Verb { get; init; } = string.Empty;

    /// <summary>JSON-serialised action arguments.</summary>
    [JsonPropertyName("args_json")]
    public string ArgsJson { get; init; } = string.Empty;
}

/// <summary>A snapshot of the engine's current operational state.</summary>
public sealed class EngineStatus
{
    /// <summary>The policy name declared in the <c>.aegisc</c> file.</summary>
    [JsonPropertyName("policy_name")]
    public string PolicyName { get; init; } = string.Empty;

    /// <summary>Overall policy severity classification.</summary>
    [JsonPropertyName("severity")]
    public string Severity { get; init; } = string.Empty;

    /// <summary>Total number of rules in the policy.</summary>
    [JsonPropertyName("total_rules")]
    public int TotalRules { get; init; }

    /// <summary>Total number of temporal state machines.</summary>
    [JsonPropertyName("total_state_machines")]
    public int TotalStateMachines { get; init; }

    /// <summary>State machines that are currently active (not yet satisfied or violated).</summary>
    [JsonPropertyName("active_state_machines")]
    public int ActiveStateMachines { get; init; }

    /// <summary>State machines that have reached a violated terminal state.</summary>
    [JsonPropertyName("violated_state_machines")]
    public int ViolatedStateMachines { get; init; }

    /// <summary>State machines that have reached a satisfied terminal state.</summary>
    [JsonPropertyName("satisfied_state_machines")]
    public int SatisfiedStateMachines { get; init; }

    /// <summary>Total number of rate-limit and quota constraints.</summary>
    [JsonPropertyName("total_constraints")]
    public int TotalConstraints { get; init; }

    /// <summary>Total events processed since creation or the last reset.</summary>
    [JsonPropertyName("events_processed")]
    public long EventsProcessed { get; init; }
}

/// <summary>The full result of evaluating one agent event against the loaded policy.</summary>
public sealed class PolicyResult
{
    /// <summary>Final verdict.</summary>
    [JsonPropertyName("verdict")]
    public Verdict Verdict { get; init; }

    /// <summary>Human-readable denial reason, or <see langword="null"/> if none.</summary>
    [JsonPropertyName("reason")]
    public string? Reason { get; init; }

    /// <summary>IDs of the rules that matched this event.</summary>
    [JsonPropertyName("triggered_rules")]
    public IReadOnlyList<int> TriggeredRules { get; init; } = [];

    /// <summary>Temporal invariant violations detected during evaluation.</summary>
    [JsonPropertyName("violations")]
    public IReadOnlyList<Violation> Violations { get; init; } = [];

    /// <summary>Rate-limit or quota constraint violations.</summary>
    [JsonPropertyName("constraint_violations")]
    public IReadOnlyList<ConstraintViolation> ConstraintViolations { get; init; } = [];

    /// <summary>Actions emitted by matched rules.</summary>
    [JsonPropertyName("actions")]
    public IReadOnlyList<RuleAction> Actions { get; init; } = [];

    /// <summary>Evaluation latency in microseconds.</summary>
    [JsonPropertyName("latency_us")]
    public long LatencyMicroseconds { get; init; }

    /// <summary><see langword="true"/> when the verdict is <see cref="Verdict.Allow"/>.</summary>
    public bool IsAllowed => Verdict == Verdict.Allow;

    /// <summary><see langword="true"/> when the verdict is <see cref="Verdict.Deny"/>.</summary>
    public bool IsDenied => Verdict == Verdict.Deny;

    /// <summary><see langword="true"/> when the verdict is <see cref="Verdict.Audit"/>.</summary>
    public bool IsAudited => Verdict == Verdict.Audit;

    /// <summary><see langword="true"/> when the verdict is <see cref="Verdict.Redact"/>.</summary>
    public bool IsRedacted => Verdict == Verdict.Redact;
}

// ── JSON converter for Verdict ────────────────────────────────────────────────

internal sealed class VerdictJsonConverter : JsonConverter<Verdict>
{
    public override Verdict Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "allow"  => Verdict.Allow,
            "deny"   => Verdict.Deny,
            "audit"  => Verdict.Audit,
            "redact" => Verdict.Redact,
            _ => throw new JsonException($"Unknown verdict value: '{value}'"),
        };
    }

    public override void Write(
        Utf8JsonWriter writer,
        Verdict value,
        JsonSerializerOptions options)
    {
        writer.WriteStringValue(value switch
        {
            Verdict.Allow  => "allow",
            Verdict.Deny   => "deny",
            Verdict.Audit  => "audit",
            Verdict.Redact => "redact",
            _ => throw new ArgumentOutOfRangeException(nameof(value)),
        });
    }
}

// ── Serialization options (shared, cached) ────────────────────────────────────

internal static class JsonOptions
{
    internal static readonly JsonSerializerOptions Default = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}

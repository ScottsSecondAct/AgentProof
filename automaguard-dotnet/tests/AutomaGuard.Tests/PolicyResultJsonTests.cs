using System.Text.Json;
using Xunit;

namespace AutomaGuard.Tests;

/// <summary>
/// Verifies that <see cref="PolicyResult"/> deserializes correctly from the
/// JSON shape returned by the native <c>aegis_engine_evaluate</c> function.
/// </summary>
public sealed class PolicyResultJsonTests
{
    [Theory]
    [InlineData("allow",  Verdict.Allow)]
    [InlineData("deny",   Verdict.Deny)]
    [InlineData("audit",  Verdict.Audit)]
    [InlineData("redact", Verdict.Redact)]
    public void Deserializes_Verdict(string raw, Verdict expected)
    {
        string json = $$"""{"verdict":"{{raw}}","reason":null,"triggered_rules":[],"violations":[],"constraint_violations":[],"actions":[],"latency_us":1}""";
        PolicyResult result = Deserialize(json);
        Assert.Equal(expected, result.Verdict);
    }

    [Fact]
    public void Deserializes_Reason_WhenPresent()
    {
        string json = """{"verdict":"deny","reason":"tool not allowed","triggered_rules":[],"violations":[],"constraint_violations":[],"actions":[],"latency_us":2}""";
        PolicyResult result = Deserialize(json);
        Assert.Equal("tool not allowed", result.Reason);
    }

    [Fact]
    public void Deserializes_Reason_WhenNull()
    {
        string json = """{"verdict":"allow","reason":null,"triggered_rules":[],"violations":[],"constraint_violations":[],"actions":[],"latency_us":3}""";
        PolicyResult result = Deserialize(json);
        Assert.Null(result.Reason);
    }

    [Fact]
    public void Deserializes_TriggeredRules()
    {
        string json = """{"verdict":"deny","reason":null,"triggered_rules":[0,2],"violations":[],"constraint_violations":[],"actions":[],"latency_us":4}""";
        PolicyResult result = Deserialize(json);
        Assert.Equal([0, 2], result.TriggeredRules);
    }

    [Fact]
    public void Deserializes_Violations()
    {
        string json = """
        {
            "verdict": "deny",
            "reason": null,
            "triggered_rules": [],
            "violations": [
                {
                    "proof": "SafetyProof",
                    "invariant": "never_exec",
                    "kind": "Never",
                    "message": "exec tool was invoked"
                }
            ],
            "constraint_violations": [],
            "actions": [],
            "latency_us": 5
        }
        """;
        PolicyResult result = Deserialize(json);
        Assert.Single(result.Violations);
        Violation v = result.Violations[0];
        Assert.Equal("SafetyProof", v.Proof);
        Assert.Equal("never_exec", v.Invariant);
        Assert.Equal("Never", v.Kind);
        Assert.Equal("exec tool was invoked", v.Message);
    }

    [Fact]
    public void Deserializes_ConstraintViolations()
    {
        string json = """
        {
            "verdict": "deny",
            "reason": null,
            "triggered_rules": [],
            "violations": [],
            "constraint_violations": [
                {
                    "kind": "RateLimit",
                    "target": "tool_call",
                    "limit": 10,
                    "current": 11,
                    "window_ms": 60000
                }
            ],
            "actions": [],
            "latency_us": 6
        }
        """;
        PolicyResult result = Deserialize(json);
        Assert.Single(result.ConstraintViolations);
        ConstraintViolation cv = result.ConstraintViolations[0];
        Assert.Equal("RateLimit", cv.Kind);
        Assert.Equal("tool_call", cv.Target);
        Assert.Equal(10, cv.Limit);
        Assert.Equal(11, cv.Current);
        Assert.Equal(60000, cv.WindowMs);
    }

    [Fact]
    public void Deserializes_Actions()
    {
        string json = """
        {
            "verdict": "audit",
            "reason": null,
            "triggered_rules": [1],
            "violations": [],
            "constraint_violations": [],
            "actions": [
                {"verb": "log", "args_json": "{\"level\":\"warn\"}"}
            ],
            "latency_us": 7
        }
        """;
        PolicyResult result = Deserialize(json);
        Assert.Single(result.Actions);
        Assert.Equal("log", result.Actions[0].Verb);
        Assert.Contains("warn", result.Actions[0].ArgsJson);
    }

    [Fact]
    public void Deserializes_LatencyMicroseconds()
    {
        string json = """{"verdict":"allow","reason":null,"triggered_rules":[],"violations":[],"constraint_violations":[],"actions":[],"latency_us":42}""";
        PolicyResult result = Deserialize(json);
        Assert.Equal(42, result.LatencyMicroseconds);
    }

    [Fact]
    public void VerdictConverter_ThrowsOnUnknownValue()
    {
        string json = """{"verdict":"unknown","reason":null,"triggered_rules":[],"violations":[],"constraint_violations":[],"actions":[],"latency_us":1}""";
        Assert.Throws<JsonException>(() => Deserialize(json));
    }

    private static PolicyResult Deserialize(string json) =>
        JsonSerializer.Deserialize<PolicyResult>(json, JsonOptions.Default)!;
}

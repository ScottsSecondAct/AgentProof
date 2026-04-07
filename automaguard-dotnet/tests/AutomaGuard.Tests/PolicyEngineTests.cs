using Xunit;

namespace AutomaGuard.Tests;

public sealed class PolicyEngineTests
{
    // ── PolicyName ────────────────────────────────────────────────────────────

    [Fact]
    public void PolicyName_ReturnsFakeEngineName()
    {
        var fake = new FakeNativeEngine { PolicyNameValue = "GuardPolicy" };
        using var engine = new PolicyEngine(fake);

        Assert.Equal("GuardPolicy", engine.PolicyName);
    }

    // ── Evaluate ──────────────────────────────────────────────────────────────

    [Fact]
    public void Evaluate_ReturnsResultFromNativeEngine()
    {
        var fake = new FakeNativeEngine { NextResult = Fixtures.DenyResult };
        using var engine = new PolicyEngine(fake);

        PolicyResult result = engine.Evaluate("tool_call", new Dictionary<string, object?>
        {
            ["tool_name"] = "exec",
        });

        Assert.Equal(Verdict.Deny, result.Verdict);
        Assert.Equal("Tool \"exec\" is not allowed", result.Reason);
    }

    [Fact]
    public void Evaluate_ForwardsEventTypeAndSerializedFields()
    {
        var fake = new FakeNativeEngine();
        using var engine = new PolicyEngine(fake);

        engine.Evaluate("data_access", new Dictionary<string, object?>
        {
            ["classification"] = "PII",
            ["record_id"] = "42",
        });

        Assert.Single(fake.EvaluateCalls);
        (string eventType, string? fieldsJson) = fake.EvaluateCalls[0];
        Assert.Equal("data_access", eventType);
        Assert.NotNull(fieldsJson);
        Assert.Contains("classification", fieldsJson);
        Assert.Contains("PII", fieldsJson);
    }

    [Fact]
    public void Evaluate_WithNoFields_PassesNullJson()
    {
        var fake = new FakeNativeEngine();
        using var engine = new PolicyEngine(fake);

        engine.Evaluate("heartbeat");

        Assert.Single(fake.EvaluateCalls);
        Assert.Null(fake.EvaluateCalls[0].FieldsJson);
    }

    [Fact]
    public void Evaluate_WithEmptyFields_PassesNullJson()
    {
        var fake = new FakeNativeEngine();
        using var engine = new PolicyEngine(fake);

        engine.Evaluate("heartbeat", new Dictionary<string, object?>());

        Assert.Null(fake.EvaluateCalls[0].FieldsJson);
    }

    [Fact]
    public void Evaluate_IncrementsEventCount()
    {
        var fake = new FakeNativeEngine();
        using var engine = new PolicyEngine(fake);

        Assert.Equal(0, engine.EventCount);
        engine.Evaluate("tool_call");
        Assert.Equal(1, engine.EventCount);
        engine.Evaluate("tool_call");
        Assert.Equal(2, engine.EventCount);
    }

    // ── Verdict helpers ───────────────────────────────────────────────────────

    [Fact]
    public void PolicyResult_IsAllowed_TrueForAllow()
    {
        Assert.True(Fixtures.AllowResult.IsAllowed);
        Assert.False(Fixtures.AllowResult.IsDenied);
        Assert.False(Fixtures.AllowResult.IsAudited);
        Assert.False(Fixtures.AllowResult.IsRedacted);
    }

    [Fact]
    public void PolicyResult_IsDenied_TrueForDeny()
    {
        Assert.True(Fixtures.DenyResult.IsDenied);
        Assert.False(Fixtures.DenyResult.IsAllowed);
    }

    [Fact]
    public void PolicyResult_IsAudited_TrueForAudit()
    {
        Assert.True(Fixtures.AuditResult.IsAudited);
    }

    [Fact]
    public void PolicyResult_IsRedacted_TrueForRedact()
    {
        Assert.True(Fixtures.RedactResult.IsRedacted);
    }

    // ── SetContext / SetConfig ────────────────────────────────────────────────

    [Fact]
    public void SetContext_DelegatesToNativeEngine()
    {
        var fake = new FakeNativeEngine();
        using var engine = new PolicyEngine(fake);

        engine.SetContext("user_role", "admin");

        Assert.Single(fake.SetContextCalls);
        Assert.Equal("user_role", fake.SetContextCalls[0].Key);
        Assert.Contains("admin", fake.SetContextCalls[0].ValueJson);
    }

    [Fact]
    public void SetConfig_DelegatesToNativeEngine()
    {
        var fake = new FakeNativeEngine();
        using var engine = new PolicyEngine(fake);

        engine.SetConfig("max_retries", 3);

        Assert.Single(fake.SetConfigCalls);
        Assert.Equal("max_retries", fake.SetConfigCalls[0].Key);
        Assert.Contains("3", fake.SetConfigCalls[0].ValueJson);
    }

    // ── Reset ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Reset_DelegatesToNativeAndResetsEventCount()
    {
        var fake = new FakeNativeEngine();
        using var engine = new PolicyEngine(fake);

        engine.Evaluate("tool_call");
        engine.Evaluate("tool_call");
        Assert.Equal(2, engine.EventCount);

        engine.Reset();

        Assert.Equal(1, fake.ResetCallCount);
        Assert.Equal(0, engine.EventCount);
    }

    // ── Status ────────────────────────────────────────────────────────────────

    [Fact]
    public void Status_ReturnsFakeStatus()
    {
        var fake = new FakeNativeEngine { NextStatus = Fixtures.DefaultStatus };
        using var engine = new PolicyEngine(fake);

        EngineStatus status = engine.Status();

        Assert.Equal("TestPolicy", status.PolicyName);
        Assert.Equal(2, status.TotalRules);
        Assert.Equal(1, fake.StatusCallCount);
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    [Fact]
    public void Dispose_FreesNativeEngine()
    {
        var fake = new FakeNativeEngine();
        var engine = new PolicyEngine(fake);

        engine.Dispose();

        Assert.True(fake.Disposed);
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var fake = new FakeNativeEngine();
        var engine = new PolicyEngine(fake);

        engine.Dispose();
        engine.Dispose(); // should not throw
    }

    [Fact]
    public void MethodsThrowAfterDispose()
    {
        var fake = new FakeNativeEngine();
        var engine = new PolicyEngine(fake);
        engine.Dispose();

        Assert.Throws<ObjectDisposedException>(() => engine.Evaluate("tool_call"));
        Assert.Throws<ObjectDisposedException>(() => engine.PolicyName);
        Assert.Throws<ObjectDisposedException>(() => engine.SetContext("k", "v"));
        Assert.Throws<ObjectDisposedException>(() => engine.SetConfig("k", "v"));
        Assert.Throws<ObjectDisposedException>(() => engine.Reset());
        Assert.Throws<ObjectDisposedException>(() => engine.Status());
    }

    // ── Argument validation ───────────────────────────────────────────────────

    [Fact]
    public void Evaluate_ThrowsOnNullOrEmptyEventType()
    {
        var fake = new FakeNativeEngine();
        using var engine = new PolicyEngine(fake);

        Assert.Throws<ArgumentException>(() => engine.Evaluate(string.Empty));
        Assert.Throws<ArgumentException>(() => engine.Evaluate(""));
    }

    [Fact]
    public void FromBytes_ThrowsOnNull()
    {
        Assert.Throws<ArgumentNullException>(() => PolicyEngine.FromBytes(null!));
    }

    [Fact]
    public void FromFile_ThrowsOnNullOrEmpty()
    {
        Assert.Throws<ArgumentException>(() => PolicyEngine.FromFile(string.Empty));
    }
}

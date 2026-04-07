using System.Reflection;
using AutomaGuard;
using AutomaGuard.SemanticKernel;
using AutomaGuard.Tests;
using Microsoft.SemanticKernel;
using Xunit;

namespace AutomaGuard.SemanticKernel.Tests;

public sealed class AutomaGuardFunctionFilterTests
{
    // ── Context factory ───────────────────────────────────────────────────────

    /// <summary>
    /// Construct a <see cref="FunctionInvocationContext"/> via reflection since
    /// its constructor is internal to the Microsoft.SemanticKernel assembly.
    /// </summary>
    private static FunctionInvocationContext MakeContext(
        string functionName = "send_email",
        KernelArguments? args = null)
    {
        KernelFunction fn = KernelFunctionFactory.CreateFromMethod(
            () => "ok",
            functionName,
            description: "test");

        var kernel = new Kernel();
        var arguments = args ?? new KernelArguments { ["to"] = "user@example.com" };
        var result = new FunctionResult(fn);

        // FunctionInvocationContext has an internal ctor:
        //   (Kernel kernel, KernelFunction function, KernelArguments arguments, FunctionResult result)
        var ctor = typeof(FunctionInvocationContext)
            .GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)
            .First();

        return (FunctionInvocationContext)ctor.Invoke([kernel, fn, arguments, result]);
    }

    /// <summary>Build a filter wrapping a <see cref="FakeNativeEngine"/>.</summary>
    private static (AutomaGuardFunctionFilter Filter, FakeNativeEngine Fake, PolicyEngine Engine)
        MakeFilter(
            PolicyResult? nextResult = null,
            Action<PolicyResult, FunctionInvocationContext>? onDeny = null,
            Action<PolicyResult, FunctionInvocationContext>? onAudit = null)
    {
        var fake = new FakeNativeEngine { NextResult = nextResult ?? Fixtures.AllowResult };
        var engine = new PolicyEngine(fake);
        var filter = new AutomaGuardFunctionFilter(engine, onDeny, onAudit);
        return (filter, fake, engine);
    }

    // ── Allow ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AllowResult_CallsNext()
    {
        var (filter, _, _) = MakeFilter(Fixtures.AllowResult);
        using (filter)
        {
            var ctx = MakeContext();
            bool nextCalled = false;
            await filter.OnFunctionInvocationAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });
            Assert.True(nextCalled);
        }
    }

    [Fact]
    public async Task AllowResult_EvaluatesToolCallThenToolResult()
    {
        var (filter, fake, engine) = MakeFilter(Fixtures.AllowResult);
        using (filter)
        using (engine)
        {
            var ctx = MakeContext();
            await filter.OnFunctionInvocationAsync(ctx, _ => Task.CompletedTask);

            Assert.Equal(2, fake.EvaluateCalls.Count);
            Assert.Equal("tool_call",   fake.EvaluateCalls[0].EventType);
            Assert.Equal("tool_result", fake.EvaluateCalls[1].EventType);
        }
    }

    // ── Deny ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task DenyResult_ThrowsEnforcementException()
    {
        var (filter, _, _) = MakeFilter(Fixtures.DenyResult);
        using (filter)
        {
            var ctx = MakeContext();
            await Assert.ThrowsAsync<EnforcementException>(
                () => filter.OnFunctionInvocationAsync(ctx, _ => Task.CompletedTask));
        }
    }

    [Fact]
    public async Task DenyResult_DoesNotCallNext()
    {
        var (filter, _, _) = MakeFilter(Fixtures.DenyResult);
        using (filter)
        {
            bool nextCalled = false;
            var ctx = MakeContext();
            try
            {
                await filter.OnFunctionInvocationAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });
            }
            catch (EnforcementException) { }
            Assert.False(nextCalled);
        }
    }

    [Fact]
    public async Task DenyResult_InvokesCustomOnDenyHandler()
    {
        PolicyResult? capturedResult = null;
        var (filter, _, engine) = MakeFilter(
            Fixtures.DenyResult,
            onDeny: (r, _) => capturedResult = r);
        using (filter)
        using (engine)
        {
            var ctx = MakeContext();
            // custom handler doesn't throw, so next is still not called
            await filter.OnFunctionInvocationAsync(ctx, _ => Task.CompletedTask);
        }
        Assert.NotNull(capturedResult);
        Assert.Equal(Verdict.Deny, capturedResult!.Verdict);
    }

    // ── Audit ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AuditResult_CallsNextAndOnAudit()
    {
        PolicyResult? auditCapture = null;
        var (filter, _, engine) = MakeFilter(
            Fixtures.AuditResult,
            onAudit: (r, _) => auditCapture = r);
        using (filter)
        using (engine)
        {
            bool nextCalled = false;
            var ctx = MakeContext();
            await filter.OnFunctionInvocationAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });

            Assert.True(nextCalled);
            Assert.NotNull(auditCapture);
        }
    }

    // ── Evaluate field content ────────────────────────────────────────────────

    [Fact]
    public async Task PreInvocation_IncludesFunctionName()
    {
        var (filter, fake, engine) = MakeFilter(Fixtures.AllowResult);
        using (filter)
        using (engine)
        {
            var ctx = MakeContext("my_tool");
            await filter.OnFunctionInvocationAsync(ctx, _ => Task.CompletedTask);

            string? fieldsJson = fake.EvaluateCalls[0].FieldsJson;
            Assert.NotNull(fieldsJson);
            Assert.Contains("my_tool", fieldsJson);
        }
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    [Fact]
    public void Dispose_FreesInternalEngine()
    {
        var fake = new FakeNativeEngine();
        var engine = new PolicyEngine(fake);
        var filter = new AutomaGuardFunctionFilter(engine);

        filter.Dispose();

        Assert.True(fake.Disposed);
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var (filter, _, _) = MakeFilter();
        filter.Dispose();
        filter.Dispose(); // must not throw
    }

    [Fact]
    public async Task ThrowsAfterDispose()
    {
        var (filter, _, _) = MakeFilter();
        filter.Dispose();
        var ctx = MakeContext();
        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => filter.OnFunctionInvocationAsync(ctx, _ => Task.CompletedTask));
    }
}

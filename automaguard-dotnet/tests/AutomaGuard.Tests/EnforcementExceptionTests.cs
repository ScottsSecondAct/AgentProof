using Xunit;

namespace AutomaGuard.Tests;

public sealed class EnforcementExceptionTests
{
    [Fact]
    public void CarriesFullPolicyResult()
    {
        var ex = new EnforcementException(Fixtures.DenyResult);
        Assert.Same(Fixtures.DenyResult, ex.Result);
    }

    [Fact]
    public void UsesReasonAsMessage()
    {
        var ex = new EnforcementException(Fixtures.DenyResult);
        Assert.Equal("Tool \"exec\" is not allowed", ex.Message);
    }

    [Fact]
    public void FallsBackToGenericMessageWhenReasonIsNull()
    {
        var result = new PolicyResult
        {
            Verdict = Verdict.Deny,
            Reason = null,
        };
        var ex = new EnforcementException(result);
        Assert.Equal("Policy denied: Deny", ex.Message);
    }

    [Fact]
    public void IsAnException()
    {
        var ex = new EnforcementException(Fixtures.DenyResult);
        Assert.IsAssignableFrom<Exception>(ex);
    }

    [Fact]
    public void CanBeCreatedWithCustomMessage()
    {
        var ex = new EnforcementException("custom message", Fixtures.DenyResult);
        Assert.Equal("custom message", ex.Message);
        Assert.Same(Fixtures.DenyResult, ex.Result);
    }

    [Fact]
    public void CanBeCaughtAsException()
    {
        Exception? caught = null;
        try
        {
            throw new EnforcementException(Fixtures.DenyResult);
        }
        catch (Exception ex)
        {
            caught = ex;
        }

        Assert.NotNull(caught);
        Assert.IsType<EnforcementException>(caught);
    }
}

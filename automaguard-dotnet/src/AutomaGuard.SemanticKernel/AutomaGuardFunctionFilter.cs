using System.Text.Json;
using AutomaGuard;
using Microsoft.SemanticKernel;

namespace AutomaGuard.SemanticKernel;

/// <summary>
/// Semantic Kernel <see cref="IFunctionInvocationFilter"/> that enforces an
/// AutomaGuard policy on every kernel function (tool) invocation.
///
/// Register via <see cref="KernelBuilderExtensions.AddAutomaGuard"/> or add
/// directly to <see cref="Kernel.FunctionInvocationFilters"/>.
///
/// <example>
/// <code>
/// var kernel = Kernel.CreateBuilder()
///     .AddOpenAIChatCompletion("gpt-4o", apiKey)
///     .AddAutomaGuard("guard.aegisc")
///     .Build();
/// </code>
/// </example>
/// </summary>
public sealed class AutomaGuardFunctionFilter : IFunctionInvocationFilter, IDisposable
{
    private readonly PolicyEngine _engine;
    private readonly Action<PolicyResult, FunctionInvocationContext>? _onDeny;
    private readonly Action<PolicyResult, FunctionInvocationContext>? _onAudit;
    private bool _disposed;

    /// <summary>
    /// Create a filter from a compiled <c>.aegisc</c> policy file.
    /// </summary>
    /// <param name="policyPath">Path to the compiled policy file.</param>
    /// <param name="onDeny">
    /// Optional handler called when a function is denied.
    /// Defaults to throwing <see cref="EnforcementException"/>.
    /// </param>
    /// <param name="onAudit">
    /// Optional handler called when a function result is <see cref="Verdict.Audit"/>.
    /// Defaults to a no-op; override to send to your audit sink.
    /// </param>
    public AutomaGuardFunctionFilter(
        string policyPath,
        Action<PolicyResult, FunctionInvocationContext>? onDeny = null,
        Action<PolicyResult, FunctionInvocationContext>? onAudit = null)
    {
        _engine = PolicyEngine.FromFile(policyPath);
        _onDeny = onDeny;
        _onAudit = onAudit;
    }

    /// <summary>
    /// Create a filter from a pre-constructed <see cref="PolicyEngine"/>.
    ///
    /// The filter does <b>not</b> take ownership of the engine — the caller
    /// is responsible for disposing it.
    /// </summary>
    internal AutomaGuardFunctionFilter(
        PolicyEngine engine,
        Action<PolicyResult, FunctionInvocationContext>? onDeny = null,
        Action<PolicyResult, FunctionInvocationContext>? onAudit = null)
    {
        _engine = engine;
        _onDeny = onDeny;
        _onAudit = onAudit;
    }

    // ── IFunctionInvocationFilter ─────────────────────────────────────────────

    /// <summary>
    /// Intercepts function invocations at the pre-invocation stage to enforce
    /// the AutomaGuard policy.
    ///
    /// <list type="bullet">
    ///   <item>
    ///     <description>
    ///       <b>Pre-invocation</b> (<c>context.IsStreaming</c> is irrelevant):
    ///       evaluates the call as a <c>tool_call</c> event. A
    ///       <see cref="Verdict.Deny"/> stops execution by throwing
    ///       <see cref="EnforcementException"/> (or calling <c>onDeny</c>).
    ///     </description>
    ///   </item>
    ///   <item>
    ///     <description>
    ///       <b>Post-invocation</b>: evaluates the result as a
    ///       <c>tool_result</c> event. Useful for policies that inspect tool
    ///       output (e.g. redacting PII before it reaches the LLM context).
    ///     </description>
    ///   </item>
    /// </list>
    /// </summary>
    public async Task OnFunctionInvocationAsync(
        FunctionInvocationContext context,
        Func<FunctionInvocationContext, Task> next)
    {
        ThrowIfDisposed();

        // ── Pre-invocation: evaluate the tool call ────────────────────────────
        var callFields = BuildCallFields(context);
        PolicyResult preResult = _engine.Evaluate("tool_call", callFields);

        if (preResult.IsDenied)
        {
            HandleDeny(preResult, context);
            return; // stop the chain
        }

        if (preResult.IsAudited)
            HandleAudit(preResult, context);

        // ── Execute the function ──────────────────────────────────────────────
        await next(context).ConfigureAwait(false);

        // ── Post-invocation: evaluate the tool result ─────────────────────────
        var resultFields = BuildResultFields(context);
        PolicyResult postResult = _engine.Evaluate("tool_result", resultFields);

        if (postResult.IsDenied)
        {
            HandleDeny(postResult, context);
        }
        else if (postResult.IsAudited)
        {
            HandleAudit(postResult, context);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Dictionary<string, object?> BuildCallFields(FunctionInvocationContext context)
    {
        var fields = new Dictionary<string, object?>
        {
            ["tool_name"]   = context.Function.Name,
            ["plugin_name"] = context.Function.PluginName,
        };

        if (context.Arguments.Count > 0)
        {
            // Serialize arguments to a plain dictionary for the policy engine.
            var args = new Dictionary<string, object?>();
            foreach (string name in context.Arguments.Names)
                args[name] = context.Arguments[name];
            fields["arguments"] = args;
        }

        return fields;
    }

    private static Dictionary<string, object?> BuildResultFields(FunctionInvocationContext context)
    {
        object? output = context.Result?.GetValue<object>();
        return new Dictionary<string, object?>
        {
            ["tool_name"] = context.Function.Name,
            ["output"]    = output,
        };
    }

    private void HandleDeny(PolicyResult result, FunctionInvocationContext context)
    {
        if (_onDeny is not null)
        {
            _onDeny(result, context);
        }
        else
        {
            throw new EnforcementException(result);
        }
    }

    private void HandleAudit(PolicyResult result, FunctionInvocationContext context)
    {
        _onAudit?.Invoke(result, context);
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _engine.Dispose();
    }
}

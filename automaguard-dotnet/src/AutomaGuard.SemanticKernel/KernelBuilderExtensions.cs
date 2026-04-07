using AutomaGuard;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.SemanticKernel;

namespace AutomaGuard.SemanticKernel;

/// <summary>
/// Extension methods for <see cref="IKernelBuilder"/> to register the
/// AutomaGuard function invocation filter.
/// </summary>
public static class KernelBuilderExtensions
{
    /// <summary>
    /// Register an AutomaGuard <see cref="AutomaGuardFunctionFilter"/> that
    /// evaluates every kernel function (tool) invocation against the compiled
    /// policy at <paramref name="policyPath"/>.
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
    /// <param name="builder">The kernel builder.</param>
    /// <param name="policyPath">
    /// Path to the compiled <c>.aegisc</c> policy file.
    /// </param>
    /// <param name="onDeny">
    /// Optional handler called when a function invocation is denied.
    /// Defaults to throwing <see cref="EnforcementException"/>.
    /// </param>
    /// <param name="onAudit">
    /// Optional handler called when an invocation result is
    /// <see cref="Verdict.Audit"/>. Defaults to a no-op.
    /// </param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    public static IKernelBuilder AddAutomaGuard(
        this IKernelBuilder builder,
        string policyPath,
        Action<PolicyResult, FunctionInvocationContext>? onDeny = null,
        Action<PolicyResult, FunctionInvocationContext>? onAudit = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(policyPath);
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddSingleton<IFunctionInvocationFilter>(
            _ => new AutomaGuardFunctionFilter(policyPath, onDeny, onAudit));

        return builder;
    }
}

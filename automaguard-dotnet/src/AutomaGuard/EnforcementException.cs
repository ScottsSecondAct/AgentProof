namespace AutomaGuard;

/// <summary>
/// Thrown when a policy evaluation returns a <see cref="Verdict.Deny"/> verdict.
///
/// The full <see cref="PolicyResult"/> is attached so callers can inspect
/// triggered rules, violations, and the denial reason.
/// </summary>
public sealed class EnforcementException : Exception
{
    /// <summary>The full policy evaluation result that triggered this exception.</summary>
    public PolicyResult Result { get; }

    /// <summary>
    /// Initialise the exception from a <see cref="PolicyResult"/> with a
    /// <see cref="Verdict.Deny"/> verdict.
    /// </summary>
    /// <param name="result">The denied evaluation result.</param>
    public EnforcementException(PolicyResult result)
        : base(result.Reason ?? $"Policy denied: {result.Verdict}")
    {
        Result = result;
    }

    /// <summary>
    /// Initialise the exception with a custom message and a full result.
    /// </summary>
    public EnforcementException(string message, PolicyResult result)
        : base(message)
    {
        Result = result;
    }
}

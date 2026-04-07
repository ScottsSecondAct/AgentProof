namespace AutomaGuard.Tests;

/// <summary>Shared test fixtures.</summary>
internal static class Fixtures
{
    internal static readonly PolicyResult AllowResult = new()
    {
        Verdict = Verdict.Allow,
        Reason = null,
        TriggeredRules = [],
        Violations = [],
        ConstraintViolations = [],
        Actions = [],
        LatencyMicroseconds = 3,
    };

    internal static readonly PolicyResult DenyResult = new()
    {
        Verdict = Verdict.Deny,
        Reason = "Tool \"exec\" is not allowed",
        TriggeredRules = [0],
        Violations = [],
        ConstraintViolations = [],
        Actions = [],
        LatencyMicroseconds = 4,
    };

    internal static readonly PolicyResult AuditResult = new()
    {
        Verdict = Verdict.Audit,
        Reason = "Flagged for audit",
        TriggeredRules = [1],
        Violations = [],
        ConstraintViolations = [],
        Actions = [],
        LatencyMicroseconds = 2,
    };

    internal static readonly PolicyResult RedactResult = new()
    {
        Verdict = Verdict.Redact,
        Reason = "PII detected in output",
        TriggeredRules = [2],
        Violations = [],
        ConstraintViolations = [],
        Actions = [],
        LatencyMicroseconds = 5,
    };

    internal static readonly EngineStatus DefaultStatus = new()
    {
        PolicyName = "TestPolicy",
        Severity = "High",
        TotalRules = 2,
        TotalStateMachines = 1,
        ActiveStateMachines = 1,
        ViolatedStateMachines = 0,
        SatisfiedStateMachines = 0,
        TotalConstraints = 0,
        EventsProcessed = 0,
    };
}

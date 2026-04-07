// Customer Data Assistant — AutomaGuard .NET SDK example.
//
// Demonstrates AutomaGuard policy enforcement on a Microsoft Semantic Kernel
// agent via the IFunctionInvocationFilter integration.
//
// Two prompts are included:
//
//   --safe    Aggregate query, no PII accessed or sent externally.
//             All events receive Allow or Audit verdicts.
//
//   --unsafe  Adversarial prompt that attempts to exfiltrate a customer's
//             PII via an external email.  The NoPIIExfiltration invariant
//             and the unapproved-domain rule block the email before it sends.
//
// Usage:
//   dotnet run -- --safe
//   dotnet run -- --unsafe

using AutomaGuard;
using AutomaGuard.SemanticKernel;
using AutomaGuard.Example;
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.Connectors.OpenAI;

// ── Policy path ───────────────────────────────────────────────────────────────

// Walk up from the build output directory to examples/customer_data_guard.aegisc
var policyPath = Path.GetFullPath(
    Path.Combine(AppContext.BaseDirectory, "..", "customer_data_guard.aegisc"));

if (!File.Exists(policyPath))
{
    Console.Error.WriteLine($"Policy bytecode not found at {policyPath}");
    Console.Error.WriteLine("Compile it first:");
    Console.Error.WriteLine(
        "  aegisc compile examples/customer_data_guard.aegis " +
        "-o examples/customer_data_guard.aegisc");
    return 1;
}

// ── Mode selection ────────────────────────────────────────────────────────────

var mode   = args.Contains("--safe") ? "safe" : "unsafe";
var prompt = args.Contains("--safe") ? Prompts.Safe : Prompts.Unsafe;

Console.WriteLine($"\n=== AutomaGuard .NET Example ({mode} run) ===\n");
Console.WriteLine($"Prompt: {prompt}\n");

// ── Kernel setup ──────────────────────────────────────────────────────────────

var apiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY")
    ?? throw new InvalidOperationException(
        "OPENAI_API_KEY environment variable is not set.");

// AddAutomaGuard registers an IFunctionInvocationFilter that:
//   - Before each tool call: emits a tool_call / data_access / external_request
//     event (inferred from the function name and parameters) and throws
//     EnforcementException if the verdict is Deny.
//   - After each tool call: evaluates the result for redaction opportunities.
var kernel = Kernel.CreateBuilder()
    .AddOpenAIChatCompletion("gpt-4o", apiKey)
    .AddAutomaGuard(policyPath, options =>
    {
        options.OnAudit = (result, functionName) =>
            Console.WriteLine(
                $"  [audit] {functionName}: {result.Reason ?? "no reason"} " +
                $"(rules: [{string.Join(", ", result.TriggeredRules)}])");
    })
    .Build();

kernel.ImportPluginFromType<CustomerDataPlugin>();

var settings = new OpenAIPromptExecutionSettings
{
    ToolCallBehavior = ToolCallBehavior.AutoInvokeKernelFunctions,
};

// ── Run ───────────────────────────────────────────────────────────────────────

try
{
    var result = await kernel.InvokePromptAsync(
        prompt,
        new KernelArguments(settings));

    Console.WriteLine($"\nResult: {result}");
    return 0;
}
catch (EnforcementException ex)
{
    Console.Error.WriteLine("\nBLOCKED by AutomaGuard policy:");
    Console.Error.WriteLine($"  Reason:  {ex.Message}");
    Console.Error.WriteLine($"  Verdict: {ex.Result.Verdict}");

    if (ex.Result.TriggeredRules.Length > 0)
        Console.Error.WriteLine(
            $"  Rules:   [{string.Join(", ", ex.Result.TriggeredRules)}]");

    foreach (var v in ex.Result.Violations)
        Console.Error.WriteLine(
            $"  Invariant: {v.ProofName}/{v.InvariantName}: {v.Message}");

    return 1;
}

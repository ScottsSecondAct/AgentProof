using System.ComponentModel;
using Microsoft.SemanticKernel;

namespace AutomaGuard.Example;

/// <summary>
/// Semantic Kernel plugin that exposes mock CRM tools to the agent.
///
/// In a real deployment these would call an external CRM API.  Here they
/// return static data so the demo runs without any network dependencies.
///
/// The AutomaGuard <c>IFunctionInvocationFilter</c> (registered via
/// <c>AddAutomaGuard</c>) intercepts each function call <em>before</em> the
/// method body executes, evaluates the tool metadata against the compiled
/// policy, and throws <see cref="EnforcementException"/> on a <c>Deny</c>
/// verdict — so none of the bodies below run during an unsafe scenario.
/// </summary>
public sealed class CustomerDataPlugin
{
    /// <summary>Retrieve a full customer record by account ID.</summary>
    /// <remarks>
    /// Returns PII-classified data.  The AutomaGuard filter emits a
    /// <c>data_access</c> event with <c>classification=PII</c>, which the
    /// policy audits and tags with <c>pii_accessed</c>.
    /// </remarks>
    [KernelFunction("get_customer_profile")]
    [Description("Retrieve a customer record by account ID.")]
    public CustomerProfile GetCustomerProfile(
        [Description("The account identifier.")] string accountId)
    {
        Console.WriteLine($"  [tool] get_customer_profile(accountId={accountId})");
        return new CustomerProfile
        {
            AccountId    = accountId,
            Name         = "Jane Smith",
            Email        = "jane@example.com",
            PaymentMethod = "Visa ending 4242",
            Classification = "PII",
        };
    }

    /// <summary>Return open support ticket counts for a region and quarter.</summary>
    /// <remarks>Returns aggregate (non-PII) data; emits a <c>tool_call</c> event.</remarks>
    [KernelFunction("query_tickets")]
    [Description("Return open support ticket counts for a region and quarter.")]
    public TicketSummary[] QueryTickets(
        [Description("Geographic region, e.g. EMEA, APAC.")] string region,
        [Description("Fiscal quarter, e.g. Q4-2025.")] string quarter)
    {
        Console.WriteLine($"  [tool] query_tickets(region={region}, quarter={quarter})");
        return
        [
            new TicketSummary { Region = region, Quarter = quarter, OpenTickets = 42 }
        ];
    }

    /// <summary>Send an email to the specified address.</summary>
    /// <remarks>
    /// The AutomaGuard filter emits an <c>external_request</c> event with the
    /// recipient domain extracted from <paramref name="to"/>.  The policy
    /// denies any domain not in the approved list.
    /// </remarks>
    [KernelFunction("send_email")]
    [Description("Send an email message.")]
    public string SendEmail(
        [Description("Recipient email address.")] string to,
        [Description("Email subject line.")]     string subject,
        [Description("Plain-text email body.")]  string body)
    {
        Console.WriteLine($"  [tool] send_email(to={to})");
        return $"Email sent to {to}";
    }

    /// <summary>Delete a customer record (requires prior human approval).</summary>
    /// <remarks>
    /// The policy's <c>ApprovalBeforeDelete</c> invariant denies this call
    /// unless a <c>human_approved</c> tool call was evaluated earlier in the
    /// same session.
    /// </remarks>
    [KernelFunction("delete_record")]
    [Description("Permanently delete a customer record. Requires prior human approval.")]
    public string DeleteRecord(
        [Description("The account identifier to delete.")] string accountId)
    {
        Console.WriteLine($"  [tool] delete_record(accountId={accountId})");
        return $"Record {accountId} deleted.";
    }
}

// ── Value-object records returned by the plugin ───────────────────────────────

/// <summary>A customer profile returned by <c>get_customer_profile</c>.</summary>
public sealed record CustomerProfile
{
    public string AccountId     { get; init; } = "";
    public string Name          { get; init; } = "";
    public string Email         { get; init; } = "";
    public string PaymentMethod { get; init; } = "";

    /// <summary>
    /// Data classification (<c>"PII"</c>, <c>"aggregate"</c>, etc.).
    /// Passed through to the AutomaGuard <c>data_access</c> event so the
    /// policy can distinguish sensitive records.
    /// </summary>
    public string Classification { get; init; } = "";
}

/// <summary>A single row returned by <c>query_tickets</c>.</summary>
public sealed record TicketSummary
{
    public string Region      { get; init; } = "";
    public string Quarter     { get; init; } = "";
    public int    OpenTickets { get; init; }
}

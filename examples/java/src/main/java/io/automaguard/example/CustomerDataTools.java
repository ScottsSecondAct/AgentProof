package io.automaguard.example;

import org.springframework.ai.tool.annotation.Tool;

import java.util.List;
import java.util.Map;

/**
 * Mock CRM tools registered with the Spring AI agent.
 *
 * <p>In a real deployment these would call an external CRM API.  Here they
 * return static data so the demo runs without any network dependencies.</p>
 *
 * <p>The AutomaGuard {@code AutomaGuardAdvisor} intercepts each tool call
 * <em>before</em> the method body executes, evaluates it against the compiled
 * policy, and throws {@link io.automaguard.EnforcementException} on a
 * {@code Deny} verdict — so none of the bodies below run during an unsafe
 * scenario.</p>
 */
public final class CustomerDataTools {

    /**
     * Retrieve a full customer record by account ID.
     *
     * <p>Returns PII-classified data.  The AutomaGuard filter emits a
     * {@code data_access} event with {@code classification=PII}, which the
     * policy audits and tags with {@code pii_accessed}.</p>
     */
    @Tool(description = "Retrieve a customer record by account ID.")
    public Map<String, Object> getCustomerProfile(String accountId) {
        System.out.println("  [tool] get_customer_profile(accountId=" + accountId + ")");
        return Map.of(
                "account_id",      accountId,
                "name",            "Jane Smith",
                "email",           "jane@example.com",
                "payment_method",  "Visa ending 4242",
                "classification",  "PII"
        );
    }

    /**
     * Return open support ticket counts for a region and quarter.
     *
     * <p>Returns aggregate (non-PII) data; the policy allows this unconditionally.</p>
     */
    @Tool(description = "Return open support ticket counts for a region and quarter.")
    public List<Map<String, Object>> queryTickets(String region, String quarter) {
        System.out.println("  [tool] query_tickets(region=" + region + ", quarter=" + quarter + ")");
        return List.of(Map.of(
                "region",       region,
                "quarter",      quarter,
                "open_tickets", 42
        ));
    }

    /**
     * Send an email to the specified address.
     *
     * <p>The AutomaGuard filter emits an {@code external_request} event with the
     * recipient domain extracted from {@code to}.  The policy denies any domain
     * not in the approved list.</p>
     */
    @Tool(description = "Send an email message.")
    public String sendEmail(String to, String subject, String body) {
        System.out.println("  [tool] send_email(to=" + to + ")");
        return "Email sent to " + to;
    }

    /**
     * Delete a customer record (requires prior human approval).
     *
     * <p>The policy's {@code ApprovalBeforeDelete} invariant denies this call
     * unless a {@code human_approved} tool call was evaluated earlier in the
     * same session.</p>
     */
    @Tool(description = "Permanently delete a customer record. Requires prior human approval.")
    public String deleteRecord(String accountId) {
        System.out.println("  [tool] delete_record(accountId=" + accountId + ")");
        return "Record " + accountId + " deleted.";
    }
}

// Customer Data Assistant — AutomaGuard Java SDK example.
//
// Demonstrates AutomaGuard policy enforcement on a Spring AI ChatClient via
// the AutomaGuardAdvisor integration.
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
//   mvn -q package -DskipTests
//   java -jar target/customer-data-assistant.jar --safe
//   java -jar target/customer-data-assistant.jar --unsafe

package io.automaguard.example;

import io.automaguard.EnforcementException;
import io.automaguard.springai.AutomaGuardAdvisor;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.ai.openai.api.OpenAiApi;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public final class Agent {

    public static void main(String[] args) throws Exception {
        // ── Policy path ───────────────────────────────────────────────────────
        Path policyPath = Paths.get(
                System.getProperty("user.dir"),
                "../customer_data_guard.aegisc").toAbsolutePath().normalize();

        if (!Files.exists(policyPath)) {
            System.err.println("Policy bytecode not found at " + policyPath);
            System.err.println("Compile it first:");
            System.err.println("  aegisc compile examples/customer_data_guard.aegis" +
                               " -o examples/customer_data_guard.aegisc");
            System.exit(1);
        }

        // ── Mode selection ────────────────────────────────────────────────────
        boolean safe   = Arrays.asList(args).contains("--safe");
        String  mode   = safe ? "safe" : "unsafe";
        String  prompt = safe ? Prompts.SAFE : Prompts.UNSAFE;

        System.out.println("\n=== AutomaGuard Java Example (" + mode + " run) ===\n");
        System.out.println("Prompt: " + prompt + "\n");

        // ── API key ───────────────────────────────────────────────────────────
        String apiKey = System.getenv("OPENAI_API_KEY");
        if (apiKey == null || apiKey.isBlank()) {
            System.err.println("Error: OPENAI_API_KEY environment variable is not set.");
            System.exit(1);
        }

        // ── Spring AI setup ───────────────────────────────────────────────────
        var openAiApi = new OpenAiApi(apiKey);
        var chatModel = new OpenAiChatModel(openAiApi,
                OpenAiChatOptions.builder().model("gpt-4o").build());

        var advisor = new AutomaGuardAdvisor(
                policyPath.toString(),
                (result, toolName) -> System.out.println(
                        "  [audit] " + toolName + ": " + result.getReason() +
                        " (rules: " + result.getTriggeredRules() + ")")
        );

        var client = ChatClient.builder(chatModel)
                .defaultAdvisors(advisor)
                .defaultTools(new CustomerDataTools())
                .build();

        // ── Run ───────────────────────────────────────────────────────────────
        try {
            String result = client.prompt(prompt).call().content();
            System.out.println("\nResult: " + result);
            System.exit(0);
        } catch (EnforcementException ex) {
            System.err.println("\nBLOCKED by AutomaGuard policy:");
            System.err.println("  Reason:  " + ex.getMessage());
            System.err.println("  Verdict: " + ex.getResult().getVerdict());
            if (!ex.getResult().getTriggeredRules().isEmpty()) {
                System.err.println("  Rules:   " + ex.getResult().getTriggeredRules());
            }
            ex.getResult().getViolations().forEach(v ->
                System.err.println("  Invariant: " + v));
            ex.getResult().getConstraintViolations().forEach(cv ->
                System.err.println("  Constraint: " + cv));
            System.exit(1);
        } finally {
            advisor.close();
        }
    }
}

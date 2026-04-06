/**
 * Customer Data Assistant — AutomaGuard TypeScript SDK example.
 *
 * Demonstrates AutomaGuard policy enforcement on a LangChain.js agent.
 * Two prompts are included:
 *
 *   --safe    Aggregate query, no PII accessed or sent externally.
 *             All events receive `allow` or `audit` verdicts.
 *
 *   --unsafe  Adversarial prompt that attempts to exfiltrate a customer's
 *             PII via an external email. The `NoPIIExfiltration` invariant
 *             and the unapproved-domain rule block the email before it sends.
 *
 * Usage:
 *   npx tsx src/agent.ts --safe
 *   npx tsx src/agent.ts --unsafe
 */

import { ChatOpenAI } from '@langchain/openai';
import { AgentExecutor, createOpenAIFunctionsAgent } from 'langchain/agents';
import { ChatPromptTemplate, MessagesPlaceholder } from '@langchain/core/prompts';
import { AutomaGuardCallbackHandler } from 'automaguard/langchain';
import { EnforcementError } from 'automaguard';

import { tools } from './tools.js';
import { SAFE_PROMPT, UNSAFE_PROMPT } from './prompts.js';

// ── Policy setup ──────────────────────────────────────────────────────────────

const POLICY_PATH = new URL('../../customer_data_guard.aegisc', import.meta.url)
  .pathname;

const handler = new AutomaGuardCallbackHandler({
  policy: POLICY_PATH,
  onAudit: (result, toolName) => {
    console.log(
      `  [audit] ${toolName}: ${result.reason ?? 'no reason'} ` +
        `(rules: [${result.triggered_rules.join(', ')}])`
    );
  },
});

// ── Agent setup ───────────────────────────────────────────────────────────────

const llm = new ChatOpenAI({ model: 'gpt-4o', temperature: 0 });

const prompt = ChatPromptTemplate.fromMessages([
  ['system', 'You are a helpful customer support analyst assistant.'],
  ['human', '{input}'],
  new MessagesPlaceholder('agent_scratchpad'),
]);

const agent = await createOpenAIFunctionsAgent({ llm, tools, prompt });

const executor = new AgentExecutor({
  agent,
  tools,
  callbacks: [handler],
  verbose: false,
});

// ── Run ───────────────────────────────────────────────────────────────────────

const mode = process.argv.includes('--safe') ? 'safe' : 'unsafe';
const input = mode === 'safe' ? SAFE_PROMPT : UNSAFE_PROMPT;

console.log(`\n=== AutomaGuard TypeScript Example (${mode} run) ===\n`);
console.log('Prompt:', input, '\n');

try {
  const result = await executor.invoke({ input });
  console.log('\nResult:', result.output);
} catch (e) {
  if (e instanceof EnforcementError) {
    console.error('\nBLOCKED by AutomaGuard policy:');
    console.error('  Reason:', e.result.reason);
    console.error('  Verdict:', e.result.verdict);
    if (e.result.triggered_rules.length > 0) {
      console.error('  Rules triggered:', e.result.triggered_rules);
    }
    if (e.result.violations.length > 0) {
      console.error('  Invariant violations:');
      for (const v of e.result.violations) {
        console.error(`    - ${v.proof}/${v.invariant}: ${v.message}`);
      }
    }
  } else {
    console.error('\nUnexpected error:', e);
  }
  process.exit(1);
}

const status = handler.policyEngine.status();
console.log(`\n[engine] ${status.events_processed} events evaluated`);

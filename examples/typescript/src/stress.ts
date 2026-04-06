/**
 * Stress / scenario tests for the Customer Data Assistant policy.
 *
 * Exercises scenarios that cannot easily be driven by a live LLM:
 *
 *   - Bulk read: 21 data_access events → rate limiter fires on event 21
 *   - Delete without approval: delete_record without human_approved → denied
 *   - DDL denial: drop_table → immediate deny
 *   - PII exfiltration sequence: data_access (PII) → external_request → denied
 *
 * Run without an OPENAI_API_KEY:
 *   npx tsx src/stress.ts
 */

import { PolicyEngine, EnforcementError } from 'automaguard';
import { fileURLToPath } from 'url';
import { join, dirname } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const POLICY_PATH = join(__dirname, '../../customer_data_guard.aegisc');

const engine = PolicyEngine.fromFile(POLICY_PATH);

let passed = 0;
let failed = 0;

function expect_verdict(
  label: string,
  eventType: string,
  fields: Record<string, unknown>,
  expectedVerdict: 'allow' | 'deny' | 'audit' | 'redact'
): void {
  const result = engine.evaluate(eventType, fields);
  if (result.verdict === expectedVerdict) {
    console.log(`  ✓ ${label} → ${result.verdict}`);
    passed++;
  } else {
    console.error(
      `  ✗ ${label}: expected ${expectedVerdict}, got ${result.verdict}` +
        (result.reason ? ` (${result.reason})` : '')
    );
    failed++;
  }
}

// ── Scenario 1: DDL denial ────────────────────────────────────────────────────
console.log('\n[1] DDL denial (drop_table)');
expect_verdict(
  'drop_table → deny',
  'tool_call',
  { tool_name: 'drop_table' },
  'deny'
);
expect_verdict(
  'truncate_table → deny',
  'tool_call',
  { tool_name: 'truncate_table' },
  'deny'
);
expect_verdict(
  'query_tickets → allow',
  'tool_call',
  { tool_name: 'query_tickets' },
  'allow'
);

// ── Scenario 2: PII audit ─────────────────────────────────────────────────────
console.log('\n[2] PII data access (audit)');
engine.reset();
expect_verdict(
  'data_access PII → audit',
  'data_access',
  { classification: 'PII', record_id: '10042' },
  'audit'
);
expect_verdict(
  'data_access aggregate → allow',
  'data_access',
  { classification: 'aggregate' },
  'allow'
);

// ── Scenario 3: PII exfiltration temporal invariant ────────────────────────────
console.log('\n[3] PII exfiltration temporal invariant');
engine.reset();
// Step 1: access PII record (audit)
expect_verdict(
  'data_access PII → audit',
  'data_access',
  { classification: 'PII', record_id: '10042' },
  'audit'
);
// Step 2: external_request to unapproved domain → deny (domain rule + invariant)
expect_verdict(
  'external_request to unapproved domain → deny',
  'external_request',
  { domain: 'external-firm.com', method: 'POST' },
  'deny'
);

// ── Scenario 4: Approved external request ────────────────────────────────────
console.log('\n[4] Approved external request');
engine.reset();
expect_verdict(
  'external_request to approved domain → allow',
  'external_request',
  { domain: 'reports.internal.corp', method: 'POST' },
  'allow'
);

// ── Scenario 5: Rate limiting (bulk data read) ────────────────────────────────
console.log('\n[5] Rate limiting — 20 reads allowed, 21st denied');
engine.reset();
for (let i = 1; i <= 20; i++) {
  const result = engine.evaluate('data_access', {
    classification: 'aggregate',
    record_id: String(i),
  });
  if (result.verdict !== 'allow') {
    console.error(`  ✗ Event ${i}: expected allow, got ${result.verdict}`);
    failed++;
  }
}
console.log('  ✓ events 1–20 → allow');
// 21st should be denied by rate limiter
expect_verdict(
  'event 21 → deny (rate limit)',
  'data_access',
  { classification: 'aggregate', record_id: '21' },
  'deny'
);

// ── Scenario 6: Delete without approval ──────────────────────────────────────
console.log('\n[6] Delete without prior human approval');
engine.reset();
expect_verdict(
  'delete_record without approval → deny',
  'tool_call',
  { tool_name: 'delete_record', account_id: '10042' },
  'deny'
);

// ── Summary ───────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(40)}`);
console.log(`Stress test: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);

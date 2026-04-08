import { NextResponse } from "next/server";
import * as fs from "fs";
import * as readline from "readline";
import type { AuditEntry, AuditResponse, AuditStats, Verdict } from "@/lib/types";

// Generate synthetic entries for the demo mode (no log file configured).
function generateDemoEntries(): AuditEntry[] {
  const eventTypes = [
    "tool_call",
    "data_access",
    "file_write",
    "network_request",
    "shell_exec",
  ];
  const policies = ["research_guard", "filesystem_guard", "network_guard"];
  const verdicts: Verdict[] = ["Allow", "Deny", "Audit", "Redact"];
  const verdictWeights = [0.65, 0.15, 0.15, 0.05];

  const now = Date.now();
  const entries: AuditEntry[] = [];

  for (let i = 0; i < 120; i++) {
    const roll = Math.random();
    let cumulative = 0;
    let verdict = verdicts[0];
    for (let v = 0; v < verdicts.length; v++) {
      cumulative += verdictWeights[v];
      if (roll < cumulative) {
        verdict = verdicts[v];
        break;
      }
    }

    const isDeny = verdict === "Deny";
    const evalUs = Math.floor(Math.random() * 800 + 50);

    entries.push({
      id: i,
      timestamp_ms: now - (120 - i) * 5000 - Math.floor(Math.random() * 2000),
      policy_name: policies[Math.floor(Math.random() * policies.length)],
      event_type: eventTypes[Math.floor(Math.random() * eventTypes.length)],
      verdict,
      reason: isDeny
        ? "Matched deny rule: sensitive path access"
        : verdict === "Audit"
          ? "Matched audit rule: external network call"
          : null,
      triggered_rules: isDeny
        ? [Math.floor(Math.random() * 5)]
        : verdict === "Audit"
          ? [Math.floor(Math.random() * 5)]
          : [],
      violation_count: isDeny ? 1 : 0,
      violations: isDeny
        ? [
            {
              proof_name: "no_sensitive_access",
              invariant_name: "never access /etc/passwd",
              message: "Agent attempted to read /etc/passwd",
            },
          ]
        : [],
      constraint_violations: [],
      eval_time_us: evalUs,
    });
  }

  return entries.sort((a, b) => a.timestamp_ms - b.timestamp_ms);
}

function computeStats(entries: AuditEntry[]): AuditStats {
  const total = entries.length;
  const allows = entries.filter((e) => e.verdict === "Allow").length;
  const denies = entries.filter((e) => e.verdict === "Deny").length;
  const audits = entries.filter((e) => e.verdict === "Audit").length;
  const redacts = entries.filter((e) => e.verdict === "Redact").length;
  const violations = entries.filter((e) => e.violation_count > 0).length;
  const avgEvalUs =
    total > 0
      ? Math.round(
          entries.reduce((s, e) => s + e.eval_time_us, 0) / total,
        )
      : 0;
  const maxEvalUs =
    total > 0 ? Math.max(...entries.map((e) => e.eval_time_us)) : 0;

  return {
    total_entries: total,
    buffered_entries: total,
    allows,
    denies,
    audits,
    redacts,
    violations,
    avg_eval_us: avgEvalUs,
    max_eval_us: maxEvalUs,
  };
}

async function readJsonlFile(path: string): Promise<AuditEntry[]> {
  const entries: AuditEntry[] = [];
  const stream = fs.createReadStream(path, { encoding: "utf8" });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      entries.push(JSON.parse(trimmed) as AuditEntry);
    } catch {
      // skip malformed lines
    }
  }

  return entries;
}

export async function GET(): Promise<NextResponse> {
  const logPath = process.env.AUDIT_LOG_PATH;

  let entries: AuditEntry[];
  let source: string;

  if (logPath && fs.existsSync(logPath)) {
    try {
      entries = await readJsonlFile(logPath);
      source = logPath;
    } catch {
      entries = generateDemoEntries();
      source = "demo (file read error)";
    }
  } else {
    entries = generateDemoEntries();
    source = "demo";
  }

  const stats = computeStats(entries);

  const body: AuditResponse = { entries, stats, source };
  return NextResponse.json(body);
}

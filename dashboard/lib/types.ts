// Mirrors AuditEntry in aegis-runtime/src/audit.rs

export type Verdict = "Allow" | "Deny" | "Audit" | "Redact";

export interface ViolationEntry {
  proof_name: string;
  invariant_name: string;
  message: string;
}

export interface ConstraintViolationEntry {
  kind: string;
  target: string;
  limit: number;
  current: number;
}

export interface AuditEntry {
  id: number;
  timestamp_ms: number;
  policy_name: string;
  event_type: string;
  verdict: Verdict;
  reason: string | null;
  triggered_rules: number[];
  violation_count: number;
  violations: ViolationEntry[];
  constraint_violations: ConstraintViolationEntry[];
  eval_time_us: number;
}

export interface AuditStats {
  total_entries: number;
  buffered_entries: number;
  allows: number;
  denies: number;
  audits: number;
  redacts: number;
  violations: number;
  avg_eval_us: number;
  max_eval_us: number;
}

export interface AuditResponse {
  entries: AuditEntry[];
  stats: AuditStats;
  source: string;
}

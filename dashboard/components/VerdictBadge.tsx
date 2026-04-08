import type { Verdict } from "@/lib/types";

const styles: Record<Verdict, string> = {
  Allow: "bg-emerald-900/50 text-emerald-300 border border-emerald-700",
  Deny: "bg-red-900/50 text-red-300 border border-red-700",
  Audit: "bg-amber-900/50 text-amber-300 border border-amber-700",
  Redact: "bg-violet-900/50 text-violet-300 border border-violet-700",
};

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-mono font-semibold ${styles[verdict]}`}
    >
      {verdict.toUpperCase()}
    </span>
  );
}

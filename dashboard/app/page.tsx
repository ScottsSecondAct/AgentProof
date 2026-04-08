import type { AuditResponse } from "@/lib/types";
import { StatCard } from "@/components/StatCard";
import { VerdictChart } from "@/components/VerdictChart";
import { LatencyChart } from "@/components/LatencyChart";
import { AuditTable } from "@/components/AuditTable";

async function getAuditData(): Promise<AuditResponse> {
  const res = await fetch("http://localhost:3000/api/audit", {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch audit data");
  return res.json();
}

export default async function DashboardPage() {
  const data = await getAuditData();
  const { stats, entries, source } = data;

  const allowPct =
    stats.total_entries > 0
      ? Math.round((stats.allows / stats.total_entries) * 100)
      : 0;

  const isDemo = source === "demo" || source.startsWith("demo (");

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      {/* Header */}
      <header className="border-b border-zinc-800 bg-zinc-900/80 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <span className="text-lg font-bold tracking-tight">AutomaGuard</span>
            <span className="rounded bg-indigo-900/60 px-2 py-0.5 text-xs font-mono text-indigo-300 border border-indigo-700">
              Compliance Dashboard
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs text-zinc-500">
            {isDemo && (
              <span className="rounded border border-amber-700 bg-amber-900/40 px-2 py-0.5 text-amber-300">
                demo mode
              </span>
            )}
            <span className="font-mono truncate max-w-xs">{source}</span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-8 space-y-6">
        {/* Stat cards */}
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
          <StatCard label="Total Events" value={stats.total_entries.toLocaleString()} />
          <StatCard
            label="Allow"
            value={stats.allows.toLocaleString()}
            sub={`${allowPct}%`}
            accent="text-emerald-400"
          />
          <StatCard
            label="Deny"
            value={stats.denies.toLocaleString()}
            accent="text-red-400"
          />
          <StatCard
            label="Audit"
            value={stats.audits.toLocaleString()}
            accent="text-amber-400"
          />
          <StatCard
            label="Redact"
            value={stats.redacts.toLocaleString()}
            accent="text-violet-400"
          />
          <StatCard
            label="Avg Latency"
            value={`${(stats.avg_eval_us / 1000).toFixed(2)}ms`}
            sub={`max ${(stats.max_eval_us / 1000).toFixed(2)}ms`}
            accent={stats.max_eval_us > 10000 ? "text-red-400" : "text-indigo-400"}
          />
        </div>

        {/* Charts row */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <VerdictChart stats={stats} />
          <LatencyChart entries={entries} />
        </div>

        {/* Audit log table */}
        <AuditTable entries={entries} />
      </main>
    </div>
  );
}

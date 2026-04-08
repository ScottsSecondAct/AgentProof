"use client";

import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import type { AuditStats } from "@/lib/types";

const COLORS: Record<string, string> = {
  Allow: "#10b981",
  Deny: "#ef4444",
  Audit: "#f59e0b",
  Redact: "#8b5cf6",
};

interface Props {
  stats: AuditStats;
}

export function VerdictChart({ stats }: Props) {
  const data = [
    { name: "Allow", value: stats.allows },
    { name: "Deny", value: stats.denies },
    { name: "Audit", value: stats.audits },
    { name: "Redact", value: stats.redacts },
  ].filter((d) => d.value > 0);

  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-900 p-4">
      <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-zinc-400">
        Verdict Distribution
      </h2>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={90}
            paddingAngle={2}
            dataKey="value"
          >
            {data.map((entry) => (
              <Cell key={entry.name} fill={COLORS[entry.name]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: "#18181b",
              border: "1px solid #3f3f46",
              borderRadius: "6px",
              color: "#f4f4f5",
              fontSize: "12px",
            }}
            formatter={(value, name) => [value as number, name as string]}
          />
          <Legend
            formatter={(value) => (
              <span style={{ color: "#a1a1aa", fontSize: 12 }}>{value}</span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

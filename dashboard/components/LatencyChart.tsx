"use client";

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";
import type { AuditEntry } from "@/lib/types";

interface Props {
  entries: AuditEntry[];
}

export function LatencyChart({ entries }: Props) {
  // Bucket into last 60 entries for the chart
  const data = entries.slice(-60).map((e, i) => ({
    i,
    us: e.eval_time_us,
    ms: (e.eval_time_us / 1000).toFixed(2),
  }));

  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-900 p-4">
      <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-zinc-400">
        Evaluation Latency (last 60 events)
      </h2>
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="latencyGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis dataKey="i" hide />
          <YAxis
            tickFormatter={(v) => `${(v / 1000).toFixed(1)}ms`}
            tick={{ fill: "#71717a", fontSize: 11 }}
            width={52}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "#18181b",
              border: "1px solid #3f3f46",
              borderRadius: "6px",
              color: "#f4f4f5",
              fontSize: "12px",
            }}
            formatter={(value) => [
              `${((value as number) / 1000).toFixed(3)} ms`,
              "latency",
            ]}
            labelFormatter={() => ""}
          />
          {/* 10ms SLA line */}
          <ReferenceLine
            y={10000}
            stroke="#ef4444"
            strokeDasharray="4 4"
            label={{
              value: "10ms SLA",
              fill: "#ef4444",
              fontSize: 10,
              position: "insideTopRight",
            }}
          />
          <Area
            type="monotone"
            dataKey="us"
            stroke="#6366f1"
            strokeWidth={1.5}
            fill="url(#latencyGrad)"
            dot={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

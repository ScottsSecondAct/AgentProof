"use client";

import { useState, useMemo } from "react";
import type { AuditEntry, Verdict } from "@/lib/types";
import { VerdictBadge } from "./VerdictBadge";

interface Props {
  entries: AuditEntry[];
}

const ALL = "All";

export function AuditTable({ entries }: Props) {
  const [verdictFilter, setVerdictFilter] = useState<string>(ALL);
  const [eventFilter, setEventFilter] = useState<string>(ALL);
  const [policyFilter, setPolicyFilter] = useState<string>(ALL);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);

  const PAGE_SIZE = 25;

  const verdicts = useMemo(
    () => [ALL, ...Array.from(new Set(entries.map((e) => e.verdict))).sort()],
    [entries],
  );
  const eventTypes = useMemo(
    () => [ALL, ...Array.from(new Set(entries.map((e) => e.event_type))).sort()],
    [entries],
  );
  const policies = useMemo(
    () => [ALL, ...Array.from(new Set(entries.map((e) => e.policy_name))).sort()],
    [entries],
  );

  const filtered = useMemo(() => {
    return [...entries]
      .reverse()
      .filter((e) => {
        if (verdictFilter !== ALL && e.verdict !== verdictFilter) return false;
        if (eventFilter !== ALL && e.event_type !== eventFilter) return false;
        if (policyFilter !== ALL && e.policy_name !== policyFilter) return false;
        if (search) {
          const q = search.toLowerCase();
          if (
            !e.event_type.toLowerCase().includes(q) &&
            !e.policy_name.toLowerCase().includes(q) &&
            !(e.reason ?? "").toLowerCase().includes(q)
          )
            return false;
        }
        return true;
      });
  }, [entries, verdictFilter, eventFilter, policyFilter, search]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const page_ = Math.min(page, Math.max(0, totalPages - 1));
  const visible = filtered.slice(page_ * PAGE_SIZE, (page_ + 1) * PAGE_SIZE);

  function handleFilterChange(setter: (v: string) => void) {
    return (e: React.ChangeEvent<HTMLSelectElement>) => {
      setter(e.target.value);
      setPage(0);
    };
  }

  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-900">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3 border-b border-zinc-700 p-4">
        <h2 className="mr-auto text-sm font-semibold uppercase tracking-wider text-zinc-400">
          Audit Log
        </h2>
        <input
          type="text"
          placeholder="Search..."
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(0); }}
          className="rounded border border-zinc-600 bg-zinc-800 px-3 py-1.5 text-xs text-zinc-200 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none w-40"
        />
        <Select label="Verdict" value={verdictFilter} options={verdicts} onChange={handleFilterChange(setVerdictFilter)} />
        <Select label="Event" value={eventFilter} options={eventTypes} onChange={handleFilterChange(setEventFilter)} />
        <Select label="Policy" value={policyFilter} options={policies} onChange={handleFilterChange(setPolicyFilter)} />
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-zinc-700 text-left text-zinc-500">
              <th className="px-4 py-2 font-medium">#</th>
              <th className="px-4 py-2 font-medium">Time</th>
              <th className="px-4 py-2 font-medium">Policy</th>
              <th className="px-4 py-2 font-medium">Event</th>
              <th className="px-4 py-2 font-medium">Verdict</th>
              <th className="px-4 py-2 font-medium">Reason</th>
              <th className="px-4 py-2 font-medium text-right">Latency</th>
            </tr>
          </thead>
          <tbody>
            {visible.length === 0 && (
              <tr>
                <td colSpan={7} className="py-10 text-center text-zinc-500">
                  No entries match the current filters.
                </td>
              </tr>
            )}
            {visible.map((e) => (
              <Row key={e.id} entry={e} />
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between border-t border-zinc-700 px-4 py-2">
          <span className="text-xs text-zinc-500">
            {filtered.length} entries · page {page_ + 1} of {totalPages}
          </span>
          <div className="flex gap-2">
            <PagBtn onClick={() => setPage(0)} disabled={page_ === 0}>«</PagBtn>
            <PagBtn onClick={() => setPage(page_ - 1)} disabled={page_ === 0}>‹</PagBtn>
            <PagBtn onClick={() => setPage(page_ + 1)} disabled={page_ >= totalPages - 1}>›</PagBtn>
            <PagBtn onClick={() => setPage(totalPages - 1)} disabled={page_ >= totalPages - 1}>»</PagBtn>
          </div>
        </div>
      )}
    </div>
  );
}

function Row({ entry }: { entry: AuditEntry }) {
  const [open, setOpen] = useState(false);
  const ts = new Date(entry.timestamp_ms).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  const latencyMs = (entry.eval_time_us / 1000).toFixed(2);
  const latencyColor =
    entry.eval_time_us > 10000
      ? "text-red-400"
      : entry.eval_time_us > 5000
        ? "text-amber-400"
        : "text-zinc-400";

  return (
    <>
      <tr
        className="cursor-pointer border-b border-zinc-800 hover:bg-zinc-800/50 transition-colors"
        onClick={() => setOpen((o) => !o)}
      >
        <td className="px-4 py-2 font-mono text-zinc-500">{entry.id}</td>
        <td className="px-4 py-2 font-mono text-zinc-400">{ts}</td>
        <td className="px-4 py-2 text-zinc-300">{entry.policy_name}</td>
        <td className="px-4 py-2 font-mono text-zinc-300">{entry.event_type}</td>
        <td className="px-4 py-2">
          <VerdictBadge verdict={entry.verdict as Verdict} />
        </td>
        <td className="px-4 py-2 max-w-xs truncate text-zinc-400">
          {entry.reason ?? <span className="text-zinc-600">—</span>}
        </td>
        <td className={`px-4 py-2 text-right font-mono ${latencyColor}`}>
          {latencyMs}ms
        </td>
      </tr>
      {open && (entry.violations.length > 0 || entry.triggered_rules.length > 0) && (
        <tr className="border-b border-zinc-800 bg-zinc-950">
          <td colSpan={7} className="px-6 py-3">
            {entry.violations.length > 0 && (
              <div className="mb-2">
                <p className="mb-1 text-xs font-semibold text-red-400">Violations</p>
                {entry.violations.map((v, i) => (
                  <p key={i} className="text-xs text-zinc-400">
                    <span className="font-mono text-red-300">{v.invariant_name}</span>{" "}
                    — {v.message}
                  </p>
                ))}
              </div>
            )}
            {entry.triggered_rules.length > 0 && (
              <p className="text-xs text-zinc-500">
                Rules triggered:{" "}
                <span className="font-mono text-zinc-300">
                  {entry.triggered_rules.join(", ")}
                </span>
              </p>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

function Select({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (e: React.ChangeEvent<HTMLSelectElement>) => void;
}) {
  return (
    <select
      value={value}
      onChange={onChange}
      className="rounded border border-zinc-600 bg-zinc-800 px-2 py-1.5 text-xs text-zinc-200 focus:border-indigo-500 focus:outline-none"
      aria-label={label}
    >
      {options.map((o) => (
        <option key={o} value={o}>
          {o === "All" ? `${label}: All` : o}
        </option>
      ))}
    </select>
  );
}

function PagBtn({
  onClick,
  disabled,
  children,
}: {
  onClick: () => void;
  disabled: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="rounded border border-zinc-600 bg-zinc-800 px-2 py-0.5 text-xs text-zinc-300 disabled:opacity-30 hover:bg-zinc-700"
    >
      {children}
    </button>
  );
}

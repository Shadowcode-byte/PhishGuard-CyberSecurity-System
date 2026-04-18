"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { History, Globe, MessageSquare, FileSearch, AlertTriangle, CheckCircle, Info, ChevronLeft, ChevronRight } from "lucide-react";
import { userApi } from "@/lib/api";
import { clsx } from "clsx";

const SCAN_TYPE_ICONS = {
  url: Globe,
  message: MessageSquare,
  file: FileSearch,
};

const LABEL_STYLES = {
  PHISHING: "badge-threat",
  FRAUD: "badge-threat",
  SUSPICIOUS: "badge-suspicious",
  SAFE: "badge-safe",
};

export default function HistoryPage() {
  const [page, setPage] = useState(1);
  const [filter, setFilter] = useState("");
  const perPage = 20;

  const { data, isLoading } = useQuery({
    queryKey: ["history", page, filter],
    queryFn: () => userApi.history(page, perPage, filter || undefined).then((r) => r.data),
  });

  const totalPages = data ? Math.ceil(data.total / perPage) : 0;

  return (
    <div className="p-8">
      <div className="mb-8">
        <div className="flex items-center gap-2 mb-1">
          <History className="w-4 h-4 text-neon-cyan" />
          <span className="text-neon-cyan font-mono text-xs uppercase tracking-widest">Scan Records</span>
        </div>
        <h1 className="font-display text-2xl font-bold text-text-primary">Scan History</h1>
      </div>

      {/* Filters */}
      <div className="flex gap-3 mb-6">
        {["", "url", "message", "file"].map((type) => (
          <button
            key={type}
            onClick={() => { setFilter(type); setPage(1); }}
            className={clsx(
              "px-4 py-2 rounded-lg text-xs font-mono border transition-all",
              filter === type
                ? "border-neon-cyan/40 bg-neon-cyan/10 text-neon-cyan"
                : "border-cyber-border text-text-secondary hover:border-cyber-border hover:text-text-primary"
            )}
          >
            {type === "" ? "All" : type.charAt(0).toUpperCase() + type.slice(1)}
          </button>
        ))}
        {data && (
          <span className="ml-auto text-text-secondary text-xs font-mono self-center">
            {data.total} total records
          </span>
        )}
      </div>

      {/* Table */}
      <div className="cyber-card overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-cyber-border">
              {["Type", "Input", "Label", "Confidence", "Time"].map((h) => (
                <th key={h} className="px-5 py-3.5 text-left text-xs font-mono uppercase tracking-wider text-text-secondary">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              Array.from({ length: 8 }).map((_, i) => (
                <tr key={i} className="border-b border-cyber-border/50">
                  {Array.from({ length: 5 }).map((_, j) => (
                    <td key={j} className="px-5 py-4">
                      <div className="h-3 bg-cyber-border rounded animate-pulse" style={{ width: `${60 + j * 10}%` }} />
                    </td>
                  ))}
                </tr>
              ))
            ) : data?.items.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-5 py-12 text-center text-text-secondary font-mono text-sm">
                  No scans yet. Start scanning to see history here.
                </td>
              </tr>
            ) : (
              data?.items.map((item: any) => {
                const Icon = SCAN_TYPE_ICONS[item.scan_type as keyof typeof SCAN_TYPE_ICONS] || Globe;
                const labelClass = LABEL_STYLES[item.label as keyof typeof LABEL_STYLES] || "badge-safe";
                return (
                  <tr key={item.id} className="border-b border-cyber-border/30 hover:bg-white/[0.02] transition-colors">
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-2">
                        <Icon className="w-3.5 h-3.5 text-text-secondary" />
                        <span className="text-xs font-mono text-text-secondary capitalize">{item.scan_type}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3.5 max-w-xs">
                      <span className="text-xs font-mono text-text-primary truncate block">{item.input_data}</span>
                    </td>
                    <td className="px-5 py-3.5">
                      <span className={clsx("text-xs font-mono px-2 py-0.5 rounded", labelClass)}>
                        {item.label}
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="text-xs font-mono text-text-secondary">
                        {Math.round(item.confidence * 100)}%
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="text-xs font-mono text-text-secondary">
                        {new Date(item.created_at).toLocaleString()}
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3 mt-5">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="p-2 rounded-lg border border-cyber-border text-text-secondary hover:text-text-primary disabled:opacity-30 transition-all"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="text-text-secondary text-xs font-mono">
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="p-2 rounded-lg border border-cyber-border text-text-secondary hover:text-text-primary disabled:opacity-30 transition-all"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      )}
    </div>
  );
}

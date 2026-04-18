"use client";
import { useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Activity, ChevronLeft, ChevronRight, Shield,
  Search, Filter, X, RefreshCw, Clock, User,
  Globe, LogIn, LogOut, Trash2, Key, AlertTriangle,
} from "lucide-react";
import { adminApi } from "@/lib/api";

// ── Action config ─────────────────────────────────────────────────────────────
const ACTION_FILTERS = [
  { value: "all",         label: "All Actions" },
  { value: "user.login",  label: "Logins" },
  { value: "user.logout", label: "Logouts" },
  { value: "user.register", label: "Registrations" },
  { value: "scan.",       label: "Scans" },
  { value: "admin.",      label: "Admin Actions" },
  { value: "failed",      label: "Failures" },
];

function getActionMeta(action: string): { color: string; bg: string; border: string; icon: React.ElementType } {
  if (action.includes("failed") || action.includes("error"))
    return { color: "#ff2d55", bg: "rgba(255,45,85,0.08)",  border: "rgba(255,45,85,0.25)",  icon: AlertTriangle };
  if (action.includes("login"))
    return { color: "#00f5ff", bg: "rgba(0,245,255,0.08)",  border: "rgba(0,245,255,0.25)",  icon: LogIn };
  if (action.includes("logout"))
    return { color: "#8892b0", bg: "rgba(136,146,176,0.06)", border: "rgba(136,146,176,0.2)", icon: LogOut };
  if (action.includes("register") || action.includes("create"))
    return { color: "#00ff88", bg: "rgba(0,255,136,0.08)",  border: "rgba(0,255,136,0.25)",  icon: User };
  if (action.includes("delete"))
    return { color: "#ff2d55", bg: "rgba(255,45,85,0.08)",  border: "rgba(255,45,85,0.25)",  icon: Trash2 };
  if (action.includes("role") || action.includes("admin"))
    return { color: "#ffd60a", bg: "rgba(255,214,10,0.08)", border: "rgba(255,214,10,0.25)", icon: Shield };
  if (action.includes("password") || action.includes("reset"))
    return { color: "#ffd60a", bg: "rgba(255,214,10,0.08)", border: "rgba(255,214,10,0.25)", icon: Key };
  if (action.includes("scan"))
    return { color: "#bf5af2", bg: "rgba(191,90,242,0.08)", border: "rgba(191,90,242,0.25)", icon: Globe };
  return { color: "#8892b0", bg: "rgba(136,146,176,0.06)", border: "rgba(136,146,176,0.2)", icon: Activity };
}

function formatAction(action: string): string {
  return action
    .replace(/\./g, " › ")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)  return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function AuditLogsPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [actionFilter, setActionFilter] = useState("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const queryParams = {
    search: search || undefined,
    action_filter: actionFilter !== "all" ? actionFilter : undefined,
  };

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["admin-logs", page, search, actionFilter],
    queryFn: () => adminApi.logs(page, queryParams).then((r) => r.data),
  });

  const totalPages = data ? Math.ceil((data.total ?? 0) / 50) : 0;

  const handleSearch = useCallback((val: string) => {
    setSearch(val);
    setPage(1);
  }, []);

  const handleFilter = useCallback((val: string) => {
    setActionFilter(val);
    setPage(1);
  }, []);

  return (
    <div className="p-6 max-w-7xl">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-2 mb-1">
          <Activity className="w-4 h-4" style={{ color: "#ffd60a" }} />
          <span className="font-mono text-xs uppercase tracking-widest" style={{ color: "#ffd60a" }}>Security</span>
        </div>
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div>
            <h1 className="font-display text-2xl font-bold" style={{ color: "#e8eaf0" }}>Audit Logs</h1>
            <p className="font-mono text-sm mt-1" style={{ color: "#8892b0" }}>
              Full platform activity trail · {data?.total ?? "—"} entries
            </p>
          </div>
          <button
            onClick={() => refetch()}
            className="flex items-center gap-2 px-3 py-2 rounded-lg border font-mono text-xs transition-all"
            style={{ borderColor: "#1a2540", color: "#8892b0" }}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-5">
        {/* Search */}
        <div className="relative flex-1 min-w-52">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: "#8892b0" }} />
          <input
            placeholder="Search action, IP, details…"
            value={search}
            onChange={(e) => handleSearch(e.target.value)}
            className="w-full bg-cyber-dark border border-cyber-border rounded-lg pl-9 pr-8 py-2 text-sm font-mono outline-none focus:border-neon-cyan/40"
            style={{ color: "#e8eaf0" }}
          />
          {search && (
            <button onClick={() => handleSearch("")} className="absolute right-3 top-1/2 -translate-y-1/2">
              <X className="w-3.5 h-3.5" style={{ color: "#8892b0" }} />
            </button>
          )}
        </div>

        {/* Action filter */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {ACTION_FILTERS.map((f) => (
            <button
              key={f.value}
              onClick={() => handleFilter(f.value)}
              className="px-3 py-1.5 rounded-lg font-mono text-xs border transition-all"
              style={
                actionFilter === f.value
                  ? { background: "rgba(255,214,10,0.1)", borderColor: "rgba(255,214,10,0.3)", color: "#ffd60a" }
                  : { background: "transparent", borderColor: "#1a2540", color: "#8892b0" }
              }
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {/* Log entries */}
      <div className="cyber-card overflow-hidden">
        {isLoading ? (
          <div className="p-6 space-y-3">
            {Array.from({ length: 10 }).map((_, i) => (
              <div key={i} className="flex items-center gap-4 p-3 rounded-lg" style={{ background: "#050810" }}>
                <div className="w-7 h-7 rounded-lg bg-cyber-border animate-pulse shrink-0" />
                <div className="flex-1 space-y-2">
                  <div className="h-3 bg-cyber-border rounded animate-pulse" style={{ width: "30%" }} />
                  <div className="h-2 bg-cyber-border rounded animate-pulse" style={{ width: "60%" }} />
                </div>
                <div className="h-2 bg-cyber-border rounded animate-pulse w-20" />
              </div>
            ))}
          </div>
        ) : !data?.items?.length ? (
          <div className="p-12 text-center">
            <Activity className="w-8 h-8 mx-auto mb-3" style={{ color: "#8892b0" }} />
            <p className="font-mono text-sm" style={{ color: "#8892b0" }}>No audit log entries found.</p>
          </div>
        ) : (
          <div className="divide-y" style={{ borderColor: "rgba(26,37,64,0.4)" }}>
            {data.items.map((log: any, i: number) => {
              const meta = getActionMeta(log.action);
              const Icon = meta.icon;
              const isExpanded = expandedId === log.id;

              return (
                <motion.div
                  key={log.id}
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.02 }}
                >
                  <div
                    className="flex items-start gap-4 px-5 py-3.5 cursor-pointer transition-colors hover:bg-white/[0.015]"
                    onClick={() => setExpandedId(isExpanded ? null : log.id)}
                  >
                    {/* Icon */}
                    <div
                      className="w-7 h-7 rounded-lg flex items-center justify-center border shrink-0 mt-0.5"
                      style={{ background: meta.bg, borderColor: meta.border }}
                    >
                      <Icon className="w-3.5 h-3.5" style={{ color: meta.color }} />
                    </div>

                    {/* Action + user */}
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs font-medium" style={{ color: meta.color }}>
                          {formatAction(log.action)}
                        </span>
                        {log.username && log.username !== "—" && (
                          <span
                            className="font-mono text-xs px-1.5 py-0.5 rounded border"
                            style={{ background: "rgba(0,245,255,0.06)", borderColor: "rgba(0,245,255,0.15)", color: "#00f5ff" }}
                          >
                            {log.username}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-3 mt-1">
                        {log.ip_address && (
                          <span className="font-mono text-xs" style={{ color: "#8892b0" }}>
                            {log.ip_address}
                          </span>
                        )}
                        {log.resource && (
                          <span className="font-mono text-xs" style={{ color: "#8892b0" }}>
                            {log.resource}{log.resource_id ? ` #${log.resource_id.slice(0, 8)}` : ""}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Timestamp */}
                    <div className="text-right shrink-0">
                      <div className="font-mono text-xs" style={{ color: "#8892b0" }}>
                        {timeAgo(log.created_at)}
                      </div>
                      <div className="font-mono text-xs mt-0.5" style={{ color: "rgba(136,146,176,0.5)" }}>
                        {new Date(log.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </div>
                    </div>
                  </div>

                  {/* Expanded details */}
                  {isExpanded && log.details && (
                    <div
                      className="px-5 pb-3.5 pt-0"
                      style={{ borderTop: `1px solid ${meta.border}` }}
                    >
                      <div
                        className="rounded-lg p-3 font-mono text-xs mt-2 overflow-x-auto"
                        style={{ background: "#050810", color: "#8892b0" }}
                      >
                        <pre>{JSON.stringify(log.details, null, 2)}</pre>
                      </div>
                      <div className="flex items-center gap-4 mt-2 font-mono text-xs" style={{ color: "rgba(136,146,176,0.5)" }}>
                        <span>ID: {log.id}</span>
                        <span>{new Date(log.created_at).toLocaleString()}</span>
                      </div>
                    </div>
                  )}
                </motion.div>
              );
            })}
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3 mt-5">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="p-2 rounded-lg border border-cyber-border text-text-secondary disabled:opacity-30 transition-all hover:border-neon-yellow/30"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="font-mono text-xs" style={{ color: "#8892b0" }}>
            Page {page} of {totalPages} · {data?.total} entries
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="p-2 rounded-lg border border-cyber-border text-text-secondary disabled:opacity-30 transition-all hover:border-neon-yellow/30"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      )}
    </div>
  );
}

"use client";
import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertTriangle, CheckCircle, XCircle, Clock, Shield,
  ChevronDown, Filter, RefreshCw, AlertCircle, Activity,
} from "lucide-react";
import { threatApi } from "@/lib/api";
import { clsx } from "clsx";

// ── Types ─────────────────────────────────────────────────────────────────────
type Severity = "low" | "medium" | "high" | "critical";
type Status = "open" | "investigating" | "resolved" | "false_positive";

interface Indicator {
  type: string;
  detail: string;
  severity: string;
}

interface Incident {
  id: string;
  timestamp: string;
  domain: string;
  ip: string | null;
  port: number | null;
  protocol: string | null;
  process: string | null;
  severity: Severity;
  confidence: number;
  risk_score: number;
  description: string | null;
  indicators: Indicator[];
  status: Status;
  resolved: boolean;
  resolved_at: string | null;
  notes: string | null;
  data_source: string;
  auto_created: boolean;
}

// ── Styling maps ──────────────────────────────────────────────────────────────
const SEV_STYLE: Record<Severity, { color: string; bg: string; border: string; label: string }> = {
  critical: { color: "#ff2d55", bg: "rgba(255,45,85,0.08)",   border: "rgba(255,45,85,0.25)",   label: "CRITICAL" },
  high:     { color: "#ff6b35", bg: "rgba(255,107,53,0.08)",  border: "rgba(255,107,53,0.25)",  label: "HIGH"     },
  medium:   { color: "#ffd60a", bg: "rgba(255,214,10,0.08)",  border: "rgba(255,214,10,0.25)",  label: "MEDIUM"   },
  low:      { color: "#8892b0", bg: "rgba(136,146,176,0.08)", border: "rgba(136,146,176,0.25)", label: "LOW"      },
};

const STATUS_STYLE: Record<Status, { color: string; bg: string; border: string; label: string; Icon: React.ElementType }> = {
  open:           { color: "#ff2d55", bg: "rgba(255,45,85,0.08)",   border: "rgba(255,45,85,0.25)",   label: "OPEN",           Icon: AlertCircle  },
  investigating:  { color: "#ffd60a", bg: "rgba(255,214,10,0.08)",  border: "rgba(255,214,10,0.25)",  label: "INVESTIGATING",  Icon: Activity     },
  resolved:       { color: "#00ff88", bg: "rgba(0,255,136,0.08)",   border: "rgba(0,255,136,0.25)",   label: "RESOLVED",       Icon: CheckCircle  },
  false_positive: { color: "#8892b0", bg: "rgba(136,146,176,0.08)", border: "rgba(136,146,176,0.25)", label: "FALSE POSITIVE", Icon: XCircle      },
};

function ago(iso: string): string {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// ── Pulsing dot ───────────────────────────────────────────────────────────────
function Dot({ color, size = 8 }: { color: string; size?: number }) {
  return (
    <span className="relative inline-flex shrink-0" style={{ width: size, height: size }}>
      <motion.span
        animate={{ scale: [1, 2.2], opacity: [0.6, 0] }}
        transition={{ repeat: Infinity, duration: 1.8, ease: "easeOut" }}
        className="absolute inset-0 rounded-full"
        style={{ background: color }}
      />
      <span className="rounded-full" style={{ width: size, height: size, background: color, display: "block" }} />
    </span>
  );
}

// ── Incident Card ─────────────────────────────────────────────────────────────
function IncidentCard({ incident, onResolve }: { incident: Incident; onResolve: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const [notes, setNotes] = useState("");
  const sev = SEV_STYLE[incident.severity] ?? SEV_STYLE.medium;
  const st = STATUS_STYLE[incident.status] ?? STATUS_STYLE.open;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="border rounded-xl overflow-hidden mb-3"
      style={{ borderColor: sev.border, background: sev.bg }}
    >
      {/* Header row */}
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer"
        onClick={() => setOpen(!open)}
      >
        {incident.status === "open" && <Dot color={sev.color} />}
        {incident.status !== "open" && (
          <st.Icon className="w-4 h-4 shrink-0" style={{ color: st.color }} />
        )}

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-sm font-medium truncate" style={{ color: "#e8eaf0" }}>
              {incident.domain}
            </span>
            {incident.data_source === "simulated" && (
              <span className="font-mono rounded border px-1"
                style={{ fontSize: "9px", color: "#ffd60a", borderColor: "rgba(255,214,10,0.3)", background: "rgba(255,214,10,0.06)" }}>
                DEMO
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 mt-0.5 flex-wrap">
            {incident.ip && <span className="font-mono text-xs" style={{ color: "#8892b0" }}>{incident.ip}</span>}
            {incident.protocol && (
              <span className="font-mono text-xs px-1.5 rounded"
                style={{ background: "rgba(0,245,255,0.06)", border: "1px solid rgba(0,245,255,0.15)", color: "#00f5ff" }}>
                {incident.protocol}
              </span>
            )}
            <div className="flex items-center gap-1">
              <Clock className="w-3 h-3" style={{ color: "#8892b0" }} />
              <span className="font-mono text-xs" style={{ color: "#8892b0" }}>{ago(incident.timestamp)}</span>
            </div>
          </div>
        </div>

        {/* Severity badge */}
        <span className="font-mono text-xs px-2 py-1 rounded border shrink-0"
          style={{ background: sev.bg, borderColor: sev.border, color: sev.color }}>
          {sev.label}
        </span>

        {/* Status badge */}
        <span className="font-mono text-xs px-2 py-1 rounded border shrink-0"
          style={{ background: st.bg, borderColor: st.border, color: st.color }}>
          {st.label}
        </span>

        {/* Risk score */}
        <span className="font-mono text-xs hidden sm:block shrink-0" style={{ color: sev.color }}>
          {incident.risk_score}%
        </span>

        <motion.div animate={{ rotate: open ? 180 : 0 }}>
          <ChevronDown className="w-4 h-4 shrink-0" style={{ color: "#8892b0" }} />
        </motion.div>
      </div>

      {/* Expanded details */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2 }}
            style={{ overflow: "hidden" }}
          >
            <div className="px-4 pb-4 pt-3 border-t" style={{ borderColor: sev.border }}>
              {/* Meta grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">
                {[
                  { k: "Remote IP",  v: incident.ip || "N/A" },
                  { k: "Port",       v: incident.port ? String(incident.port) : "N/A" },
                  { k: "Protocol",   v: incident.protocol || "N/A" },
                  { k: "Process",    v: incident.process || "N/A" },
                  { k: "Confidence", v: `${(incident.confidence * 100).toFixed(0)}%` },
                  { k: "Risk Score", v: `${incident.risk_score}/100` },
                  { k: "Source",     v: incident.data_source },
                  { k: "Auto",       v: incident.auto_created ? "Yes" : "No" },
                ].map(({ k, v }) => (
                  <div key={k} className="p-2 rounded-lg" style={{ background: "#050810", border: "1px solid #1a2540" }}>
                    <div className="font-mono text-xs mb-0.5" style={{ color: "#8892b0" }}>{k}</div>
                    <div className="font-mono text-xs font-medium truncate" style={{ color: "#e8eaf0" }}>{v}</div>
                  </div>
                ))}
              </div>

              {/* Indicators */}
              {incident.indicators.length > 0 && (
                <div className="mb-3 space-y-1.5">
                  <div className="font-mono text-xs mb-1" style={{ color: "#8892b0" }}>THREAT INDICATORS</div>
                  {incident.indicators.map((ind, i) => {
                    const c = ind.severity === "critical" ? "#ff2d55" : ind.severity === "high" ? "#ff6b35" : ind.severity === "medium" ? "#ffd60a" : "#8892b0";
                    return (
                      <div key={i} className="flex items-start gap-2 px-2.5 py-1.5 rounded"
                        style={{ background: `${c}08`, border: `1px solid ${c}22` }}>
                        <span className="font-mono text-xs font-bold shrink-0" style={{ color: c }}>
                          {ind.severity.toUpperCase().slice(0, 4)}
                        </span>
                        <span className="font-mono text-xs" style={{ color: "#8892b0" }}>{ind.detail}</span>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Resolve action */}
              {incident.status === "open" && (
                <div className="mt-3 flex gap-2 items-start">
                  <input
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    placeholder="Optional resolution notes…"
                    className="flex-1 bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-xs font-mono outline-none focus:border-neon-cyan/40"
                    style={{ color: "#e8eaf0" }}
                  />
                  <button
                    onClick={() => onResolve(incident.id)}
                    className="shrink-0 flex items-center gap-1.5 px-3 py-2 rounded-lg font-mono text-xs border transition-all"
                    style={{ background: "rgba(0,255,136,0.1)", borderColor: "rgba(0,255,136,0.3)", color: "#00ff88" }}
                  >
                    <CheckCircle className="w-3.5 h-3.5" /> Resolve
                  </button>
                </div>
              )}

              {incident.resolved_at && (
                <div className="mt-2 font-mono text-xs" style={{ color: "#00ff88" }}>
                  ✓ Resolved {ago(incident.resolved_at)}{incident.notes ? ` — ${incident.notes}` : ""}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────
export default function IncidentsPage() {
  const [statusFilter, setStatusFilter] = useState<Status | "all">("all");
  const [sevFilter, setSevFilter] = useState<Severity | "all">("all");
  const qc = useQueryClient();

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["incidents", statusFilter, sevFilter],
    queryFn: () => threatApi.incidents(statusFilter, sevFilter).then((r) => r.data),
    staleTime: 30000,
    refetchInterval: 60000,
  });

  const resolveMut = useMutation({
    mutationFn: (id: string) => threatApi.resolveIncident(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["incidents"] }),
  });

  const incidents: Incident[] = data?.incidents ?? [];
  const total = data?.total ?? 0;

  const openCount = incidents.filter((i) => i.status === "open").length;
  const critCount = incidents.filter((i) => i.severity === "critical").length;
  const resolvedCount = incidents.filter((i) => i.status === "resolved").length;

  return (
    <div className="p-6 max-w-6xl">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-1">
          <motion.div animate={{ scale: [1, 1.2, 1] }} transition={{ repeat: Infinity, duration: 2 }}>
            <Shield className="w-4 h-4" style={{ color: "#ff2d55" }} />
          </motion.div>
          <span className="font-mono text-xs uppercase tracking-widest" style={{ color: "#ff2d55" }}>
            Incident Management
          </span>
          {openCount > 0 && <Dot color="#ff2d55" size={6} />}
        </div>
        <h1 className="font-display text-2xl font-bold" style={{ color: "#e8eaf0" }}>Security Incidents</h1>
        <p className="font-mono text-sm mt-1" style={{ color: "#8892b0" }}>
          Auto-detected security events · track, investigate, and resolve threats
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {[
          { label: "Total",    value: total,         color: "#00f5ff",  Icon: Activity      },
          { label: "Open",     value: openCount,     color: "#ff2d55",  Icon: AlertCircle   },
          { label: "Critical", value: critCount,     color: "#ff6b35",  Icon: AlertTriangle },
          { label: "Resolved", value: resolvedCount, color: "#00ff88",  Icon: CheckCircle   },
        ].map(({ label, value, color, Icon }) => (
          <motion.div key={label} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
            className="cyber-card p-4">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-7 h-7 rounded-lg flex items-center justify-center border"
                style={{ background: `${color}10`, borderColor: `${color}28` }}>
                <Icon className="w-3.5 h-3.5" style={{ color }} />
              </div>
              <span className="font-mono text-xs uppercase tracking-wider" style={{ color: "#8892b0" }}>{label}</span>
            </div>
            <div className="font-display text-2xl font-bold" style={{ color }}>{value}</div>
          </motion.div>
        ))}
      </div>

      {/* Filters + refresh */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
        <div className="flex items-center gap-2 flex-wrap">
          <Filter className="w-3.5 h-3.5" style={{ color: "#8892b0" }} />
          {(["all", "open", "investigating", "resolved"] as const).map((s) => (
            <button key={s} onClick={() => setStatusFilter(s)}
              className="px-3 py-1.5 rounded-lg font-mono text-xs border transition-all capitalize"
              style={statusFilter === s
                ? { background: "rgba(0,245,255,0.1)", borderColor: "rgba(0,245,255,0.3)", color: "#00f5ff" }
                : { background: "transparent", borderColor: "#1a2540", color: "#8892b0" }}>
              {s}
            </button>
          ))}
          <span className="font-mono text-xs" style={{ color: "#1a2540" }}>|</span>
          {(["all", "critical", "high", "medium", "low"] as const).map((sv) => {
            const c = sv !== "all" ? SEV_STYLE[sv as Severity].color : "#00f5ff";
            return (
              <button key={sv} onClick={() => setSevFilter(sv)}
                className="px-3 py-1.5 rounded-lg font-mono text-xs border transition-all capitalize"
                style={sevFilter === sv
                  ? { background: `${c}15`, borderColor: `${c}40`, color: c }
                  : { background: "transparent", borderColor: "#1a2540", color: "#8892b0" }}>
                {sv}
              </button>
            );
          })}
        </div>

        <button onClick={() => refetch()} disabled={isFetching}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-mono text-xs border transition-all"
          style={{ borderColor: "#1a2540", color: "#8892b0" }}>
          <RefreshCw className={clsx("w-3.5 h-3.5", isFetching && "animate-spin")} />
          Refresh
        </button>
      </div>

      {/* Incidents list */}
      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="cyber-card p-4 flex items-center gap-3">
              <div className="w-4 h-4 rounded-full bg-cyber-border animate-pulse shrink-0" />
              <div className="flex-1 space-y-2">
                <div className="h-3 bg-cyber-border rounded animate-pulse" style={{ width: "40%" }} />
                <div className="h-2 bg-cyber-border rounded animate-pulse" style={{ width: "60%" }} />
              </div>
              <div className="h-6 w-20 bg-cyber-border rounded animate-pulse" />
            </div>
          ))}
        </div>
      ) : incidents.length === 0 ? (
        <div className="cyber-card p-12 text-center">
          <CheckCircle className="w-10 h-10 mx-auto mb-3" style={{ color: "#00ff88" }} />
          <p className="font-mono text-sm" style={{ color: "#8892b0" }}>
            No incidents found. {statusFilter !== "all" || sevFilter !== "all" ? "Try clearing filters." : "Network looks clean."}
          </p>
        </div>
      ) : (
        <div>
          {incidents.map((incident) => (
            <IncidentCard
              key={incident.id}
              incident={incident}
              onResolve={(id) => resolveMut.mutate(id)}
            />
          ))}
        </div>
      )}

      {/* Info note */}
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.4 }}
        className="mt-5 p-4 rounded-xl border"
        style={{ borderColor: "rgba(0,245,255,0.1)", background: "rgba(0,245,255,0.025)" }}>
        <div className="flex items-start gap-2.5">
          <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" style={{ color: "#00f5ff" }} />
          <div className="font-mono text-xs leading-relaxed" style={{ color: "#8892b0" }}>
            <span className="font-semibold" style={{ color: "#00f5ff" }}>Incident auto-detection — </span>
            Incidents are automatically created when the network monitor detects dangerous connections (risk score ≥ 55%).
            Each incident records the domain, IP, protocol, threat indicators, and confidence score.
            Resolve incidents after investigation to keep your security posture clear.
          </div>
        </div>
      </motion.div>
    </div>
  );
}

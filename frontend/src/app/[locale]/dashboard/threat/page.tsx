"use client";
import { useState, useCallback, useEffect, useRef } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  Activity, AlertTriangle, CheckCircle, Wifi, RefreshCw,
  XCircle, Clock, ChevronDown, Network, Info, AlertCircle,
  Globe, Search, ArrowRight, Terminal,
} from "lucide-react";
import { threatApi } from "@/lib/api";
import { clsx } from "clsx";

// ── Types ─────────────────────────────────────────────────────────────────────
type Risk = "safe" | "suspicious" | "dangerous";
type Mode = "real" | "simulation";

interface Indicator { type: string; detail: string; severity: "low" | "medium" | "high"; }
interface Event {
  id: string; domain: string; ip: string; port: number;
  protocol: string; process: string; risk_level: Risk;
  reasons: string[]; indicators: Indicator[];
  confidence: number; is_known_safe: boolean;
  timestamp: string; local_port: number | null;
  status: string; data_source: "real" | "simulated";
}
interface IO {
  bytes_sent_total: number; bytes_recv_total: number;
  bytes_sent_rate: number; bytes_recv_rate: number;
  packets_sent: number; packets_recv: number; is_real: boolean;
}
interface Feed {
  events: Event[];
  stats: { total: number; safe: number; suspicious: number; dangerous: number };
  io: IO; monitoring_mode: Mode; mode_description: string; captured_at: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const RISK: Record<Risk, { color: string; bg: string; border: string; Icon: React.ElementType; label: string }> = {
  safe:       { color: "#00ff88", bg: "rgba(0,255,136,0.07)",  border: "rgba(0,255,136,0.2)",  Icon: CheckCircle,   label: "Safe"       },
  suspicious: { color: "#ffd60a", bg: "rgba(255,214,10,0.07)", border: "rgba(255,214,10,0.2)", Icon: AlertTriangle, label: "Suspicious" },
  dangerous:  { color: "#ff2d55", bg: "rgba(255,45,85,0.07)",  border: "rgba(255,45,85,0.2)",  Icon: XCircle,       label: "Dangerous"  },
};
const SEV: Record<string, { color: string; tag: string }> = {
  high:   { color: "#ff2d55", tag: "HIGH" },
  medium: { color: "#ffd60a", tag: "MED"  },
  low:    { color: "#8892b0", tag: "LOW"  },
};

function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}
function ago(iso: string): string {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 10) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

// ── Pulsing dot ───────────────────────────────────────────────────────────────
function Dot({ color, size = 8 }: { color: string; size?: number }) {
  return (
    <span className="relative inline-flex shrink-0" style={{ width: size, height: size }}>
      <motion.span
        animate={{ scale: [1, 2.4], opacity: [0.6, 0] }}
        transition={{ repeat: Infinity, duration: 1.6, ease: "easeOut" }}
        className="absolute inset-0 rounded-full"
        style={{ background: color }}
      />
      <span className="rounded-full" style={{ width: size, height: size, background: color, display: "block" }} />
    </span>
  );
}

// ── Countdown ring ────────────────────────────────────────────────────────────
const INTERVAL = 15; // seconds
function CountdownRing({ active, onComplete }: { active: boolean; onComplete: () => void }) {
  const [remaining, setRemaining] = useState(INTERVAL);
  const ref = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!active) { setRemaining(INTERVAL); return; }
    setRemaining(INTERVAL);
    ref.current = setInterval(() => {
      setRemaining(prev => {
        if (prev <= 1) { onComplete(); return INTERVAL; }
        return prev - 1;
      });
    }, 1000);
    return () => { if (ref.current) clearInterval(ref.current); };
  }, [active]);

  const pct = remaining / INTERVAL;
  const r = 14; const circ = 2 * Math.PI * r;

  return (
    <div className="relative flex items-center justify-center" style={{ width: 36, height: 36 }}>
      <svg width="36" height="36" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="18" cy="18" r={r} fill="none" stroke="#1a2540" strokeWidth="2" />
        <motion.circle
          cx="18" cy="18" r={r} fill="none"
          stroke={active ? "#00f5ff" : "#1a2540"} strokeWidth="2"
          strokeDasharray={circ}
          strokeDashoffset={circ * (1 - pct)}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.9s linear" }}
        />
      </svg>
      <span className="absolute font-mono text-xs font-bold" style={{ color: active ? "#00f5ff" : "#8892b0", fontSize: "9px" }}>
        {active ? `${remaining}s` : "off"}
      </span>
    </div>
  );
}

// ── IO strip ──────────────────────────────────────────────────────────────────
function IOStrip({ io }: { io: IO }) {
  return (
    <div className="cyber-card px-4 py-3 mb-5 flex flex-wrap items-center gap-x-6 gap-y-2">
      <div className="flex items-center gap-2">
        <Network className="w-3.5 h-3.5" style={{ color: "#00f5ff" }} />
        <span className="font-mono text-xs uppercase tracking-wider" style={{ color: "#8892b0" }}>Network I/O</span>
        {io.is_real && <Dot color="#00ff88" size={6} />}
      </div>
      {[
        { label: "↑ /s",    val: `${bytes(io.bytes_sent_rate)}`,      color: "#00f5ff" },
        { label: "↓ /s",    val: `${bytes(io.bytes_recv_rate)}`,      color: "#00ff88" },
        { label: "Sent",    val: bytes(io.bytes_sent_total),           color: "#8892b0" },
        { label: "Recv",    val: bytes(io.bytes_recv_total),           color: "#8892b0" },
        { label: "Pkts ↑",  val: io.packets_sent.toLocaleString(),    color: "#bf5af2" },
        { label: "Pkts ↓",  val: io.packets_recv.toLocaleString(),    color: "#bf5af2" },
      ].map(({ label, val, color }) => (
        <div key={label} className="text-center">
          <div className="font-mono text-xs mb-0.5" style={{ color: "#8892b0" }}>{label}</div>
          <div className="font-mono text-sm font-semibold" style={{ color }}>{val}</div>
        </div>
      ))}
    </div>
  );
}

// ── Mode banner ───────────────────────────────────────────────────────────────
function ModeBanner({ mode, desc }: { mode: Mode; desc: string }) {
  const [open, setOpen] = useState(false);
  if (mode === "real") {
    return (
      <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}
        className="mb-5 flex items-center gap-3 px-4 py-2.5 rounded-xl border"
        style={{ borderColor: "rgba(0,255,136,0.25)", background: "rgba(0,255,136,0.05)" }}
      >
        <Dot color="#00ff88" size={8} />
        <span className="font-mono text-xs font-semibold" style={{ color: "#00ff88" }}>LIVE MONITORING</span>
        <span className="font-mono text-xs" style={{ color: "#8892b0" }}>— reading real OS connections via psutil</span>
      </motion.div>
    );
  }
  return (
    <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}
      className="mb-5 rounded-xl border overflow-hidden"
      style={{ borderColor: "rgba(255,214,10,0.3)", background: "rgba(255,214,10,0.04)" }}
    >
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left"
      >
        <AlertCircle className="w-4 h-4 shrink-0" style={{ color: "#ffd60a" }} />
        <div className="flex-1 min-w-0">
          <span className="font-mono text-xs font-semibold" style={{ color: "#ffd60a" }}>
            SIMULATION MODE
          </span>
          <span className="font-mono text-xs ml-2" style={{ color: "#8892b0" }}>
            — demo traffic only, not your real connections
          </span>
        </div>
        <motion.div animate={{ rotate: open ? 180 : 0 }} className="shrink-0">
          <ChevronDown className="w-4 h-4" style={{ color: "#8892b0" }} />
        </motion.div>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div initial={{ height: 0 }} animate={{ height: "auto" }} exit={{ height: 0 }} style={{ overflow: "hidden" }}>
            <div className="px-4 pb-4 pt-0 border-t" style={{ borderColor: "rgba(255,214,10,0.15)" }}>
              <p className="font-mono text-xs mt-3 mb-3 leading-relaxed" style={{ color: "#8892b0" }}>{desc}</p>
              <div className="p-3 rounded-lg font-mono text-xs leading-relaxed space-y-1.5"
                style={{ background: "#050810", border: "1px solid #1a2540", color: "#8892b0" }}>
                <div><span style={{ color: "#00ff88" }}>→ How real monitoring works</span></div>
                <div>The backend calls <span style={{ color: "#00f5ff" }}>psutil.net_connections()</span> to enumerate all OS-level TCP/UDP sockets in ESTABLISHED state.</div>
                <div>Each remote IP gets a reverse DNS lookup, then the resolved hostname is passed through <span style={{ color: "#e8eaf0" }}>10 detection rules</span>: TLD risk, brand impersonation, phishing patterns, DGA entropy, suspicious ports, and more.</div>
                <div><span style={{ color: "#ffd60a" }}>This sandbox has no external network access</span> so real connections aren't available. Deploy to your own machine/server to see actual traffic.</div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ── Domain analyser input ─────────────────────────────────────────────────────
function DomainAnalyser() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const analyse = useCallback(async () => {
    const d = input.trim();
    if (!d) return;
    setLoading(true);
    try {
      const res = await threatApi.analyze(d);
      setResult(res.data);
    } catch {
      setResult({ error: "Analysis failed" });
    }
    setLoading(false);
  }, [input]);

  const handleKey = (e: React.KeyboardEvent) => { if (e.key === "Enter") analyse(); };

  return (
    <div className="cyber-card p-4 mb-5">
      <div className="flex items-center gap-2 mb-3">
        <Terminal className="w-3.5 h-3.5" style={{ color: "#00f5ff" }} />
        <span className="font-mono text-xs uppercase tracking-wider" style={{ color: "#00f5ff" }}>Domain Analyser</span>
      </div>
      <div className="flex gap-2">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Enter domain or IP to analyse…"
          className="flex-1 bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-sm font-mono outline-none focus:border-neon-cyan/40"
          style={{ color: "#e8eaf0" }}
        />
        <button
          onClick={analyse}
          disabled={loading || !input.trim()}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg font-mono text-xs font-medium border transition-all disabled:opacity-40"
          style={{ background: "rgba(0,245,255,0.1)", borderColor: "rgba(0,245,255,0.3)", color: "#00f5ff" }}
        >
          {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
          Analyse
        </button>
      </div>

      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="mt-3 p-3 rounded-lg border"
            style={result.error
              ? { borderColor: "#1a2540", background: "rgba(5,8,16,0.8)" }
              : { borderColor: RISK[result.risk_level as Risk]?.border, background: RISK[result.risk_level as Risk]?.bg }
            }
          >
            {result.error ? (
              <span className="font-mono text-xs" style={{ color: "#ff2d55" }}>{result.error}</span>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <span className="font-mono text-sm font-medium" style={{ color: "#e8eaf0" }}>{result.domain}</span>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs px-2.5 py-1 rounded-full border"
                      style={{ background: RISK[result.risk_level as Risk]?.bg, borderColor: RISK[result.risk_level as Risk]?.border, color: RISK[result.risk_level as Risk]?.color }}>
                      {RISK[result.risk_level as Risk]?.label}
                    </span>
                    {result.confidence > 0 && (
                      <span className="font-mono text-xs" style={{ color: "#8892b0" }}>
                        {(result.confidence * 100).toFixed(0)}% risk score
                      </span>
                    )}
                  </div>
                </div>
                {result.is_known_safe && (
                  <div className="flex items-center gap-2 font-mono text-xs" style={{ color: "#00ff88" }}>
                    <CheckCircle className="w-3.5 h-3.5" /> Verified safe — known CDN/service domain
                  </div>
                )}
                {(result.indicators ?? []).map((ind: Indicator, i: number) => (
                  <div key={i} className="flex items-start gap-2 font-mono text-xs px-2.5 py-1.5 rounded"
                    style={{ background: `${SEV[ind.severity]?.color}08`, border: `1px solid ${SEV[ind.severity]?.color}25` }}>
                    <span className="font-bold shrink-0" style={{ color: SEV[ind.severity]?.color }}>{SEV[ind.severity]?.tag}</span>
                    <span style={{ color: "#8892b0" }}>{ind.detail}</span>
                  </div>
                ))}
                {result.indicators?.length === 0 && !result.is_known_safe && (
                  <span className="font-mono text-xs" style={{ color: "#8892b0" }}>No threat indicators detected.</span>
                )}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ── Indicator chip ────────────────────────────────────────────────────────────
function IndicatorChip({ ind }: { ind: Indicator }) {
  const s = SEV[ind.severity] ?? SEV.low;
  return (
    <div className="flex items-start gap-2 px-2.5 py-1.5 rounded-lg"
      style={{ background: `${s.color}08`, border: `1px solid ${s.color}22` }}>
      <span className="font-mono text-xs font-bold shrink-0 mt-0.5" style={{ color: s.color }}>{s.tag}</span>
      <span className="font-mono text-xs leading-relaxed" style={{ color: "#8892b0" }}>{ind.detail}</span>
    </div>
  );
}

// ── Event row ─────────────────────────────────────────────────────────────────
function EventRow({ event, index }: { event: Event; index: number }) {
  const [open, setOpen] = useState(false);
  const r = RISK[event.risk_level];

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: Math.min(index * 0.03, 0.45) }}
      className="border-b last:border-b-0 hover:bg-white/[0.012] transition-colors"
      style={{ borderColor: "rgba(26,37,64,0.45)" }}
    >
      {/* Row */}
      <div className="flex items-center gap-3 px-4 py-3 cursor-pointer" onClick={() => setOpen(!open)}>

        {/* Status dot */}
        <Dot color={r.color} size={7} />

        {/* Domain block */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 min-w-0">
            <span className="font-mono text-sm truncate" style={{ color: "#e8eaf0" }}>{event.domain}</span>
            {event.data_source === "simulated" && (
              <span className="shrink-0 font-mono rounded border px-1"
                style={{ fontSize: "9px", color: "#ffd60a", borderColor: "rgba(255,214,10,0.3)", background: "rgba(255,214,10,0.06)" }}>
                DEMO
              </span>
            )}
          </div>
          <div className="flex items-center gap-2.5 mt-0.5 flex-wrap">
            <span className="font-mono text-xs" style={{ color: "#8892b0" }}>{event.ip}</span>
            <span className="font-mono text-xs px-1.5 rounded"
              style={{ background: "rgba(0,245,255,0.06)", border: "1px solid rgba(0,245,255,0.15)", color: "#00f5ff" }}>
              {event.protocol}
            </span>
            <span className="font-mono text-xs" style={{ color: "#8892b0" }}>:{event.port}</span>
            {event.process && event.process !== "unknown" && (
              <span className="font-mono text-xs" style={{ color: "#8892b0" }}>[{event.process}]</span>
            )}
          </div>
        </div>

        {/* Risk badge */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full border font-mono text-xs shrink-0"
          style={{ background: r.bg, borderColor: r.border, color: r.color }}>
          <r.Icon className="w-3 h-3" />
          {r.label}
        </div>

        {/* Confidence */}
        {event.confidence > 0 && (
          <span className="font-mono text-xs hidden sm:block shrink-0" style={{ color: "#8892b0" }}>
            {(event.confidence * 100).toFixed(0)}%
          </span>
        )}

        {/* Timestamp */}
        <div className="font-mono text-xs hidden md:flex items-center gap-1 shrink-0" style={{ color: "#8892b0" }}>
          <Clock className="w-3 h-3" />{ago(event.timestamp)}
        </div>

        {/* Chevron */}
        <motion.div animate={{ rotate: open ? 180 : 0 }} className="shrink-0">
          <ChevronDown className="w-3.5 h-3.5" style={{ color: "#8892b0" }} />
        </motion.div>
      </div>

      {/* Expanded */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.18 }}
            style={{ overflow: "hidden" }}
          >
            <div className="px-4 pb-4 pt-2 border-t" style={{ borderColor: r.border }}>
              {/* Details grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 mb-3">
                {[
                  { k: "Remote IP",    v: event.ip           },
                  { k: "Protocol",     v: event.protocol     },
                  { k: "Remote Port",  v: String(event.port) },
                  { k: "Conn Status",  v: event.status       },
                ].map(({ k, v }) => (
                  <div key={k} className="p-2.5 rounded-lg" style={{ background: "rgba(5,8,16,0.8)", border: "1px solid #1a2540" }}>
                    <div className="font-mono text-xs mb-0.5" style={{ color: "#8892b0" }}>{k}</div>
                    <div className="font-mono text-xs font-medium" style={{ color: "#e8eaf0" }}>{v}</div>
                  </div>
                ))}
              </div>

              {/* Indicators */}
              {event.indicators.length > 0 ? (
                <div className="space-y-1.5">
                  <div className="font-mono text-xs mb-1.5" style={{ color: "#8892b0" }}>THREAT INDICATORS</div>
                  {event.indicators.map((ind, i) => <IndicatorChip key={i} ind={ind} />)}
                </div>
              ) : (
                <div className="flex items-center gap-2 p-2.5 rounded-lg"
                  style={{ background: "rgba(0,255,136,0.05)", border: "1px solid rgba(0,255,136,0.15)" }}>
                  <CheckCircle className="w-3.5 h-3.5" style={{ color: "#00ff88" }} />
                  <span className="font-mono text-xs" style={{ color: "#00ff88" }}>
                    {event.is_known_safe ? "Verified safe — known CDN/service domain" : "No threat indicators detected"}
                  </span>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ── Stat card ─────────────────────────────────────────────────────────────────
function StatCard({ label, value, color, icon: Icon }: { label: string; value: number; color: string; icon: React.ElementType }) {
  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="cyber-card p-4">
      <div className="flex items-center gap-2 mb-2">
        <div className="w-7 h-7 rounded-lg flex items-center justify-center border"
          style={{ background: `${color}10`, borderColor: `${color}28` }}>
          <Icon className="w-3.5 h-3.5" style={{ color }} />
        </div>
        <span className="font-mono text-xs uppercase tracking-wider" style={{ color: "#8892b0" }}>{label}</span>
      </div>
      <div className="font-display text-2xl font-bold" style={{ color }}>{value}</div>
    </motion.div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────
export default function LiveThreatPage() {
  const [filter, setFilter] = useState<Risk | "all">("all");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const qc = useQueryClient();

  const { data, isLoading, refetch, isFetching, dataUpdatedAt } = useQuery<Feed>({
    queryKey: ["threat-live"],
    queryFn: () => threatApi.live(35).then(r => r.data),
    staleTime: 12000,
  });

  const doRefresh = useCallback(() => {
    qc.invalidateQueries({ queryKey: ["threat-live"] });
  }, [qc]);

  const events  = data?.events ?? [];
  const stats   = data?.stats  ?? { total: 0, safe: 0, suspicious: 0, dangerous: 0 };
  const io      = data?.io;
  const mode    = data?.monitoring_mode ?? "simulation";
  const filtered = filter === "all" ? events : events.filter(e => e.risk_level === filter);

  const lastUpdate = dataUpdatedAt
    ? new Date(dataUpdatedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : "—";

  return (
    <div className="p-6 max-w-6xl">

      {/* ── Header ────────────────────────────────────────────────────────── */}
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-1">
          <motion.div animate={{ scale: [1, 1.2, 1] }} transition={{ repeat: Infinity, duration: 2.2 }}>
            <Wifi className="w-4 h-4" style={{ color: "#00f5ff" }} />
          </motion.div>
          <span className="font-mono text-xs uppercase tracking-widest" style={{ color: "#00f5ff" }}>
            Network Monitor
          </span>
          {mode === "real" && <Dot color="#00ff88" size={6} />}
        </div>
        <h1 className="font-display text-2xl font-bold" style={{ color: "#e8eaf0" }}>
          Live Threat Detection
        </h1>
        <p className="font-mono text-sm mt-1" style={{ color: "#8892b0" }}>
          Real-time connection analysis · domain reputation · threat intelligence
        </p>
      </div>

      {/* Mode banner */}
      {data && <ModeBanner mode={mode} desc={data.mode_description} />}

      {/* IO strip */}
      {io && <IOStrip io={io} />}

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard label="Connections"  value={stats.total}       color="#00f5ff"  icon={Activity}      />
        <StatCard label="Safe"         value={stats.safe}        color="#00ff88"  icon={CheckCircle}   />
        <StatCard label="Suspicious"   value={stats.suspicious}  color="#ffd60a"  icon={AlertTriangle} />
        <StatCard label="Dangerous"    value={stats.dangerous}   color="#ff2d55"  icon={XCircle}       />
      </div>

      {/* Domain analyser */}
      <DomainAnalyser />

      {/* Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        {/* Filters */}
        <div className="flex items-center gap-2 flex-wrap">
          {(["all", "safe", "suspicious", "dangerous"] as const).map(f => {
            const active = filter === f;
            const r = f !== "all" ? RISK[f] : null;
            const cnt = f === "all" ? stats.total : f === "safe" ? stats.safe : f === "suspicious" ? stats.suspicious : stats.dangerous;
            return (
              <button key={f} onClick={() => setFilter(f)}
                className="px-3 py-1.5 rounded-lg font-mono text-xs border transition-all"
                style={active
                  ? { background: r?.bg ?? "rgba(0,245,255,0.1)", borderColor: r?.border ?? "rgba(0,245,255,0.3)", color: r?.color ?? "#00f5ff" }
                  : { background: "transparent", borderColor: "#1a2540", color: "#8892b0" }
                }
              >
                {f === "all" ? "All" : RISK[f].label}
                <span className="ml-1.5 opacity-55">{cnt}</span>
              </button>
            );
          })}
        </div>

        {/* Right controls */}
        <div className="flex items-center gap-3">
          {/* Auto-refresh countdown */}
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs" style={{ color: "#8892b0" }}>Auto</span>
            <CountdownRing active={autoRefresh} onComplete={doRefresh} />
            <button
              onClick={() => setAutoRefresh(a => !a)}
              className="w-10 h-5 rounded-full relative border transition-all"
              style={{
                background: autoRefresh ? "rgba(0,245,255,0.15)" : "transparent",
                borderColor: autoRefresh ? "rgba(0,245,255,0.35)" : "#1a2540",
              }}
            >
              <div className="absolute top-0.5 w-4 h-4 rounded-full transition-all"
                style={{ background: autoRefresh ? "#00f5ff" : "#8892b0", left: autoRefresh ? "calc(100% - 18px)" : "2px" }} />
            </button>
          </div>

          <button onClick={() => refetch()} disabled={isFetching}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-mono text-xs border transition-all disabled:opacity-50"
            style={{ borderColor: "#1a2540", color: "#8892b0" }}
          >
            <RefreshCw className={clsx("w-3.5 h-3.5", isFetching && "animate-spin")} />
            Refresh
          </button>

          <span className="font-mono text-xs hidden sm:block" style={{ color: "#8892b0" }}>{lastUpdate}</span>
        </div>
      </div>

      {/* Table */}
      <div className="cyber-card overflow-hidden">
        {/* Header row */}
        <div className="flex items-center gap-3 px-4 py-2.5 border-b"
          style={{ borderColor: "#1a2540", background: "rgba(5,8,16,0.7)" }}>
          <span className="w-4" />
          <span className="flex-1 font-mono text-xs uppercase tracking-wider" style={{ color: "#8892b0" }}>Domain / IP · Protocol · Port</span>
          <span className="font-mono text-xs uppercase tracking-wider hidden md:block" style={{ color: "#8892b0" }}>Status</span>
          <span className="font-mono text-xs uppercase tracking-wider hidden sm:block w-12" style={{ color: "#8892b0" }}>Score</span>
          <span className="font-mono text-xs uppercase tracking-wider hidden md:block w-20 text-right" style={{ color: "#8892b0" }}>Time</span>
          <span className="w-4" />
        </div>

        {isLoading ? (
          <div className="p-5 space-y-2.5">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 p-3 rounded-lg" style={{ background: "#050810" }}>
                <div className="w-2 h-2 rounded-full bg-cyber-border animate-pulse shrink-0" />
                <div className="flex-1 space-y-1.5">
                  <div className="h-3 bg-cyber-border rounded animate-pulse" style={{ width: "38%" }} />
                  <div className="h-2 bg-cyber-border rounded animate-pulse" style={{ width: "58%" }} />
                </div>
                <div className="h-6 w-20 bg-cyber-border rounded-full animate-pulse" />
              </div>
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center">
            <Globe className="w-8 h-8 mx-auto mb-3" style={{ color: "#8892b0" }} />
            <p className="font-mono text-sm" style={{ color: "#8892b0" }}>
              No {filter !== "all" ? filter + " " : ""}connections found.
            </p>
          </div>
        ) : (
          filtered.map((e, i) => <EventRow key={e.id} event={e} index={i} />)
        )}
      </div>

      {/* How it works */}
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.4 }}
        className="mt-5 p-4 rounded-xl border"
        style={{ borderColor: "rgba(0,245,255,0.1)", background: "rgba(0,245,255,0.025)" }}
      >
        <div className="flex items-start gap-2.5">
          <Info className="w-4 h-4 mt-0.5 shrink-0" style={{ color: "#00f5ff" }} />
          <div className="font-mono text-xs leading-relaxed" style={{ color: "#8892b0" }}>
            <span className="font-semibold" style={{ color: "#00f5ff" }}>Detection engine — </span>
            backend reads OS connections via <code style={{ color: "#00f5ff" }}>psutil.net_connections()</code>, resolves each remote IP with reverse DNS, then applies{" "}
            <span style={{ color: "#e8eaf0" }}>10 independent rules</span>:{" "}
            suspicious TLDs (.tk/.ga/.xyz/...), brand impersonation (26 brands), phishing regex patterns, DGA entropy analysis (Shannon H &gt; 3.9), suspicious ports, raw IP connections, deep subdomains, long domains, numeric hostnames, and hyphen abuse.
            Risk score is clamped to [0, 1]. Dangerous ≥ 0.55 · Suspicious ≥ 0.20.
            Click any row to see per-rule breakdown with severity levels.
          </div>
        </div>
      </motion.div>
    </div>
  );
}

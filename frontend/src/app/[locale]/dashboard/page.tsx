"use client";
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { motion, useInView, useMotionValue, useSpring, AnimatePresence } from "framer-motion";
import {
  Shield, Globe, MessageSquare, FileSearch, TrendingUp,
  AlertTriangle, CheckCircle2, Activity, Clock, ArrowRight,
  Eye, Zap, Wifi, Network, AlertCircle, BarChart3,
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell,
} from "recharts";
import { userApi, threatApi } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import { useTranslations } from "next-intl";

// ── Animated number counter ────────────────────────────────────────────────────
function AnimatedCounter({ value }: { value: number }) {
  const ref = useRef<HTMLSpanElement>(null);
  const mv = useMotionValue(0);
  const sp = useSpring(mv, { duration: 1400, bounce: 0 });
  const inView = useInView(ref, { once: true });
  useEffect(() => { if (inView) mv.set(value); }, [inView, value, mv]);
  useEffect(() => sp.on("change", (v) => { if (ref.current) ref.current.textContent = Math.round(v).toLocaleString(); }), [sp]);
  return <span ref={ref}>0</span>;
}

// ── Typing effect ─────────────────────────────────────────────────────────────
function TypedText({ text, delay = 0 }: { text: string; delay?: number }) {
  const [displayed, setDisplayed] = useState("");
  const [started, setStarted] = useState(false);
  useEffect(() => { const t = setTimeout(() => setStarted(true), delay * 1000); return () => clearTimeout(t); }, [delay]);
  useEffect(() => {
    if (!started) return;
    let i = 0;
    const iv = setInterval(() => { setDisplayed(text.slice(0, ++i)); if (i >= text.length) clearInterval(iv); }, 40);
    return () => clearInterval(iv);
  }, [started, text]);
  return (
    <span>
      {displayed}
      {displayed.length < text.length && started && (
        <motion.span animate={{ opacity: [1, 0] }} transition={{ repeat: Infinity, duration: 0.5 }} style={{ color: "#00e5ff" }}>▊</motion.span>
      )}
    </span>
  );
}

// ── Label badge ────────────────────────────────────────────────────────────────
function LabelBadge({ label }: { label: string }) {
  const cfg: Record<string, { color: string; bg: string; border: string }> = {
    PHISHING:   { color: "#ff3d5a", bg: "rgba(255,61,90,0.08)",  border: "rgba(255,61,90,0.2)"  },
    FRAUD:      { color: "#ff3d5a", bg: "rgba(255,61,90,0.08)",  border: "rgba(255,61,90,0.2)"  },
    SUSPICIOUS: { color: "#ffb300", bg: "rgba(255,179,0,0.08)",  border: "rgba(255,179,0,0.2)"  },
    SAFE:       { color: "#00e676", bg: "rgba(0,230,118,0.08)",  border: "rgba(0,230,118,0.2)"  },
  };
  const c = cfg[label] ?? { color: "#7986a8", bg: "transparent", border: "rgba(255,255,255,0.08)" };
  return (
    <span
      className="font-mono flex-shrink-0"
      style={{
        ...c,
        fontSize: 9,
        letterSpacing: "0.08em",
        padding: "2px 8px",
        borderRadius: 999,
        border: `1px solid ${c.border}`,
        fontWeight: 600,
        textTransform: "uppercase",
      }}
    >
      {label}
    </span>
  );
}

// ── Scan type icon ─────────────────────────────────────────────────────────────
function ScanTypeIcon({ type }: { type: string }) {
  if (type === "url")     return <Globe size={13} style={{ color: "#00e5ff" }} />;
  if (type === "message") return <MessageSquare size={13} style={{ color: "#00e676" }} />;
  if (type === "file")    return <FileSearch size={13} style={{ color: "#c471ed" }} />;
  return <Activity size={13} style={{ color: "#7986a8" }} />;
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// ── Stat card ──────────────────────────────────────────────────────────────────
function StatCard({
  icon: Icon, label, value, color, sublabel, delay = 0,
}: {
  icon: React.ElementType; label: string; value: number | string;
  color: string; sublabel?: string; delay?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4, ease: "easeOut" }}
      whileHover={{ y: -2 }}
      className="glass-card p-5 cursor-default"
    >
      <div
        className="w-9 h-9 rounded-xl flex items-center justify-center mb-4"
        style={{ background: `${color}10`, border: `1px solid ${color}22` }}
      >
        <Icon size={16} style={{ color }} />
      </div>
      <div className="font-display font-black text-3xl mb-1" style={{ color }}>
        {typeof value === "number" ? <AnimatedCounter value={value} /> : value}
      </div>
      <div className="font-mono text-xs uppercase tracking-widest" style={{ color: "#7986a8" }}>{label}</div>
      {sublabel && <div className="font-mono text-xs mt-1" style={{ color: "#3d4d6e" }}>{sublabel}</div>}
    </motion.div>
  );
}

// ── Scanner quick-link card ────────────────────────────────────────────────────
function ScannerCard({
  icon: Icon, label, value, color, href, delay, badge,
}: {
  icon: React.ElementType; label: string; value: number;
  color: string; href: string; delay: number; badge?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay, duration: 0.4 }}
      whileHover={{ scale: 1.02, y: -2 }}
    >
      <Link
        href={href}
        className="glass-card p-4 flex items-center gap-3 group block"
        style={{ textDecoration: "none" }}
      >
        <div
          className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
          style={{ background: `${color}10`, border: `1px solid ${color}22` }}
        >
          <Icon size={18} style={{ color }} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="font-display font-bold text-xl" style={{ color }}>
            <AnimatedCounter value={value} />
          </div>
          <div className="font-mono text-xs" style={{ color: "#7986a8" }}>{label}</div>
        </div>
        {badge && (
          <span
            className="font-mono text-xs px-2 py-0.5 rounded flex-shrink-0"
            style={{
              background: `${color}10`,
              border: `1px solid ${color}25`,
              color,
              fontSize: 9,
              letterSpacing: "0.08em",
              fontWeight: 600,
            }}
          >
            {badge}
          </span>
        )}
        <motion.div
          animate={{ x: 0 }}
          whileHover={{ x: 4 }}
          style={{ color: "#3d4d6e" }}
          className="flex-shrink-0"
        >
          <ArrowRight size={14} />
        </motion.div>
      </Link>
    </motion.div>
  );
}

// ── System risk widget ─────────────────────────────────────────────────────────
function SystemRiskBadge({ risk }: {
  risk: { level: string; label: string; color: string; description: string; score: number };
}) {
  const r = 30;
  const circ = 2 * Math.PI * r;
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="glass-card p-5 flex items-center gap-5"
    >
      <div className="relative flex-shrink-0">
        <svg width={76} height={76} style={{ transform: "rotate(-90deg)" }}>
          <circle cx={38} cy={38} r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth={5} />
          <motion.circle
            cx={38} cy={38} r={r}
            fill="none"
            stroke={risk.color}
            strokeWidth={5}
            strokeDasharray={circ}
            strokeLinecap="round"
            initial={{ strokeDashoffset: circ }}
            animate={{ strokeDashoffset: circ * (1 - risk.score / 100) }}
            transition={{ duration: 1.4, ease: "easeOut" }}
            style={{ filter: `drop-shadow(0 0 6px ${risk.color})` }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="font-mono text-xs font-bold" style={{ color: risk.color }}>{risk.score}</span>
        </div>
      </div>
      <div>
        <div className="font-mono text-xs uppercase tracking-widest mb-1" style={{ color: "#3d4d6e" }}>System Risk</div>
        <div className="font-display text-xl font-black mb-1" style={{ color: risk.color }}>{risk.label}</div>
        <div className="font-body text-xs leading-relaxed" style={{ color: "#7986a8" }}>{risk.description}</div>
      </div>
    </motion.div>
  );
}

// ── Top threat domains ─────────────────────────────────────────────────────────
function TopThreatsWidget({ domains }: {
  domains: Array<{ domain: string; hits: number; risk_level: string; risk_score: number }>;
}) {
  if (!domains.length) return null;
  return (
    <div className="glass-card p-5">
      <div className="flex items-center gap-2 mb-4">
        <AlertTriangle size={14} style={{ color: "#ff3d5a" }} />
        <h2 className="font-display font-semibold text-sm" style={{ color: "#e2e8f8" }}>Top Threat Domains</h2>
      </div>
      <div className="space-y-2">
        {domains.map((d, i) => {
          const color = d.risk_level === "dangerous" ? "#ff3d5a" : "#ffb300";
          return (
            <motion.div
              key={d.domain}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.06 }}
              className="flex items-center gap-3 p-2.5 rounded-xl"
              style={{ background: `${color}06`, border: `1px solid ${color}18` }}
            >
              <div className="font-mono text-xs w-4 text-center flex-shrink-0" style={{ color: "#3d4d6e" }}>{i + 1}</div>
              <div className="flex-1 min-w-0">
                <div className="font-mono text-xs truncate" style={{ color: "#e2e8f8" }}>{d.domain}</div>
                <div className="font-mono text-xs" style={{ color: "#3d4d6e" }}>{d.hits} hits · score {d.risk_score}</div>
              </div>
              <span className="font-mono text-xs font-bold flex-shrink-0" style={{ color, fontSize: 9, letterSpacing: "0.08em" }}>
                {d.risk_level.toUpperCase()}
              </span>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}

// ── Mock trend data ────────────────────────────────────────────────────────────
const mockTrend = [
  { date: "Mon", scans: 12, threats: 3 },
  { date: "Tue", scans: 19, threats: 5 },
  { date: "Wed", scans: 8,  threats: 1 },
  { date: "Thu", scans: 27, threats: 8 },
  { date: "Fri", scans: 34, threats: 12 },
  { date: "Sat", scans: 15, threats: 2 },
  { date: "Sun", scans: 22, threats: 7 },
];

// ── Custom chart tooltip ───────────────────────────────────────────────────────
function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div
      className="font-mono text-xs p-3 rounded-xl"
      style={{ background: "rgba(8,14,28,0.95)", border: "1px solid rgba(255,255,255,0.08)", backdropFilter: "blur(10px)" }}
    >
      <div className="mb-2" style={{ color: "#7986a8" }}>{label}</div>
      {payload.map((p: any) => (
        <div key={p.name} className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full" style={{ background: p.color }} />
          <span style={{ color: "#e2e8f8" }}>{p.name}: {p.value}</span>
        </div>
      ))}
    </div>
  );
}

// ── Dashboard page ─────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const t = useTranslations("dashboard");
  const { user } = useAuthStore();

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ["user-stats"],
    queryFn: () => userApi.stats().then((r) => r.data),
  });

  const { data: historyData, isLoading: historyLoading } = useQuery({
    queryKey: ["user-history-recent"],
    queryFn: () => userApi.history(1, 8).then((r) => r.data),
  });

  const { data: systemRiskData } = useQuery({
    queryKey: ["system-risk"],
    queryFn: () => threatApi.systemRisk().then((r) => r.data),
    staleTime: 30000,
    refetchInterval: 60000,
  });

  const { data: topDomainsData } = useQuery({
    queryKey: ["top-threat-domains"],
    queryFn: () => threatApi.topDomains(5).then((r) => r.data),
    staleTime: 60000,
  });

  const recentScans = historyData?.items ?? [];
  const recentThreats = recentScans.filter((s: any) =>
    s.label === "PHISHING" || s.label === "FRAUD" || s.label === "SUSPICIOUS"
  );

  const pieData = stats
    ? [
        { name: "Safe",       value: stats.safe ?? 0,             color: "#00e676" },
        { name: "Threats",    value: stats.threats_detected ?? 0, color: "#ff3d5a" },
        { name: "Suspicious", value: stats.suspicious ?? 0,       color: "#ffb300" },
      ]
    : [];

  const systemRisk = systemRiskData?.system_risk;
  const topDomains = topDomainsData?.domains ?? [];

  return (
    <div className="p-6 lg:p-8 max-w-7xl">

      {/* ── Header ── */}
      <div className="mb-8">
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center gap-2 mb-2"
        >
          <motion.div animate={{ scale: [1, 1.3, 1] }} transition={{ repeat: Infinity, duration: 2.5 }}>
            <Activity size={14} style={{ color: "#00e5ff" }} />
          </motion.div>
          <span className="font-mono text-xs uppercase tracking-widest" style={{ color: "#00e5ff" }}>SOC Dashboard</span>
          <span className="pulse-dot ml-1" />
        </motion.div>
        <motion.h1
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="font-display font-black text-2xl lg:text-3xl"
          style={{ color: "#e2e8f8", letterSpacing: "-0.02em" }}
        >
          {t("welcome")},{" "}
          <span style={{ color: "#00e5ff" }}>
            <TypedText text={user?.username ?? "Analyst"} delay={0.3} />
          </span>
        </motion.h1>
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
          className="font-body text-sm mt-1"
          style={{ color: "#7986a8" }}
        >
          Security Operations Center · Real-time threat monitoring &amp; incident response
        </motion.p>
      </div>

      {/* ── Threat alert banner ── */}
      <AnimatePresence>
        {!statsLoading && (stats?.threats_detected ?? 0) > 0 && (
          <motion.div
            initial={{ opacity: 0, y: -10, height: 0 }}
            animate={{ opacity: 1, y: 0, height: "auto" }}
            exit={{ opacity: 0, y: -10, height: 0 }}
            className="mb-6 overflow-hidden"
          >
            <div
              className="p-4 rounded-xl flex items-center gap-3"
              style={{ border: "1px solid rgba(255,61,90,0.2)", background: "rgba(255,61,90,0.05)" }}
            >
              <motion.div animate={{ scale: [1, 1.2, 1] }} transition={{ repeat: Infinity, duration: 2 }}>
                <AlertTriangle size={14} style={{ color: "#ff3d5a", flexShrink: 0 }} />
              </motion.div>
              <span className="font-mono text-xs" style={{ color: "#ff3d5a" }}>
                {stats?.threats_detected} threat{stats?.threats_detected !== 1 ? "s" : ""} detected
                · {stats?.threat_rate}% threat rate
              </span>
              <Link href="/dashboard/history" className="ml-auto">
                <motion.span
                  className="font-mono text-xs"
                  style={{ color: "#ff3d5a", textDecoration: "underline" }}
                  whileHover={{ opacity: 0.7 }}
                >
                  View history →
                </motion.span>
              </Link>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── System risk + top threats ── */}
      {(systemRisk || topDomains.length > 0) && (
        <div className="grid lg:grid-cols-2 gap-4 mb-8">
          {systemRisk && <SystemRiskBadge risk={systemRisk} />}
          {topDomains.length > 0 && <TopThreatsWidget domains={topDomains} />}
        </div>
      )}

      {/* ── Stat cards ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard icon={Shield}        label={t("totalScans")}      value={statsLoading ? 0 : (stats?.total_scans ?? 0)}      color="#00e5ff" delay={0}    />
        <StatCard icon={AlertTriangle} label={t("threatsDetected")} value={statsLoading ? 0 : (stats?.threats_detected ?? 0)} color="#ff3d5a" delay={0.07} sublabel={`${stats?.threat_rate ?? 0}% rate`} />
        <StatCard icon={CheckCircle2}  label={t("safeItems")}       value={statsLoading ? 0 : (stats?.safe ?? 0)}             color="#00e676" delay={0.14} />
        <StatCard icon={TrendingUp}    label="Suspicious"           value={statsLoading ? 0 : (stats?.suspicious ?? 0)}       color="#ffb300" delay={0.21} />
      </div>

      {/* ── Charts ── */}
      <div className="grid lg:grid-cols-3 gap-5 mb-8">
        {/* Area chart */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="glass-card p-5 lg:col-span-2"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="font-display font-semibold text-sm" style={{ color: "#e2e8f8" }}>Scan Activity</h2>
              <p className="font-mono text-xs mt-0.5" style={{ color: "#7986a8" }}>7-day scan vs threat trend</p>
            </div>
            <motion.div
              animate={{ opacity: [0.4, 1, 0.4] }}
              transition={{ repeat: Infinity, duration: 2.5 }}
              className="flex items-center gap-1.5"
            >
              <div className="w-1.5 h-1.5 rounded-full" style={{ background: "#00e5ff" }} />
              <span className="font-mono text-xs" style={{ color: "#3d4d6e" }}>LIVE</span>
            </motion.div>
          </div>
          <ResponsiveContainer width="100%" height={170}>
            <AreaChart data={mockTrend} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="scanGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#00e5ff" stopOpacity={0.18} />
                  <stop offset="95%" stopColor="#00e5ff" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#ff3d5a" stopOpacity={0.18} />
                  <stop offset="95%" stopColor="#ff3d5a" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="date" stroke="#3d4d6e" tick={{ fontSize: 10, fontFamily: "JetBrains Mono", fill: "#3d4d6e" }} tickLine={false} axisLine={false} />
              <YAxis stroke="#3d4d6e" tick={{ fontSize: 10, fontFamily: "JetBrains Mono", fill: "#3d4d6e" }} tickLine={false} axisLine={false} />
              <Tooltip content={<ChartTooltip />} />
              <Area type="monotone" dataKey="scans"   stroke="#00e5ff" fill="url(#scanGrad)"   strokeWidth={2} name="Scans"   dot={false} />
              <Area type="monotone" dataKey="threats" stroke="#ff3d5a" fill="url(#threatGrad)" strokeWidth={2} name="Threats" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Pie chart */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="glass-card p-5"
        >
          <div className="mb-4">
            <h2 className="font-display font-semibold text-sm" style={{ color: "#e2e8f8" }}>Breakdown</h2>
            <p className="font-mono text-xs mt-0.5" style={{ color: "#7986a8" }}>Results distribution</p>
          </div>
          {pieData.some((d) => d.value > 0) ? (
            <>
              <ResponsiveContainer width="100%" height={120}>
                <PieChart>
                  <Pie data={pieData} innerRadius={32} outerRadius={52} paddingAngle={4} dataKey="value">
                    {pieData.map((entry, i) => (
                      <Cell
                        key={i}
                        fill={entry.color}
                        opacity={0.9}
                        style={{ filter: `drop-shadow(0 0 6px ${entry.color}55)` }}
                      />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2 mt-2">
                {pieData.map((d) => (
                  <div key={d.name} className="flex items-center justify-between font-mono text-xs">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full" style={{ background: d.color }} />
                      <span style={{ color: "#7986a8" }}>{d.name}</span>
                    </div>
                    <span style={{ color: d.color }}>{d.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex flex-col items-center justify-center h-40 gap-2">
              <Eye size={22} style={{ color: "#3d4d6e" }} />
              <span className="font-mono text-xs" style={{ color: "#3d4d6e" }}>No scan data yet</span>
            </div>
          )}
        </motion.div>
      </div>

      {/* ── Scanner shortcuts ── */}
      <div className="mb-3">
        <h2 className="font-mono text-xs uppercase tracking-widest" style={{ color: "#3d4d6e" }}>Scanners</h2>
      </div>
      <div className="grid md:grid-cols-3 gap-3 mb-8">
        <ScannerCard icon={Globe}         label="URL Scans"     value={stats?.url_scans ?? 0}     color="#00e5ff" href="/dashboard/url"     delay={0.35} />
        <ScannerCard icon={MessageSquare} label="Message Scans" value={stats?.message_scans ?? 0} color="#00e676" href="/dashboard/message" delay={0.42} />
        <ScannerCard icon={FileSearch}    label="File Scans"    value={stats?.file_scans ?? 0}    color="#c471ed" href="/dashboard/file"    delay={0.49} />
      </div>

      <div className="mb-3">
        <h2 className="font-mono text-xs uppercase tracking-widest" style={{ color: "#3d4d6e" }}>Monitoring</h2>
      </div>
      <div className="grid md:grid-cols-3 gap-3 mb-8">
        <ScannerCard icon={Wifi}    label="Live Threat Detection" value={0} color="#ff3d5a" href="/dashboard/threat"    delay={0.56} badge="LIVE" />
        <ScannerCard icon={Shield}  label="Security Incidents"    value={0} color="#ffb300" href="/dashboard/incidents" delay={0.63} />
        <ScannerCard icon={Network} label="Network Scanner"       value={0} color="#00e5ff" href="/dashboard/network"   delay={0.70} />
      </div>

      {/* ── Recent activity ── */}
      <div className="grid lg:grid-cols-2 gap-5">

        {/* Recent scans */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.55 }}
          className="glass-card p-5"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="font-display font-semibold text-sm" style={{ color: "#e2e8f8" }}>Recent Scans</h2>
              <p className="font-mono text-xs mt-0.5" style={{ color: "#7986a8" }}>Your last 8 submissions</p>
            </div>
            <Link href="/dashboard/history" className="font-mono text-xs transition-opacity hover:opacity-70" style={{ color: "#00e5ff" }}>
              View all →
            </Link>
          </div>

          {historyLoading ? (
            <div className="space-y-2">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="flex items-center gap-3 p-3 rounded-xl" style={{ background: "rgba(255,255,255,0.02)" }}>
                  <div className="w-5 h-5 rounded-lg skeleton flex-shrink-0" />
                  <div className="flex-1 space-y-1.5">
                    <div className="h-2.5 rounded skeleton" style={{ width: "65%" }} />
                    <div className="h-2 rounded skeleton" style={{ width: "40%" }} />
                  </div>
                  <div className="w-14 h-5 rounded-full skeleton" />
                </div>
              ))}
            </div>
          ) : recentScans.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 gap-3">
              <div
                className="w-12 h-12 rounded-2xl flex items-center justify-center"
                style={{ background: "rgba(0,229,255,0.04)", border: "1px solid rgba(0,229,255,0.08)" }}
              >
                <Zap size={20} style={{ color: "#3d4d6e" }} />
              </div>
              <p className="font-mono text-xs" style={{ color: "#3d4d6e" }}>No scans yet — run your first scan</p>
              <Link href="/dashboard/url" className="btn-cyber text-xs px-4 py-2">Start Scanning</Link>
            </div>
          ) : (
            <div className="space-y-1">
              {recentScans.map((scan: any, i: number) => (
                <motion.div
                  key={scan.id}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.55 + i * 0.04 }}
                  className="flex items-center gap-3 p-2.5 rounded-xl transition-colors"
                  style={{ cursor: "default" }}
                >
                  <div className="flex-shrink-0"><ScanTypeIcon type={scan.scan_type} /></div>
                  <div className="flex-1 min-w-0">
                    <div className="font-mono text-xs truncate" style={{ color: "#e2e8f8" }}>{scan.input_data}</div>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <Clock size={9} style={{ color: "#3d4d6e" }} />
                      <span className="font-mono text-xs" style={{ color: "#3d4d6e" }}>{timeAgo(scan.created_at)}</span>
                    </div>
                  </div>
                  <LabelBadge label={scan.label} />
                </motion.div>
              ))}
            </div>
          )}
        </motion.div>

        {/* Recent threats */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="glass-card p-5"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="font-display font-semibold text-sm" style={{ color: "#e2e8f8" }}>Recent Threats</h2>
              <p className="font-mono text-xs mt-0.5" style={{ color: "#7986a8" }}>Phishing, fraud & suspicious</p>
            </div>
            <Link href="/dashboard/history" className="font-mono text-xs transition-opacity hover:opacity-70" style={{ color: "#ff3d5a" }}>
              View all →
            </Link>
          </div>

          {historyLoading ? (
            <div className="space-y-2">
              {[...Array(4)].map((_, i) => (
                <div
                  key={i}
                  className="p-3 rounded-xl"
                  style={{ background: "rgba(255,61,90,0.03)", border: "1px solid rgba(255,61,90,0.08)" }}
                >
                  <div className="h-2.5 rounded skeleton mb-2" style={{ width: "70%" }} />
                  <div className="h-2 rounded skeleton" style={{ width: "45%" }} />
                </div>
              ))}
            </div>
          ) : recentThreats.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 gap-3">
              <div
                className="w-12 h-12 rounded-2xl flex items-center justify-center"
                style={{ background: "rgba(0,230,118,0.04)", border: "1px solid rgba(0,230,118,0.1)" }}
              >
                <CheckCircle2 size={20} style={{ color: "#3d4d6e" }} />
              </div>
              <p className="font-mono text-xs" style={{ color: "#3d4d6e" }}>No threats detected — you're clear</p>
            </div>
          ) : (
            <div className="space-y-2">
              {recentThreats.slice(0, 6).map((scan: any, i: number) => {
                const isPhishing = scan.label === "PHISHING" || scan.label === "FRAUD";
                const color  = isPhishing ? "#ff3d5a" : "#ffb300";
                const bg     = isPhishing ? "rgba(255,61,90,0.05)" : "rgba(255,179,0,0.05)";
                const border = isPhishing ? "rgba(255,61,90,0.15)" : "rgba(255,179,0,0.15)";
                return (
                  <motion.div
                    key={scan.id}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.6 + i * 0.05 }}
                    className="p-3 rounded-xl"
                    style={{ background: bg, border: `1px solid ${border}` }}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-1.5 min-w-0 flex-1">
                        <AlertTriangle size={11} style={{ color, flexShrink: 0 }} />
                        <span className="font-mono text-xs truncate" style={{ color: "#e2e8f8" }}>{scan.input_data}</span>
                      </div>
                      <LabelBadge label={scan.label} />
                    </div>
                    <div className="flex items-center gap-3 mt-1.5">
                      <span className="font-mono text-xs" style={{ color }}>
                        {(scan.confidence * 100).toFixed(0)}% conf.
                      </span>
                      <span className="font-mono text-xs" style={{ color: "#3d4d6e" }}>{timeAgo(scan.created_at)}</span>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          )}
        </motion.div>
      </div>
    </div>
  );
}

"use client";
import Link from "next/link";
import { motion, useMotionValue, useTransform, AnimatePresence } from "framer-motion";
import { useState, useEffect, useRef } from "react";
import {
  Shield, Zap, Lock, Globe, MessageSquare, FileSearch,
  ChevronRight, Activity, User, ArrowUpRight, Terminal,
  Cpu, Eye, AlertTriangle, CheckCircle2, Layers,
} from "lucide-react";
import ThemeToggle from "@/components/ThemeToggle";

// ── Animated stat counter ──────────────────────────────────────────────────────
function CountUp({ end, suffix = "" }: { end: number; suffix?: string }) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let start = 0;
    const duration = 1800;
    const step = 16;
    const increment = end / (duration / step);
    const timer = setInterval(() => {
      start += increment;
      if (start >= end) { setVal(end); clearInterval(timer); }
      else setVal(Math.floor(start));
    }, step);
    return () => clearInterval(timer);
  }, [end]);
  return <>{val.toLocaleString()}{suffix}</>;
}

// ── Terminal typewriter ────────────────────────────────────────────────────────
const terminalLines = [
  { delay: 0, text: "$ phishguard scan --url https://login-paypal-secure.xyz" },
  { delay: 800, text: "> Extracting 30 URL features..." },
  { delay: 1600, text: "> Running RandomForest model..." },
  { delay: 2400, text: "> [PHISHING] Confidence: 97.4%", danger: true },
  { delay: 3200, text: "> 6 indicators found: brand_impersonation, suspicious_tld..." },
  { delay: 4000, text: "> Threat blocked. User protected. ✓", safe: true },
];

function TerminalWindow() {
  const [lines, setLines] = useState<typeof terminalLines>([]);

  useEffect(() => {
    terminalLines.forEach((line) => {
      setTimeout(() => setLines((prev) => [...prev, line]), line.delay);
    });
    const reset = setInterval(() => {
      setLines([]);
      terminalLines.forEach((line) => {
        setTimeout(() => setLines((prev) => [...prev, line]), line.delay);
      });
    }, 7000);
    return () => clearInterval(reset);
  }, []);

  return (
    <>
      <div style={{ position: "absolute", top: 20, right: 20 }}>
        <ThemeToggle />
      </div>

      {/* Your UI */}
      <motion.div
        initial={{ opacity: 0, y: 30, scale: 0.96 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ delay: 0.8, duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
        className="glass-card p-0 overflow-hidden"
        style={{ maxWidth: 580, margin: "0 auto" }}
      >
        {/* Window chrome */}
        <div className="flex items-center gap-2 px-4 py-3" style={{
          borderBottom: "1px solid var(--border-default)",
          background: "var(--bg-surface)"
        }}>
          <div className="w-3 h-3 rounded-full" style={{ background: "#ff5f56" }} />
          <div className="w-3 h-3 rounded-full" style={{ background: "#ffbd2e" }} />
          <div className="w-3 h-3 rounded-full" style={{ background: "#27c93f" }} />
          <span className="font-mono text-xs ml-3" style={{ color: "var(--text-secondary)" }}>phishguard — scan</span>
        </div>
        {/* Terminal body */}
        <div className="p-5 min-h-[180px]" style={{ background: "var(--bg-elevated)" }}>
          <AnimatePresence>
            {lines.map((line, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3 }}
                className="font-mono text-xs leading-7"
                style={{
                  color: line.danger ? "var(--neon-danger)" : line.safe ? "var(--neon-safe)" : i === 0 ? "var(--text-secondary)" : "var(--text-primary)",
                  textShadow: line.danger ? "0 0 12px rgba(255,61,90,0.4)" : line.safe ? "0 0 12px rgba(0,230,118,0.4)" : "none",
                }}
              >
                {line.text}
                {i === lines.length - 1 && lines.length < terminalLines.length && (
                  <span className="cursor-blink" style={{ color: "var(--neon-primary)" }}>▊</span>
                )}
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      </motion.div>
    </>
  );
}

// ── Feature card ───────────────────────────────────────────────────────────────
const features = [
  {
    icon: Globe,
    title: "URL Phishing Detection",
    description: "RandomForest ML trained on 68K+ URLs with 23-feature extraction. Catches brand impersonation, suspicious TLDs, entropy anomalies.",
    accent: "#00e5ff",
    glow: "rgba(0,229,255,0.12)",
  },
  {
    icon: MessageSquare,
    title: "SMS Fraud Detection",
    description: "Hybrid rule-based + AI classification. Detects OTP theft, prize scams, and bank fraud. Native English, Hindi & Hinglish support.",
    accent: "#00e676",
    glow: "rgba(0,230,118,0.12)",
  },
  {
    icon: FileSearch,
    title: "File Content Scanner",
    description: "Upload emails, documents, logs. AES-256 encrypted storage with deep phishing signature analysis and macro detection.",
    accent: "#c471ed",
    glow: "rgba(196,113,237,0.12)",
  },
  {
    icon: Lock,
    title: "Enterprise Security",
    description: "JWT auth, RBAC, bcrypt hashing, per-IP rate limiting, account lockout protection, and full audit trail logging.",
    accent: "#ffb300",
    glow: "rgba(255,179,0,0.12)",
  },
];

// ── Trust indicators ───────────────────────────────────────────────────────────
const stats = [
  { label: "URLs Analyzed", value: 2400000, suffix: "+", display: "8M+" },
  { label: "Threats Blocked", value: 187000, suffix: "+", display: "10K+" },
  { label: "Detection Accuracy", value: 97, suffix: ".2%", display: "97.2%" },
  { label: "Avg Response", value: 200, suffix: "ms", display: "<200ms" },
];

// ── Scanning orb ───────────────────────────────────────────────────────────────
function ScanOrb() {
  return (
    <div className="relative mx-auto" style={{ width: 120, height: 120 }}>
      {/* Outer rings */}
      {[1, 2, 3].map((i) => (
        <motion.div
          key={i}
          className="absolute inset-0 rounded-full"
          style={{
            border: `1px solid rgba(0,229,255,${0.15 / i})`,
            scale: 1 + i * 0.25,
          }}
          animate={{ rotate: 360 * (i % 2 === 0 ? 1 : -1) }}
          transition={{ duration: 8 + i * 4, repeat: Infinity, ease: "linear" }}
        />
      ))}
      {/* Core */}
      <div
        className="absolute inset-0 rounded-full flex items-center justify-center"
        style={{
          background: "radial-gradient(circle, rgba(0,229,255,0.15) 0%, rgba(0,229,255,0.04) 60%, transparent 100%)",
          border: "1px solid rgba(0,229,255,0.3)",
        }}
      >
        <Shield style={{ width: 36, height: 36, color: "#00e5ff", filter: "drop-shadow(0 0 12px rgba(0,229,255,0.7))" }} />
      </div>
    </div>
  );
}

// ── Creator button ─────────────────────────────────────────────────────────────
function CreatorButton() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) return (
    <Link href="/creator" className="font-mono text-xs" style={{ color: "#7986a8" }}>
      About Creator
    </Link>
  );
  return (
    <Link href="/creator" style={{ textDecoration: "none" }}>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.96 }}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg font-mono text-xs"
        style={{
          background: "rgba(0,229,255,0.05)",
          border: "1px solid rgba(0,229,255,0.15)",
          color: "#7986a8",
          transition: "all 0.2s",
        }}
      >
        <User size={11} style={{ color: "#00e5ff" }} />
        About Creator
      </motion.div>
    </Link>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────
export default function LandingPage() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  return (
    <div className="min-h-screen grid-bg relative overflow-hidden" style={{ background: "var(--bg-void)" }}>

      {/* ── Ambient background orbs ── */}
      <div className="fixed inset-0" style={{ zIndex: 0, pointerEvents: "none" }} aria-hidden>
        <div className="absolute" style={{
          top: "-20%", left: "50%", transform: "translateX(-50%)",
          width: 800, height: 600,
          background: "radial-gradient(ellipse, rgba(0,229,255,0.06) 0%, transparent 65%)",
          filter: "blur(40px)",
        }} />
        <div className="absolute" style={{
          bottom: "10%", right: "-10%",
          width: 500, height: 500,
          background: "radial-gradient(ellipse, rgba(196,113,237,0.05) 0%, transparent 65%)",
          filter: "blur(60px)",
        }} />
        <div className="absolute" style={{
          top: "40%", left: "-10%",
          width: 400, height: 400,
          background: "radial-gradient(ellipse, rgba(99,102,241,0.04) 0%, transparent 65%)",
          filter: "blur(50px)",
        }} />
      </div>

      {/* ── Nav ── */}
      <motion.nav
        initial={{ opacity: 0, y: -16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="relative flex items-center justify-between px-8 py-4"
        style={{ zIndex: 10, borderBottom: "1px solid rgba(255,255,255,0.05)" }}
      >
        {/* Logo */}
        <Link href="/" style={{ textDecoration: "none" }} className="flex items-center gap-3">
          <div className="relative">
            <div
              className="w-8 h-8 rounded-xl flex items-center justify-center"
              style={{ background: "rgba(0,229,255,0.08)", border: "1px solid rgba(0,229,255,0.2)" }}
            >
              <Shield size={16} style={{ color: "#00e5ff" }} />
            </div>
            <div
              className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full"
              style={{ background: "#00e676", boxShadow: "0 0 6px #00e676" }}
            />
          </div>
          <span className="font-display font-bold text-lg" style={{ color: "#e2e8f8", letterSpacing: "-0.02em" }}>
            Phish<span style={{ color: "#00e5ff" }}>Guard</span>
          </span>
        </Link>

        {/* Nav actions */}
        <div className="flex items-center gap-3">
          <CreatorButton />
          <Link
            href="/auth/login"
            className="font-mono text-xs px-4 py-2 rounded-lg transition-colors"
            style={{ color: "#7986a8", border: "1px solid transparent" }}
          >
            Sign In
          </Link>
          <Link href="/auth/register" className="btn-primary text-xs">
            Get Started
            <ChevronRight size={13} />
          </Link>
        </div>
      </motion.nav>

      {/* ── Hero ── */}
      <section className="relative max-w-6xl mx-auto px-8 pt-20 pb-12" style={{ zIndex: 10 }}>

        {/* Live badge */}
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2, duration: 0.5 }}
          className="flex justify-center mb-8"
        >
          <div
            className="inline-flex items-center gap-2.5 px-4 py-2 rounded-full font-mono text-xs"
            style={{
              background: "rgba(0,230,118,0.06)",
              border: "1px solid rgba(0,230,118,0.18)",
              color: "#00e676",
              letterSpacing: "0.08em",
            }}
          >
            <span className="pulse-dot" />
            LIVE THREAT DETECTION · 97.2% ACCURACY
          </div>
        </motion.div>

        {/* Heading */}
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3, duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          className="text-center mb-6"
        >
          <h1
            className="font-display font-black leading-none mb-4"
            style={{
              fontSize: "clamp(48px, 8vw, 88px)",
              letterSpacing: "-0.03em",
              color: "#e2e8f8",
            }}
          >
            Detect Phishing<br />
            <span style={{
              background: "linear-gradient(135deg, #00e5ff 0%, #c471ed 100%)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              backgroundClip: "text",
            }}>
              Stop Fraud
            </span>
          </h1>
          <p
            className="font-body text-lg max-w-xl mx-auto leading-relaxed"
            style={{ color: "#7986a8" }}
          >
            Enterprise-grade AI protection against phishing URLs, SMS fraud, and malicious files.
            Real-time. Accurate. Built for security teams.
          </p>
        </motion.div>

        {/* CTAs */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5, duration: 0.5 }}
          className="flex flex-col sm:flex-row items-center justify-center gap-3 mb-16"
        >
          <Link href="/auth/register" className="btn-primary">
            Start Scanning Free
            <ChevronRight size={15} />
          </Link>
          <Link
            href="/auth/login"
            className="btn-cyber"
            style={{ fontSize: 13 }}
          >
            <Eye size={14} />
            View Dashboard
          </Link>
        </motion.div>

        {/* Terminal demo */}
        {mounted && <TerminalWindow />}

        {/* Stats row */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.2, duration: 0.6 }}
          className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-12"
        >
          {stats.map((stat, i) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 1.2 + i * 0.1 }}
              className="glass-card p-5 text-center"
            >
              <div
                className="font-display font-black mb-1"
                style={{ fontSize: 28, color: "#00e5ff", textShadow: "0 0 20px rgba(0,229,255,0.4)" }}
              >
                {stat.display}
              </div>
              <div className="font-mono text-xs uppercase tracking-wider" style={{ color: "#7986a8" }}>
                {stat.label}
              </div>
            </motion.div>
          ))}
        </motion.div>
      </section>

      {/* ── Features ── */}
      <section className="relative max-w-6xl mx-auto px-8 py-20" style={{ zIndex: 10 }}>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center mb-14"
        >
          <div className="font-mono text-xs uppercase tracking-widest mb-3" style={{ color: "#00e5ff" }}>
            Detection Capabilities
          </div>
          <h2 className="font-display font-bold text-3xl mb-3" style={{ color: "#e2e8f8", letterSpacing: "-0.02em" }}>
            Three Layers of Protection
          </h2>
          <p className="font-body text-sm" style={{ color: "#7986a8" }}>
            Built for security analysts, enterprises, and developers
          </p>
        </motion.div>

        <div className="grid md:grid-cols-2 gap-5">
          {features.map((f, i) => (
            <motion.div
              key={f.title}
              initial={{ opacity: 0, y: 24 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.1, duration: 0.5 }}
              whileHover={{ y: -3 }}
              className="glass-card p-6 group cursor-default"
              style={{ transition: "box-shadow 0.2s" }}
            >
              <div className="flex items-start gap-4">
                <motion.div
                  whileHover={{ scale: 1.1, rotate: 5 }}
                  className="w-11 h-11 rounded-xl flex items-center justify-center shrink-0"
                  style={{
                    background: f.glow,
                    border: `1px solid ${f.accent}30`,
                    boxShadow: `0 0 20px ${f.glow}`,
                  }}
                >
                  <f.icon size={20} style={{ color: f.accent }} />
                </motion.div>
                <div>
                  <h3
                    className="font-display font-bold mb-2 text-base"
                    style={{ color: "#e2e8f8", letterSpacing: "-0.01em" }}
                  >
                    {f.title}
                  </h3>
                  <p className="font-body text-sm leading-relaxed" style={{ color: "#7986a8" }}>
                    {f.description}
                  </p>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </section>

      {/* ── How it works ── */}
      <section className="relative max-w-4xl mx-auto px-8 py-16" style={{ zIndex: 10 }}>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="glass-card p-10 text-center overflow-hidden"
        >
          <div className="scanner-line-slow" />
          <ScanOrb />
          <h2
            className="font-display font-bold text-3xl mt-8 mb-3"
            style={{ color: "#e2e8f8", letterSpacing: "-0.02em" }}
          >
            Ready to protect your organization?
          </h2>
          <p className="font-body text-sm mb-8" style={{ color: "#7986a8" }}>
            Free tier available. No credit card required. Enterprise plans with SLA.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            <Link href="/auth/register" className="btn-primary">
              Create Free Account
              <ArrowUpRight size={15} />
            </Link>
          </div>

          <div className="flex items-center justify-center gap-8 mt-10">
            {[
              { icon: CheckCircle2, text: "No card needed", color: "#00e676" },
              { icon: Zap, text: "<200ms response", color: "#00e5ff" },
              { icon: Lock, text: "AES-256 encrypted", color: "#c471ed" },
            ].map((item) => (
              <div key={item.text} className="flex items-center gap-2">
                <item.icon size={13} style={{ color: item.color }} />
                <span className="font-mono text-xs" style={{ color: "#7986a8" }}>{item.text}</span>
              </div>
            ))}
          </div>
        </motion.div>
      </section>

      {/* ── Footer ── */}
      <footer
        className="relative px-8 py-5"
        style={{ zIndex: 10, borderTop: "1px solid rgba(255,255,255,0.05)" }}
      >
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <span className="font-mono text-xs" style={{ color: "#3d4d6e" }}>
            © 2025 PhishGuard · Enterprise Cybersecurity Platform
          </span>
          <div className="flex items-center gap-2">
            <span className="pulse-dot" style={{ background: "#00e676" }} />
            <span className="font-mono text-xs" style={{ color: "#3d4d6e" }}>All systems operational</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

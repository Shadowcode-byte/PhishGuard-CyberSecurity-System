"use client";
import { useState, useEffect, useRef } from "react";
import {
  Globe, Shield, AlertTriangle, CheckCircle2,
  ChevronRight, Loader2, AlertCircle, Zap,
  Copy, ExternalLink, RotateCcw, Clock,
} from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { scanApi } from "@/lib/api";
import toast from "react-hot-toast";
import { clsx } from "clsx";
import { motion, AnimatePresence, useMotionValue, useSpring } from "framer-motion";
import { useTranslations } from "next-intl";


// ── Types ──────────────────────────────────────────────────────────────────────
interface ScanResult {
  scan_id: string;
  label: "SAFE" | "SUSPICIOUS" | "PHISHING";
  confidence: number;
  reasons: string[];
  detection_mode: string;
  created_at: string;
}

// ── Verdict config ─────────────────────────────────────────────────────────────
const VERDICT = {
  PHISHING: {
    color: "#ff3d5a",
    glow: "rgba(255,61,90,0.15)",
    border: "rgba(255,61,90,0.25)",
    bg: "rgba(255,61,90,0.06)",
    icon: AlertTriangle,
    label: "PHISHING",
    ring: "var(--neon-danger)",
    barGrad: "linear-gradient(90deg, #ff3d5a, #ff6b7a)",
    leftBorder: "#ff3d5a",
  },
  SUSPICIOUS: {
    color: "#ffb300",
    glow: "rgba(255,179,0,0.15)",
    border: "rgba(255,179,0,0.25)",
    bg: "rgba(255,179,0,0.06)",
    icon: AlertCircle,
    label: "SUSPICIOUS",
    ring: "var(--neon-warn)",
    barGrad: "linear-gradient(90deg, #ffb300, #ffd54f)",
    leftBorder: "#ffb300",
  },
  SAFE: {
    color: "#00e676",
    glow: "rgba(0,230,118,0.15)",
    border: "rgba(0,230,118,0.25)",
    bg: "rgba(0,230,118,0.06)",
    icon: CheckCircle2,
    label: "SAFE",
    ring: "var(--neon-safe)",
    barGrad: "linear-gradient(90deg, #00e676, #69f0ae)",
    leftBorder: "#00e676",
  },
};

// ── Animated confidence ring ───────────────────────────────────────────────────
function ConfidenceRing({ value, color, size = 100 }: { value: number; color: string; size?: number }) {
  const r = (size - 12) / 2;
  const circ = 2 * Math.PI * r;
  const motionVal = useMotionValue(0);
  const spring = useSpring(motionVal, { duration: 1200, bounce: 0 });
  const [dashOffset, setDashOffset] = useState(circ);

  useEffect(() => {
    motionVal.set(value);
    spring.on("change", (v) => setDashOffset(circ * (1 - v / 100)));
  }, [value]);

  return (
    <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={6} />
      <circle
        cx={size / 2} cy={size / 2} r={r}
        fill="none"
        stroke={color}
        strokeWidth={6}
        strokeDasharray={circ}
        strokeDashoffset={dashOffset}
        strokeLinecap="round"
        style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: "stroke-dashoffset 0.1s" }}
      />
    </svg>
  );
}

// ── Scanning animation ─────────────────────────────────────────────────────────
function ScanningState({ url }: { url: string }) {
  const steps = [
    "Parsing URL structure...",
    "Extracting 23 features...",
    "Checking brand impersonation...",
    "Analyzing domain entropy...",
    "Running RandomForest model...",
    "Computing confidence score...",
  ];
  const [step, setStep] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setStep((prev) => (prev < steps.length - 1 ? prev + 1 : prev));
    }, 400);
    return () => clearInterval(interval);
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.97 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0 }}
      className="glass-card p-8 mt-6 relative overflow-hidden"
    >
      <div className="scanner-line" />

      <div className="flex flex-col items-center text-center">
        {/* Animated shield */}
        <div className="relative mb-6">
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
            className="w-20 h-20 rounded-full absolute inset-0"
            style={{ border: "1px dashed rgba(0,229,255,0.2)" }}
          />
          <motion.div
            animate={{ rotate: -360 }}
            transition={{ duration: 5, repeat: Infinity, ease: "linear" }}
            className="w-16 h-16 rounded-full absolute"
            style={{ top: "50%", left: "50%", transform: "translate(-50%,-50%)", border: "1px dashed rgba(0,229,255,0.1)" }}
          />
          <div
            className="w-14 h-14 rounded-full flex items-center justify-center relative"
            style={{ background: "rgba(0,229,255,0.08)", border: "1px solid rgba(0,229,255,0.2)", margin: "0 auto" }}
          >
            <motion.div animate={{ scale: [1, 1.1, 1] }} transition={{ duration: 1.5, repeat: Infinity }}>
              <Shield size={24} style={{ color: "#00e5ff", filter: "drop-shadow(0 0 8px #00e5ff)" }} />
            </motion.div>
          </div>
        </div>

        <div className="font-mono text-xs mb-1" style={{ color: "#7986a8" }}>ANALYZING</div>
        <div
          className="font-mono text-xs mb-4 truncate max-w-xs"
          style={{ color: "#00e5ff", opacity: 0.8 }}
        >
          {url.slice(0, 50)}{url.length > 50 ? "..." : ""}
        </div>

        {/* Step progress */}
        <div className="w-full max-w-xs space-y-1.5">
          {steps.map((s, i) => (
            <motion.div
              key={s}
              initial={{ opacity: 0 }}
              animate={{ opacity: i <= step ? 1 : 0.2 }}
              className="flex items-center gap-2"
            >
              <div
                className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                style={{
                  background: i < step ? "#00e676" : i === step ? "#00e5ff" : "rgba(255,255,255,0.1)",
                  boxShadow: i === step ? "0 0 8px #00e5ff" : "none",
                }}
              />
              <div
                className="font-mono text-xs text-left"
                style={{ color: i <= step ? "#e2e8f8" : "#3d4d6e" }}
              >
                {s}
              </div>
              {i === step && (
                <motion.div
                  animate={{ opacity: [1, 0, 1] }}
                  transition={{ duration: 0.6, repeat: Infinity }}
                  className="font-mono text-xs"
                  style={{ color: "#00e5ff" }}
                >
                  ●
                </motion.div>
              )}
            </motion.div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

// ── Result card ────────────────────────────────────────────────────────────────
function ResultCard({ result, url }: { result: ScanResult; url: string }) {
  const conf = Math.round(result.confidence * 100);
  const v = VERDICT[result.label] ?? VERDICT.SAFE;
  const Icon = v.icon;

  const copyId = () => {
    navigator.clipboard?.writeText(result.scan_id);
    toast.success("Scan ID copied");
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
      className="mt-6 glass-card overflow-hidden"
      style={{ borderLeft: `3px solid ${v.leftBorder}` }}
    >
      {/* Header */}
      <div className="p-6 pb-0">
        <div className="flex items-start gap-5">
          {/* Icon + ring */}
          <div className="relative flex-shrink-0">
            <ConfidenceRing value={conf} color={v.color} size={80} />
            <div className="absolute inset-0 flex items-center justify-center">
              <Icon size={22} style={{ color: v.color, filter: `drop-shadow(0 0 8px ${v.color})` }} />
            </div>
          </div>

          {/* Verdict text */}
          <div className="flex-1 min-w-0 pt-1">
            <div className="flex items-center gap-3 mb-1 flex-wrap">
              <h2
                className="font-display font-black text-3xl"
                style={{
                  color: v.color,
                  textShadow: `0 0 20px ${v.color}55`,
                  letterSpacing: "-0.02em",
                }}
              >
                {v.label}
              </h2>
              <span
                className="font-mono text-xs px-2 py-1 rounded"
                style={{ background: v.bg, color: v.color, border: `1px solid ${v.border}` }}
              >
                {result.detection_mode}
              </span>
            </div>
            <div
              className="font-mono text-sm truncate mb-3"
              style={{ color: "#7986a8" }}
            >
              {url.slice(0, 60)}{url.length > 60 ? "..." : ""}
            </div>

            {/* Confidence bar */}
            <div className="progress-bar">
              <motion.div
                className="progress-fill"
                initial={{ width: "0%" }}
                animate={{ width: `${conf}%` }}
                transition={{ duration: 0.9, delay: 0.2, ease: [0.22, 1, 0.36, 1] }}
                style={{ background: v.barGrad }}
              />
            </div>
            <div className="flex justify-between mt-1.5">
              <span className="font-mono text-xs" style={{ color: "#7986a8" }}>Confidence</span>
              <span className="font-mono text-xs font-bold" style={{ color: v.color }}>{conf}%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Reasons */}
      {result.reasons.length > 0 && (
        <div className="px-6 pb-6 pt-5">
          <div
            className="font-mono text-xs uppercase tracking-widest mb-3"
            style={{ color: "#3d4d6e" }}
          >
            Detection Signals ({result.reasons.length})
          </div>
          <div className="space-y-2">
            {result.reasons.map((reason, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.3 + i * 0.06 }}
                className="flex items-start gap-3 p-3 rounded-lg text-xs font-mono"
                style={{ background: v.bg, border: `1px solid ${v.border}` }}
              >
                <ChevronRight size={12} style={{ color: v.color, marginTop: 1, flexShrink: 0 }} />
                <span style={{ color: "#c8d0e8" }}>{reason}</span>
              </motion.div>
            ))}
          </div>
        </div>
      )}

      {/* Safe empty state */}
      {result.label === "SAFE" && result.reasons.length === 0 && (
        <div className="px-6 pb-6 pt-2">
          <div
            className="flex items-center gap-3 p-3 rounded-lg font-mono text-xs"
            style={{ background: "rgba(0,230,118,0.05)", border: "1px solid rgba(0,230,118,0.15)" }}
          >
            <CheckCircle2 size={14} style={{ color: "#00e676", flexShrink: 0 }} />
            <span style={{ color: "#7986a8" }}>
              No phishing indicators detected. URL appears legitimate.
            </span>
          </div>
        </div>
      )}

      {/* Footer metadata */}
      <div
        className="px-6 py-3 flex items-center justify-between"
        style={{ borderTop: "1px solid rgba(255,255,255,0.04)", background: "rgba(2,4,10,0.3)" }}
      >
        <div className="flex items-center gap-2">
          <Clock size={11} style={{ color: "#3d4d6e" }} />
          <span className="font-mono text-xs" style={{ color: "#3d4d6e" }}>
            {new Date(result.created_at).toLocaleTimeString()}
          </span>
        </div>
        <button
          onClick={copyId}
          className="flex items-center gap-1.5 font-mono text-xs transition-colors"
          style={{ color: "#3d4d6e", background: "none", border: "none", cursor: "pointer" }}
        >
          <Copy size={11} />
          {result.scan_id.slice(0, 8)}...
        </button>
      </div>
    </motion.div>
  );
}

// ── Sample URLs ────────────────────────────────────────────────────────────────
const SAMPLES = [
  { url: "http://login-paypal-secure.xyz/account", label: "Phishing", color: "#ff3d5a" },
  { url: "https://google.com", label: "Safe", color: "#00e676" },
  { url: "http://192.168.1.1/verify-account-now", label: "Suspicious", color: "#ffb300" },
];

// ── Page ───────────────────────────────────────────────────────────────────────
export default function URLScanPage() {
  const [url, setUrl]       = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const { mutate, isPending } = useMutation({
    mutationFn: (u: string) => scanApi.url(u).then((r) => r.data),
    onSuccess: (data) => {
      setResult(data);
      toast.success(`Analysis complete: ${data.label}`, {
        style: { background: "#080e1c", color: "#e2e8f8", border: "1px solid rgba(255,255,255,0.08)" },
      });
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Scan failed");
    },
  });

  const handleScan = () => {
    if (!url || isPending) return;
    setResult(null);
    mutate(url);
  };

  const handleReset = () => {
    setUrl("");
    setResult(null);
    inputRef.current?.focus();
  };

  return (
    <div className="p-6 md:p-8 max-w-3xl">

      {/* Page header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8"
      >
        <div className="flex items-center gap-2 mb-1">
          <Globe size={14} style={{ color: "#00e5ff" }} />
          <span className="font-mono text-xs uppercase tracking-widest" style={{ color: "#00e5ff" }}>
            URL Analysis
          </span>
        </div>
        <h1
          className="font-display font-bold text-2xl mb-1"
          style={{ color: "#e2e8f8", letterSpacing: "-0.02em" }}
        >
          URL Phishing Scanner
        </h1>
        <p className="font-body text-sm" style={{ color: "#7986a8" }}>
          RandomForest ML · 23 features extracted · 97.2% accuracy
        </p>
      </motion.div>

      {/* Scan form */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="glass-card p-6 relative overflow-hidden"
      >
        <div className="scanner-line-slow" />

        <label className="block font-mono text-xs uppercase tracking-widest mb-3" style={{ color: "#3d4d6e" }}>
          URL to analyze
        </label>

        <div className="flex gap-3">
          <div className="flex-1 relative">
            <Globe
              size={14}
              className="absolute left-4 top-1/2 -translate-y-1/2"
              style={{ color: "#3d4d6e", pointerEvents: "none" }}
            />
            <input
              ref={inputRef}
              type="url"
              className="scan-input"
              style={{ paddingLeft: 36 }}
              placeholder="https://example.com/login?token=..."
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
          </div>

          <motion.button
            className="btn-cyber px-5 flex-shrink-0"
            onClick={handleScan}
            disabled={!url || isPending}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.97 }}
          >
            {isPending ? (
              <Loader2 size={15} className="animate-spin" />
            ) : (
              <>
                <Shield size={15} />
                <span>Scan</span>
              </>
            )}
          </motion.button>

          {(result || url) && (
            <motion.button
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              className="btn-cyber px-3 flex-shrink-0"
              onClick={handleReset}
              title="Reset"
            >
              <RotateCcw size={14} />
            </motion.button>
          )}
        </div>

        {/* Sample URLs */}
        <div className="mt-4">
          <div className="font-mono text-xs mb-2" style={{ color: "#3d4d6e" }}>Try a sample:</div>
          <div className="flex flex-wrap gap-2">
            {SAMPLES.map((s) => (
              <button
                key={s.url}
                onClick={() => setUrl(s.url)}
                className="group flex items-center gap-1.5 font-mono text-xs px-3 py-1.5 rounded-lg transition-all"
                style={{
                  background: "rgba(255,255,255,0.02)",
                  border: "1px solid rgba(255,255,255,0.06)",
                  color: "#7986a8",
                  cursor: "pointer",
                }}
              >
                <span
                  className="w-1.5 h-1.5 rounded-full"
                  style={{ background: s.color, flexShrink: 0 }}
                />
                {s.label}
                <ExternalLink size={10} style={{ opacity: 0.4 }} />
              </button>
            ))}
          </div>
        </div>
      </motion.div>

      {/* Scanning animation */}
      <AnimatePresence>
        {isPending && <ScanningState url={url} />}
      </AnimatePresence>

      {/* Result */}
      <AnimatePresence>
        {result && !isPending && <ResultCard result={result} url={url} />}
      </AnimatePresence>

      {/* Empty state */}
      <AnimatePresence>
        {!result && !isPending && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="mt-8 text-center"
          >
            <div
              className="w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-4"
              style={{ background: "rgba(0,229,255,0.04)", border: "1px solid rgba(0,229,255,0.1)" }}
            >
              <Zap size={24} style={{ color: "rgba(0,229,255,0.3)" }} />
            </div>
            <p className="font-body text-sm" style={{ color: "#3d4d6e" }}>
              Enter a URL above to analyze it for phishing threats
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

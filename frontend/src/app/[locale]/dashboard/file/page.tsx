"use client";
import { useState, useCallback } from "react";
import { useDropzone } from "react-dropzone";
import {
  FileSearch, Upload, FileText, AlertTriangle, Loader2,
  ShieldCheck, ShieldAlert, ShieldX, ChevronDown, ChevronUp,
  AlertCircle, Info, Link2, MessageSquareWarning, Zap,
  ScanLine, FlaskConical, Microscope, BrainCircuit, RotateCcw,
  CheckCircle2, X, File,
} from "lucide-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { scanApi } from "@/lib/api";
import toast from "react-hot-toast";
import { clsx } from "clsx";
import { motion, AnimatePresence } from "framer-motion";
import { useTranslations } from "next-intl";

// ── Types ──────────────────────────────────────────────────────────────────────
type ScanLabel = "SAFE" | "SUSPICIOUS" | "PHISHING" | "FRAUD";

interface ScanStatusData {
  file_id: string;
  status: "pending" | "processing" | "done" | "error";
  progress: number;
  message: string;
  result_label?: ScanLabel;
  result_reasons?: string[];
  confidence?: number;
  threats_found?: number;
  urls_found?: number;
  messages_found?: number;
}

// ── Finding tier classifier ────────────────────────────────────────────────────
type FindingTier = "critical" | "danger" | "warning" | "ok" | "info";

const CRITICAL_TERMS = ["virustotal","executable","macro","vba","base64 payload","high entropy","packed","encrypted payload","malicious engine"];
const DANGER_TERMS   = ["malicious","javascript","launch action","phishing","fraud","/js ","auto-open","obfuscat"];
const WARNING_TERMS  = ["suspicious","high risk","high-risk","embedded","uri object","[ai]","credit card","wire transfer","bitcoin"];

function classifyFinding(text: string): FindingTier {
  const t = text.toLowerCase();
  if (t.startsWith("file is clean") || t.includes("no suspicious content") || t.includes("no threats detected")) return "ok";
  if (CRITICAL_TERMS.some((k) => t.includes(k))) return "critical";
  if (DANGER_TERMS.some((k) => t.includes(k)))   return "danger";
  if (WARNING_TERMS.some((k) => t.includes(k)))  return "warning";
  if (t.includes("clean") || t.includes("no suspicious") || t.includes("safe")) return "ok";
  return "info";
}

// ── Tier styling ───────────────────────────────────────────────────────────────
const TIER_CONFIG = {
  critical: { color: "#ff3d5a", bg: "rgba(255,61,90,0.08)",  border: "rgba(255,61,90,0.2)",  icon: ShieldX,      label: "CRITICAL" },
  danger:   { color: "#ff3d5a", bg: "rgba(255,61,90,0.06)",  border: "rgba(255,61,90,0.15)", icon: ShieldAlert,  label: "DANGER"   },
  warning:  { color: "#ffb300", bg: "rgba(255,179,0,0.06)",  border: "rgba(255,179,0,0.15)", icon: AlertTriangle, label: "WARNING"  },
  ok:       { color: "#00e676", bg: "rgba(0,230,118,0.06)",  border: "rgba(0,230,118,0.15)", icon: ShieldCheck,  label: "OK"       },
  info:     { color: "#00e5ff", bg: "rgba(0,229,255,0.05)",  border: "rgba(0,229,255,0.12)", icon: Info,         label: "INFO"     },
};

// ── Label verdict config ───────────────────────────────────────────────────────
const VERDICT_CONFIG = {
  SAFE:       { color: "#00e676", barGrad: "linear-gradient(90deg,#00e676,#69f0ae)", leftBorder: "#00e676" },
  SUSPICIOUS: { color: "#ffb300", barGrad: "linear-gradient(90deg,#ffb300,#ffd54f)", leftBorder: "#ffb300" },
  PHISHING:   { color: "#ff3d5a", barGrad: "linear-gradient(90deg,#ff3d5a,#ff6b7a)", leftBorder: "#ff3d5a" },
  FRAUD:      { color: "#ff3d5a", barGrad: "linear-gradient(90deg,#ff3d5a,#ff6b7a)", leftBorder: "#ff3d5a" },
};

// ── Finding row ────────────────────────────────────────────────────────────────
function FindingRow({ text }: { text: string }) {
  const tier = classifyFinding(text);
  const cfg  = TIER_CONFIG[tier];
  const Icon = cfg.icon;

  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      className="flex items-start gap-3 p-3 rounded-lg text-xs font-mono"
      style={{ background: cfg.bg, border: `1px solid ${cfg.border}` }}
    >
      <Icon size={12} style={{ color: cfg.color, flexShrink: 0, marginTop: 1 }} />
      <span style={{ color: "#c8d0e8" }}>{text}</span>
      <span
        className="ml-auto flex-shrink-0 text-xs font-bold"
        style={{ color: cfg.color, fontSize: 9, letterSpacing: "0.08em" }}
      >
        {cfg.label}
      </span>
    </motion.div>
  );
}

// ── Result panel ───────────────────────────────────────────────────────────────
function ScanResultPanel({ scanStatus }: { scanStatus: ScanStatusData }) {
  const [expanded, setExpanded] = useState(true);
  const reasons = scanStatus.result_reasons ?? [];
  const label   = (scanStatus.result_label ?? "SAFE") as ScanLabel;
  const conf    = Math.round((scanStatus.confidence ?? 0) * 100);
  const v = VERDICT_CONFIG[label] ?? VERDICT_CONFIG.SAFE;

  const VerdictIcon =
    label === "SAFE" ? ShieldCheck :
    label === "SUSPICIOUS" ? ShieldAlert :
    ShieldX;

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card mt-5 overflow-hidden"
      style={{ borderLeft: `3px solid ${v.leftBorder}` }}
    >
      {/* Verdict header */}
      <div className="p-5 flex items-center gap-4">
        <div
          className="w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0"
          style={{
            background: `${v.color}12`,
            border: `1px solid ${v.color}25`,
            boxShadow: `0 0 20px ${v.color}20`,
          }}
        >
          <VerdictIcon size={22} style={{ color: v.color, filter: `drop-shadow(0 0 6px ${v.color})` }} />
        </div>
        <div className="flex-1 min-w-0">
          <div
            className="font-display font-black text-2xl"
            style={{ color: v.color, letterSpacing: "-0.02em", textShadow: `0 0 20px ${v.color}55` }}
          >
            {label}
          </div>
          {conf > 0 && (
            <div className="mt-1.5">
              <div className="progress-bar" style={{ height: 3 }}>
                <motion.div
                  className="progress-fill"
                  initial={{ width: "0%" }}
                  animate={{ width: `${conf}%` }}
                  transition={{ duration: 0.8, delay: 0.2 }}
                  style={{ background: v.barGrad }}
                />
              </div>
              <div className="font-mono text-xs mt-1" style={{ color: "#7986a8" }}>
                {conf}% confidence
              </div>
            </div>
          )}
        </div>

        <div className="flex items-center gap-3 flex-shrink-0 font-mono text-xs" style={{ color: "#7986a8" }}>
          {scanStatus.threats_found !== undefined && (
            <span style={{ color: scanStatus.threats_found > 0 ? "#ff3d5a" : "#00e676" }}>
              {scanStatus.threats_found} threats
            </span>
          )}
          {scanStatus.urls_found !== undefined && (
            <span>{scanStatus.urls_found} URLs</span>
          )}
          <button
            onClick={() => setExpanded((p) => !p)}
            className="p-1 rounded"
            style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.07)", cursor: "pointer" }}
          >
            {expanded ? <ChevronUp size={13} style={{ color: "#7986a8" }} /> : <ChevronDown size={13} style={{ color: "#7986a8" }} />}
          </button>
        </div>
      </div>

      {/* Expandable findings */}
      <AnimatePresence>
        {expanded && reasons.length > 0 && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            style={{ overflow: "hidden" }}
          >
            <div
              className="px-5 pb-5"
              style={{ borderTop: "1px solid rgba(255,255,255,0.04)" }}
            >
              <div className="font-mono text-xs uppercase tracking-widest mb-3 mt-4" style={{ color: "#3d4d6e" }}>
                Analysis Findings ({reasons.length})
              </div>
              <div className="space-y-1.5">
                {reasons.map((r, i) => (
                  <FindingRow key={i} text={r} />
                ))}
              </div>
            </div>
          </motion.div>
        )}

        {expanded && reasons.length === 0 && label === "SAFE" && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="px-5 pb-5"
            style={{ borderTop: "1px solid rgba(255,255,255,0.04)" }}
          >
            <div className="flex items-center gap-3 mt-4 p-3 rounded-lg font-mono text-xs"
              style={{ background: "rgba(0,230,118,0.05)", border: "1px solid rgba(0,230,118,0.15)" }}>
              <CheckCircle2 size={13} style={{ color: "#00e676", flexShrink: 0 }} />
              <span style={{ color: "#7986a8" }}>No malicious content detected. File appears clean.</span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ── Progress tracker ───────────────────────────────────────────────────────────
function ScanProgress({ scanStatus, fileName, fileId }: {
  scanStatus: ScanStatusData; fileName: string; fileId: string;
}) {
  const progress = scanStatus.progress ?? 0;
  const isError  = scanStatus.status === "error";

  const stages = [
    { label: "Encrypting", done: progress >= 10 },
    { label: "Hashing", done: progress >= 25 },
    { label: "VT Lookup", done: progress >= 45 },
    { label: "Deep Scan", done: progress >= 70 },
    { label: "AI Analysis", done: progress >= 90 },
    { label: "Report", done: progress >= 100 },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card p-6 mt-5 relative overflow-hidden"
      style={{ borderLeft: `3px solid ${isError ? "#ff3d5a" : "#c471ed"}` }}
    >
      <div className="scanner-line" />

      <div className="flex items-center gap-3 mb-5">
        {isError ? (
          <AlertTriangle size={20} style={{ color: "#ff3d5a" }} />
        ) : (
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
          >
            <Loader2 size={20} style={{ color: "#c471ed" }} />
          </motion.div>
        )}
        <div>
          <div className="font-display font-bold text-base" style={{ color: "#e2e8f8" }}>
            {isError ? "Sandbox Error" : "Detonating in Sandbox..."}
          </div>
          <div className="font-mono text-xs mt-0.5" style={{ color: "#7986a8" }}>
            {fileName} · ID: {fileId.slice(0, 8)}…
          </div>
        </div>
        <div className="ml-auto font-mono text-sm font-bold" style={{ color: isError ? "#ff3d5a" : "#c471ed" }}>
          {progress}%
        </div>
      </div>

      {/* Stage dots */}
      <div className="flex items-center justify-between mb-4">
        {stages.map((stage, i) => (
          <div key={stage.label} className="flex flex-col items-center gap-1 flex-1">
            <div
              className="w-2 h-2 rounded-full transition-all duration-500"
              style={{
                background: stage.done ? "#c471ed" : "rgba(255,255,255,0.08)",
                boxShadow: stage.done ? "0 0 8px #c471ed" : "none",
              }}
            />
            <div className="font-mono text-xs hidden sm:block" style={{ color: stage.done ? "#c471ed" : "#3d4d6e", fontSize: 9 }}>
              {stage.label}
            </div>
            {i < stages.length - 1 && (
              <div className="absolute" /> /* connector handled by bar */
            )}
          </div>
        ))}
      </div>

      {/* Progress bar */}
      <div className="progress-bar" style={{ height: 3 }}>
        <motion.div
          className="progress-fill"
          style={{ width: `${progress}%`, background: isError ? "#ff3d5a" : "linear-gradient(90deg,#c471ed,#6366f1)" }}
        />
      </div>

      <div className="font-mono text-xs mt-3" style={{ color: "#7986a8" }}>
        {scanStatus.message ?? "Initializing sandbox..."}
      </div>
    </motion.div>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────────
export default function FileScanPage() {
  const [file, setFile]     = useState<File | null>(null);
  const [result, setResult] = useState<{ file_id: string; filename?: string } | null>(null);

  const { mutate, isPending } = useMutation({
    mutationFn: (f: File) => scanApi.file(f).then((r) => r.data),
    onSuccess: (data) => setResult(data),
    onError: (err: any) => toast.error(err?.response?.data?.detail || "Upload failed"),
  });

  const { data: scanStatus } = useQuery({
    queryKey: ["scan-status", result?.file_id],
    queryFn: () => scanApi.fileStatus(result!.file_id).then((r) => r.data),
    enabled: !!result?.file_id,
    refetchInterval: (data: any) =>
      data?.status === "done" || data?.status === "error" ? false : 1500,
  });

  const onDrop = useCallback((files: File[]) => {
    if (files[0]) setFile(files[0]);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false,
    maxSize: 10 * 1024 * 1024,
    accept: {
      "text/plain": [".txt"],
      "text/html": [".html", ".htm"],
      "application/pdf": [".pdf"],
      "application/json": [".json"],
      "text/csv": [".csv"],
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [".docx"],
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [".xlsx"],
      "application/zip": [".zip"],
    },
  });

  const isDone     = scanStatus?.status === "done";
  const isError    = scanStatus?.status === "error";
  const isScanning = !!result && !isDone && !isError;

  const handleReset = () => { setFile(null); setResult(null); };

  return (
    <div className="p-6 md:p-8 max-w-3xl">

      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8"
      >
        <div className="flex items-center gap-2 mb-1">
          <ScanLine size={14} style={{ color: "#c471ed" }} />
          <span className="font-mono text-xs uppercase tracking-widest" style={{ color: "#c471ed" }}>
            Malware Sandbox
          </span>
        </div>
        <h1 className="font-display font-bold text-2xl mb-1" style={{ color: "#e2e8f8", letterSpacing: "-0.02em" }}>
          File Scanner
        </h1>
        <p className="font-body text-sm" style={{ color: "#7986a8" }}>
          VirusTotal integration · Zero-day detection · Macro & entropy analysis
        </p>
      </motion.div>

      {/* Drop zone — hidden while scanning or done */}
      <AnimatePresence>
        {!isDone && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
          >
            <div
              {...getRootProps()}
              className="glass-card p-10 text-center cursor-pointer relative overflow-hidden transition-all duration-300"
              style={{
                borderStyle: "dashed",
                borderColor: isDragActive
                  ? "rgba(196,113,237,0.6)"
                  : file
                  ? "rgba(196,113,237,0.3)"
                  : "rgba(255,255,255,0.08)",
                background: isDragActive
                  ? "rgba(196,113,237,0.05)"
                  : file
                  ? "rgba(196,113,237,0.03)"
                  : "rgba(13,22,40,0.5)",
              }}
            >
              <input {...getInputProps()} />
              {file ? (
                <div className="flex flex-col items-center gap-3">
                  <div
                    className="w-14 h-14 rounded-2xl flex items-center justify-center"
                    style={{ background: "rgba(196,113,237,0.1)", border: "1px solid rgba(196,113,237,0.25)" }}
                  >
                    <FileText size={26} style={{ color: "#c471ed" }} />
                  </div>
                  <div>
                    <div className="font-display font-semibold text-sm mb-0.5" style={{ color: "#e2e8f8" }}>
                      {file.name}
                    </div>
                    <div className="font-mono text-xs" style={{ color: "#7986a8" }}>
                      {(file.size / 1024).toFixed(1)} KB · {file.type || "unknown type"}
                    </div>
                  </div>
                  <div className="font-mono text-xs" style={{ color: "rgba(196,113,237,0.6)" }}>
                    Drop another file to replace
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center gap-3">
                  <motion.div
                    animate={isDragActive ? { scale: [1, 1.1, 1] } : {}}
                    transition={{ duration: 0.5, repeat: Infinity }}
                    className="w-14 h-14 rounded-2xl flex items-center justify-center"
                    style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)" }}
                  >
                    <Upload size={24} style={{ color: "#7986a8" }} />
                  </motion.div>
                  <div>
                    <div className="font-display font-semibold text-sm mb-1" style={{ color: "#e2e8f8" }}>
                      {isDragActive ? "Release to detonate..." : "Drag & drop or click to upload"}
                    </div>
                    <div className="font-mono text-xs" style={{ color: "#3d4d6e" }}>
                      .pdf · .docx · .xlsx · .zip · .txt · .html · .csv · .json · Max 10MB
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Capability cards */}
            {!result && (
              <div className="grid grid-cols-3 gap-3 mt-4">
                {[
                  { Icon: FlaskConical, label: "Static Analysis",  desc: "SHA-256 · VT hash lookup · entropy" },
                  { Icon: Microscope,   label: "Deep Inspection",   desc: "Macros · EXEs in ZIP · base64" },
                  { Icon: BrainCircuit, label: "AI Threat Eval",   desc: "LLM classification of strings" },
                ].map(({ Icon, label, desc }) => (
                  <div key={label} className="glass-card p-3 text-center">
                    <div className="flex items-center justify-center gap-1.5 mb-1.5">
                      <Icon size={12} style={{ color: "#c471ed" }} />
                      <div className="font-mono text-xs font-semibold" style={{ color: "#e2e8f8" }}>{label}</div>
                    </div>
                    <div className="font-mono text-xs" style={{ color: "#3d4d6e" }}>{desc}</div>
                  </div>
                ))}
              </div>
            )}

            {/* Submit button */}
            {file && !result && (
              <motion.button
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="btn-cyber w-full py-3.5 mt-4 font-mono text-sm"
                style={{ borderColor: "rgba(196,113,237,0.4)", color: "#c471ed" }}
                onClick={() => mutate(file)}
                disabled={isPending}
                whileHover={{ scale: 1.01 }}
                whileTap={{ scale: 0.99 }}
              >
                {isPending ? (
                  <span className="flex items-center justify-center gap-2">
                    <Loader2 size={15} className="animate-spin" />
                    Uploading & Encrypting...
                  </span>
                ) : (
                  <span className="flex items-center justify-center gap-2">
                    <Zap size={15} />
                    Detonate in Sandbox
                  </span>
                )}
              </motion.button>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Scanning progress */}
      <AnimatePresence>
        {isScanning && scanStatus && (
          <ScanProgress
            scanStatus={scanStatus}
            fileName={file?.name ?? result?.filename ?? "file"}
            fileId={result?.file_id ?? ""}
          />
        )}
      </AnimatePresence>

      {/* Done: result */}
      <AnimatePresence>
        {isDone && scanStatus && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <div className="flex items-center gap-2 mb-1 px-1">
              <File size={13} style={{ color: "#c471ed" }} />
              <span className="font-mono text-xs truncate" style={{ color: "#7986a8" }}>
                {file?.name ?? result?.filename ?? "Uploaded file"}
              </span>
              <span className="font-mono text-xs flex-shrink-0" style={{ color: "#3d4d6e" }}>
                · {result?.file_id?.slice(0, 8)}…
              </span>
            </div>

            <ScanResultPanel scanStatus={scanStatus} />

            <motion.button
              className="btn-cyber w-full py-3 mt-4 text-xs font-mono"
              style={{ borderColor: "rgba(196,113,237,0.2)", color: "#c471ed" }}
              onClick={handleReset}
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.99 }}
            >
              <RotateCcw size={13} />
              Submit Another Sample
            </motion.button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Empty state */}
      <AnimatePresence>
        {!file && !result && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="mt-8 text-center"
          >
            <p className="font-body text-sm" style={{ color: "#3d4d6e" }}>
              Upload a file to scan it for phishing, malware, and fraud indicators
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

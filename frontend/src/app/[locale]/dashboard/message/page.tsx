"use client";
import { useState } from "react";
import { MessageSquare, AlertTriangle, CheckCircle, Info, ChevronRight, Loader2 } from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { scanApi } from "@/lib/api";
import toast from "react-hot-toast";
import { clsx } from "clsx";
import { useTranslations } from "next-intl";

interface MessageResult {
  scan_id: string;
  label: string;
  final_score: number;
  rule_score: number;
  confidence_level: string;
  reasons: string[];
  language: string;
  api_used: boolean;
  created_at: string;
}

const LABEL_CONFIG = {
  FRAUD: { color: "red", icon: AlertTriangle, text: "text-neon-red", bg: "bg-neon-red/10", border: "border-neon-red/30" },
  SUSPICIOUS: { color: "yellow", icon: Info, text: "text-neon-yellow", bg: "bg-neon-yellow/10", border: "border-neon-yellow/30" },
  SAFE: { color: "green", icon: CheckCircle, text: "text-neon-green", bg: "bg-neon-green/10", border: "border-neon-green/30" },
};

const SAMPLES = [
  "Your bank account will be blocked. Send OTP immediately to verify your account.",
  "Congratulations! You've won Rs 5,00,000 in our lucky draw. Click here to claim now!",
  "Hi, your order has been shipped. Track at amazon.com/track/123",
  "Aapka bank account band ho jayega. Abhi apna PIN bhejiye warna legal action hoga.",
];

export default function MessageScanPage() {
  const t = useTranslations("scan.message");
  const [message, setMessage] = useState("");
  const [result, setResult] = useState<MessageResult | null>(null);

  const { mutate, isPending } = useMutation({
    mutationFn: (m: string) => scanApi.message(m).then((r) => r.data),
    onSuccess: (data) => {
      setResult(data);
      toast.success(`Analysis complete: ${data.label}`);
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Scan failed");
    },
  });

  const cfg = result ? LABEL_CONFIG[result.label as keyof typeof LABEL_CONFIG] || LABEL_CONFIG.SAFE : null;

  return (
    <div className="p-8 max-w-3xl">
      <div className="mb-8">
        <div className="flex items-center gap-2 mb-1">
          <MessageSquare className="w-4 h-4 text-neon-green" />
          <span className="text-neon-green font-mono text-xs uppercase tracking-widest">Message Analysis</span>
        </div>
        <h1 className="font-display text-2xl font-bold text-text-primary">SMS Fraud Detector</h1>
        <p className="text-text-secondary font-mono text-sm mt-1">
          Rule-based + AI hybrid · Multi-language · OTP / bank fraud detection
        </p>
      </div>

      <div className="cyber-card p-6">
        <div className="scanner-line" />
        <label className="block text-text-secondary text-xs font-mono uppercase tracking-wider mb-3">
          Paste message to analyze
        </label>
        <textarea
          className="scan-input min-h-32 resize-y leading-relaxed"
          placeholder="Enter suspicious SMS, WhatsApp message, or email text..."
          value={message}
          onChange={(e) => setMessage(e.target.value)}
        />

        <div className="flex items-center justify-between mt-4">
          <div className="flex flex-wrap gap-2">
            <span className="text-text-secondary text-xs font-mono">Samples:</span>
            {SAMPLES.map((s, i) => (
              <button
                key={i}
                onClick={() => setMessage(s)}
                className="text-xs font-mono text-text-secondary border border-cyber-border px-2 py-1 rounded hover:border-neon-green/30 hover:text-neon-green transition-all"
              >
                Sample {i + 1}
              </button>
            ))}
          </div>

          <button
            className="btn-cyber px-6 shrink-0"
            style={{ borderColor: "rgba(0,255,136,0.4)", color: "#00ff88" }}
            onClick={() => mutate(message)}
            disabled={!message.trim() || isPending}
          >
            {isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : "Analyze →"}
          </button>
        </div>
      </div>

      {isPending && (
        <div className="cyber-card p-8 mt-6 text-center">
          <div className="scanner-line" />
          <Loader2 className="w-8 h-8 text-neon-green animate-spin mx-auto mb-3" />
          <div className="text-neon-green font-mono text-sm">Analyzing message...</div>
          <div className="text-text-secondary font-mono text-xs mt-1">
            Detecting language · Running rule engine · AI classification
          </div>
        </div>
      )}

      {result && !isPending && cfg && (
        <div className={clsx("cyber-card p-6 mt-6 border-l-4", {
          "border-l-neon-red": result.label === "FRAUD",
          "border-l-neon-yellow": result.label === "SUSPICIOUS",
          "border-l-neon-green": result.label === "SAFE",
        })}>
          {/* Verdict */}
          <div className="flex items-center gap-4 mb-5">
            <div className={clsx("w-12 h-12 rounded-xl flex items-center justify-center border", cfg.bg, cfg.border)}>
              <cfg.icon className={clsx("w-6 h-6", cfg.text)} />
            </div>
            <div>
              <div className={clsx("font-display text-2xl font-bold", cfg.text)}>{result.label}</div>
              <div className="text-text-secondary text-xs font-mono">
                Language: {result.language} · {result.api_used ? "AI enhanced" : "Rule-based"} · {result.confidence_level} confidence
              </div>
            </div>
            <div className="ml-auto text-right">
              <div className={clsx("font-display text-3xl font-bold", cfg.text)}>
                {Math.round(result.final_score * 100)}%
              </div>
              <div className="text-text-secondary text-xs font-mono">risk score</div>
            </div>
          </div>

          {/* Scores */}
          <div className="grid grid-cols-2 gap-3 mb-5">
            {[
              { label: "Rule Score", value: result.rule_score },
              { label: "Final Score", value: result.final_score },
            ].map((s) => (
              <div key={s.label} className="bg-cyber-dark/50 rounded-lg p-3">
                <div className="text-text-secondary text-xs font-mono mb-2">{s.label}</div>
                <div className="progress-bar">
                  <div className="progress-fill" style={{
                    width: `${Math.round(s.value * 100)}%`,
                    background: result.label === "FRAUD"
                      ? "linear-gradient(90deg, #ff2d55, #ff6b88)"
                      : result.label === "SUSPICIOUS"
                      ? "linear-gradient(90deg, #ffd60a, #ffea70)"
                      : "linear-gradient(90deg, #00ff88, #00ffaa)",
                  }} />
                </div>
                <div className={clsx("font-mono text-sm mt-1", cfg.text)}>
                  {Math.round(s.value * 100)}%
                </div>
              </div>
            ))}
          </div>

          {/* Reasons */}
          {result.reasons.length > 0 && (
            <div>
              <div className="text-text-secondary text-xs font-mono uppercase tracking-wider mb-3">
                Triggered Rules ({result.reasons.length})
              </div>
              <div className="space-y-2">
                {result.reasons.map((reason, i) => (
                  <div key={i} className={clsx(
                    "flex items-start gap-2.5 p-3 rounded-lg text-xs font-mono border",
                    cfg.bg, cfg.border
                  )}>
                    <ChevronRight className={clsx("w-3.5 h-3.5 mt-0.5 shrink-0", cfg.text)} />
                    <span className="text-text-primary">{reason}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

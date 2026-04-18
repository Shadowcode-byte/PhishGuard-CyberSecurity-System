"use client";
/**
 * PhishGuard UI Components
 * ─────────────────────────────────────────────────────────────────────────────
 * Shared, reusable components for the PhishGuard design system.
 * Import from: @/components/ui
 */
import { motion, AnimatePresence } from "framer-motion";
import { ReactNode, useState } from "react";
import {
  CheckCircle2, AlertTriangle, AlertCircle, Info,
  X, Shield, Loader2,
} from "lucide-react";

// ── SectionHeader ─────────────────────────────────────────────────────────────
export function SectionHeader({
  eyebrow, title, description, accentColor = "#00e5ff",
}: {
  eyebrow?: string; title: string; description?: string; accentColor?: string;
}) {
  return (
    <div className="mb-8">
      {eyebrow && (
        <div className="flex items-center gap-2 mb-2">
          <div className="w-1.5 h-1.5 rounded-full" style={{ background: accentColor }} />
          <span className="font-mono text-xs uppercase tracking-widest" style={{ color: accentColor }}>
            {eyebrow}
          </span>
        </div>
      )}
      <h1 className="font-display font-bold text-2xl" style={{ color: "#e2e8f8", letterSpacing: "-0.02em" }}>
        {title}
      </h1>
      {description && (
        <p className="font-body text-sm mt-1" style={{ color: "#7986a8" }}>{description}</p>
      )}
    </div>
  );
}

// ── StatusPill ────────────────────────────────────────────────────────────────
export function StatusPill({ label }: { label: string }) {
  const cfg: Record<string, { color: string; bg: string; border: string }> = {
    PHISHING:   { color: "#ff3d5a", bg: "rgba(255,61,90,0.1)",  border: "rgba(255,61,90,0.2)"  },
    FRAUD:      { color: "#ff3d5a", bg: "rgba(255,61,90,0.1)",  border: "rgba(255,61,90,0.2)"  },
    SUSPICIOUS: { color: "#ffb300", bg: "rgba(255,179,0,0.1)",  border: "rgba(255,179,0,0.2)"  },
    SAFE:       { color: "#00e676", bg: "rgba(0,230,118,0.1)",  border: "rgba(0,230,118,0.2)"  },
    PENDING:    { color: "#00e5ff", bg: "rgba(0,229,255,0.1)",  border: "rgba(0,229,255,0.2)"  },
    ERROR:      { color: "#ff3d5a", bg: "rgba(255,61,90,0.1)",  border: "rgba(255,61,90,0.2)"  },
  };
  const c = cfg[label?.toUpperCase()] ?? { color: "#7986a8", bg: "transparent", border: "rgba(255,255,255,0.08)" };
  return (
    <span
      className="font-mono inline-flex items-center gap-1.5"
      style={{
        color: c.color,
        background: c.bg,
        border: `1px solid ${c.border}`,
        fontSize: 10,
        letterSpacing: "0.08em",
        padding: "2px 8px",
        borderRadius: 999,
        fontWeight: 700,
        textTransform: "uppercase",
      }}
    >
      {label}
    </span>
  );
}

// ── Toast-like alert banner ────────────────────────────────────────────────────
type AlertVariant = "info" | "success" | "warning" | "error";

const ALERT_CONFIG: Record<AlertVariant, { color: string; bg: string; border: string; icon: React.ElementType }> = {
  info:    { color: "#00e5ff", bg: "rgba(0,229,255,0.07)",   border: "rgba(0,229,255,0.2)",   icon: Info         },
  success: { color: "#00e676", bg: "rgba(0,230,118,0.07)",   border: "rgba(0,230,118,0.2)",   icon: CheckCircle2 },
  warning: { color: "#ffb300", bg: "rgba(255,179,0,0.07)",   border: "rgba(255,179,0,0.2)",   icon: AlertTriangle },
  error:   { color: "#ff3d5a", bg: "rgba(255,61,90,0.07)",   border: "rgba(255,61,90,0.2)",   icon: AlertCircle  },
};

export function AlertBanner({
  variant = "info", message, dismissible = false,
}: {
  variant?: AlertVariant; message: string; dismissible?: boolean;
}) {
  const [visible, setVisible] = useState(true);
  const cfg = ALERT_CONFIG[variant];
  const Icon = cfg.icon;

  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          exit={{ opacity: 0, height: 0 }}
          className="overflow-hidden"
        >
          <div
            className="flex items-center gap-3 p-3 rounded-xl font-mono text-xs mb-4"
            style={{ background: cfg.bg, border: `1px solid ${cfg.border}`, color: cfg.color }}
          >
            <Icon size={13} style={{ flexShrink: 0 }} />
            <span style={{ color: "#e2e8f8" }}>{message}</span>
            {dismissible && (
              <button
                onClick={() => setVisible(false)}
                className="ml-auto"
                style={{ background: "none", border: "none", cursor: "pointer", color: "#7986a8", padding: 2 }}
              >
                <X size={12} />
              </button>
            )}
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

// ── Glass Card wrapper ─────────────────────────────────────────────────────────
export function GlassCard({
  children, className = "", style = {}, hover = false, onClick,
}: {
  children: ReactNode; className?: string; style?: React.CSSProperties;
  hover?: boolean; onClick?: () => void;
}) {
  return (
    <motion.div
      className={`glass-card ${className}`}
      style={style}
      whileHover={hover ? { y: -2, boxShadow: "0 8px 32px rgba(0,0,0,0.3)" } : undefined}
      onClick={onClick}
    >
      {children}
    </motion.div>
  );
}

// ── Empty state ───────────────────────────────────────────────────────────────
export function EmptyState({
  icon: Icon = Shield, title, description, action,
}: {
  icon?: React.ElementType; title: string; description?: string;
  action?: { label: string; onClick: () => void };
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-4 text-center">
      <div
        className="w-16 h-16 rounded-2xl flex items-center justify-center"
        style={{ background: "rgba(0,229,255,0.04)", border: "1px solid rgba(0,229,255,0.08)" }}
      >
        <Icon size={28} style={{ color: "#3d4d6e" }} />
      </div>
      <div>
        <div className="font-display font-semibold text-base mb-1" style={{ color: "#e2e8f8" }}>{title}</div>
        {description && (
          <div className="font-body text-sm" style={{ color: "#7986a8" }}>{description}</div>
        )}
      </div>
      {action && (
        <button
          onClick={action.onClick}
          className="btn-cyber text-xs px-5 py-2"
        >
          {action.label}
        </button>
      )}
    </div>
  );
}

// ── Loading spinner ────────────────────────────────────────────────────────────
export function Spinner({ size = 20, color = "#00e5ff" }: { size?: number; color?: string }) {
  return (
    <motion.div
      animate={{ rotate: 360 }}
      transition={{ duration: 1.2, repeat: Infinity, ease: "linear" }}
      style={{
        width: size,
        height: size,
        borderRadius: "50%",
        border: `2px solid rgba(255,255,255,0.06)`,
        borderTopColor: color,
        flexShrink: 0,
      }}
    />
  );
}

// ── Full-page loading state ────────────────────────────────────────────────────
export function PageLoader({ message = "Loading..." }: { message?: string }) {
  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center gap-4"
      style={{ background: "var(--bg-void)" }}
    >
      <div className="relative">
        <Spinner size={48} />
        <Shield
          size={18}
          className="absolute inset-0 m-auto"
          style={{ color: "#00e5ff" }}
        />
      </div>
      <div className="font-mono text-xs" style={{ color: "#00e5ff" }}>{message}</div>
    </div>
  );
}

// ── Skeleton line ─────────────────────────────────────────────────────────────
export function SkeletonLine({ width = "100%", height = 12 }: { width?: string | number; height?: number }) {
  return (
    <div
      className="skeleton rounded"
      style={{ width, height, borderRadius: Math.floor(height / 2) }}
    />
  );
}

// ── Confidence score bar ──────────────────────────────────────────────────────
export function ConfidenceBar({
  value, color = "#00e5ff", animated = true,
}: {
  value: number; color?: string; animated?: boolean;
}) {
  const gradient = color === "#ff3d5a"
    ? "linear-gradient(90deg,#ff3d5a,#ff6b7a)"
    : color === "#ffb300"
    ? "linear-gradient(90deg,#ffb300,#ffd54f)"
    : color === "#00e676"
    ? "linear-gradient(90deg,#00e676,#69f0ae)"
    : `linear-gradient(90deg,${color},${color}aa)`;

  return (
    <div className="progress-bar">
      <motion.div
        className="progress-fill"
        initial={animated ? { width: "0%" } : undefined}
        animate={{ width: `${value}%` }}
        transition={animated ? { duration: 0.9, delay: 0.2, ease: [0.22, 1, 0.36, 1] } : undefined}
        style={{ background: gradient }}
      />
    </div>
  );
}

// ── Neon icon button ──────────────────────────────────────────────────────────
export function IconButton({
  icon: Icon, onClick, title, color = "#7986a8", size = 15,
}: {
  icon: React.ElementType; onClick?: () => void; title?: string;
  color?: string; size?: number;
}) {
  return (
    <motion.button
      whileHover={{ scale: 1.1 }}
      whileTap={{ scale: 0.9 }}
      onClick={onClick}
      title={title}
      style={{
        background: "rgba(255,255,255,0.04)",
        border: "1px solid rgba(255,255,255,0.07)",
        borderRadius: 8,
        padding: 6,
        cursor: "pointer",
        color,
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <Icon size={size} />
    </motion.button>
  );
}

// ── Section divider ───────────────────────────────────────────────────────────
export function Divider({ label }: { label?: string }) {
  if (!label) {
    return <div style={{ height: 1, background: "rgba(255,255,255,0.05)", margin: "16px 0" }} />;
  }
  return (
    <div className="flex items-center gap-3 my-4">
      <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.05)" }} />
      <span className="font-mono text-xs uppercase tracking-widest" style={{ color: "#3d4d6e" }}>{label}</span>
      <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.05)" }} />
    </div>
  );
}

// ── Pulsing live indicator ────────────────────────────────────────────────────
export function LiveIndicator({ label = "LIVE", color = "#00e676" }: { label?: string; color?: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <motion.div
        animate={{ opacity: [1, 0.3, 1], scale: [1, 0.8, 1] }}
        transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
        className="w-1.5 h-1.5 rounded-full"
        style={{ background: color, boxShadow: `0 0 6px ${color}` }}
      />
      <span className="font-mono text-xs font-bold" style={{ color, letterSpacing: "0.1em" }}>{label}</span>
    </div>
  );
}

// ── Scan type chip ────────────────────────────────────────────────────────────
export function ScanTypeChip({ type }: { type: "url" | "message" | "file" | string }) {
  const cfg: Record<string, { label: string; color: string }> = {
    url:     { label: "URL",     color: "#00e5ff" },
    message: { label: "SMS",     color: "#00e676" },
    file:    { label: "FILE",    color: "#c471ed" },
  };
  const c = cfg[type] ?? { label: type.toUpperCase(), color: "#7986a8" };
  return (
    <span
      className="font-mono"
      style={{
        color: c.color,
        background: `${c.color}10`,
        border: `1px solid ${c.color}20`,
        fontSize: 9,
        letterSpacing: "0.1em",
        padding: "2px 7px",
        borderRadius: 999,
        fontWeight: 700,
        textTransform: "uppercase",
      }}
    >
      {c.label}
    </span>
  );
}

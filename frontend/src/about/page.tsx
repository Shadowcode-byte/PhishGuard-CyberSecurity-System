"use client";

/*
 * PRODUCTION FIX NOTES
 * ────────────────────────────────────────────────────────────────────────────
 * WHY THE PREVIOUS VERSION DID NOT APPEAR ON VERCEL
 *
 * 1. FRAMER-MOTION SSR CRASH → EMPTY PAGE (root cause)
 *    `useScroll` with a DOM `target` ref and `useTransform` both require a
 *    real browser DOM. Vercel runs `next build` which statically pre-renders
 *    every page in Node.js. In Node.js there is no DOM — the ref is null.
 *    Framer-motion throws during the pre-render pass. Next.js catches the
 *    error, serves an EMPTY HTML shell, and reports a successful build.
 *    This is the "build succeeds but page is blank" pattern.
 *    FIX: All framer-motion hooks are gated behind a `mounted` state that
 *    is only set to true after `useEffect` fires (client-only).
 *
 * 2. "use client" MUST BE LINE 1 — NO EXCEPTIONS
 *    In Next.js 14 App Router, if ANY content (blank line, comment, BOM)
 *    precedes "use client", the directive is silently ignored. The file is
 *    treated as a Server Component and hooks are illegal — the compiler
 *    strips the interactive parts and the page is blank.
 *
 * 3. INLINE @import IN globals.css DROPPED BY POSTCSS
 *    PostCSS processes @tailwind directives and hoists them before @import
 *    statements. This violates the CSS spec rule that @import must come
 *    before all other rules. Browsers silently discard the @import, so
 *    Syne font never loads and all `font-family: 'Syne'` declarations fall
 *    back to system fonts. The page looks broken enough to seem "missing".
 *    FIX: Fonts are declared via <link> in layout.tsx (already correct).
 *    The @import in globals.css is redundant and should be removed.
 *
 * CORRECT FOLDER STRUCTURE
 * ────────────────────────────────────────────────────────────────────────────
 *  src/
 *  └── app/
 *      ├── layout.tsx            ← root layout
 *      ├── globals.css
 *      ├── page.tsx              ← home / landing  →  /
 *      ├── about/
 *      │   └── page.tsx          ← THIS FILE       →  /about  ✓
 *      └── dashboard/
 *          ├── layout.tsx
 *          └── ...
 *
 *  Rules:
 *  • Folder name must be lowercase: `about` not `About`
 *  • File must be named exactly `page.tsx` (not index.tsx, not Page.tsx)
 *  • No route group brackets around it: (about)/page.tsx creates /about but
 *    also silently conflicts if another layout wraps it incorrectly.
 *  • The about folder must NOT contain a layout.tsx that imports Zustand or
 *    localStorage — that would make it a broken Server Component shell.
 */

import { motion } from "framer-motion";
import { useEffect, useState } from "react";
import {
  Shield, Link2, MessageSquare, FileSearch,
  Cpu, Clock, Github, Linkedin, AlertTriangle,
  Lock, Database, Zap, ChevronDown, Users,
} from "lucide-react";

// ─── CONSTANTS ───────────────────────────────────────────────────────────────

const features = [
  {
    icon: Link2,
    title: "URL Scanner",
    desc: "Analyzes suspicious links using heuristic and ML-based engines to detect phishing patterns before you click.",
    accent: "#00f5ff",
    glow: "rgba(0,245,255,0.2)",
  },
  {
    icon: MessageSquare,
    title: "Message Scanner",
    desc: "Detects scam messages, fraud patterns, and social engineering attempts across SMS and text content.",
    accent: "#38bdf8",
    glow: "rgba(56,189,248,0.2)",
  },
  {
    icon: FileSearch,
    title: "File Scanner",
    desc: "Upload suspicious files for deep inspection. Extracts indicators of compromise and potential malware signatures.",
    accent: "#14b8a6",
    glow: "rgba(20,184,166,0.2)",
  },
  {
    icon: Cpu,
    title: "Detection Engine",
    desc: "ML models combined with rule-based logic for accurate, layered threat analysis that improves over time.",
    accent: "#00f5ff",
    glow: "rgba(0,245,255,0.2)",
  },
  {
    icon: Users,
    title: "Role-Based Access",
    desc: "Tailored dashboards for Users, Analysts, and Admins — each with scoped tooling and audit visibility.",
    accent: "#38bdf8",
    glow: "rgba(56,189,248,0.2)",
  },
  {
    icon: Clock,
    title: "Scan History",
    desc: "Full audit trail of every scan. Review, compare, and export results at any time.",
    accent: "#14b8a6",
    glow: "rgba(20,184,166,0.2)",
  },
];

const techStack = [
  { name: "FastAPI",     color: "#00ff88", icon: Zap      },
  { name: "Next.js",     color: "#e8eaf0", icon: Cpu      },
  { name: "TailwindCSS", color: "#00f5ff", icon: Cpu      },
  { name: "PostgreSQL",  color: "#38bdf8", icon: Database },
  { name: "JWT Auth",    color: "#ffd60a", icon: Lock     },
  { name: "ML Models",   color: "#bf5af2", icon: Cpu      },
];

const terms = [
  {
    title: "Educational & Security Use Only",
    desc: "PhishGuard is intended for educational and security analysis purposes only.",
  },
  {
    title: "No Misuse",
    desc: "Users must not leverage PhishGuard to facilitate illegal activity or circumvent security systems.",
  },
  {
    title: "Legal Content",
    desc: "All uploaded content must comply with applicable legal standards. You are solely responsible for submitted material.",
  },
  {
    title: "Activity Logging",
    desc: "Platform activity may be logged for security, audit, and quality assurance purposes.",
  },
];

// ─── ANIMATION VARIANTS ───────────────────────────────────────────────────────

const fadeUp = {
  hidden:  { opacity: 0, y: 32 },
  visible: { opacity: 1, y: 0,  transition: { duration: 0.65, ease: [0.22, 1, 0.36, 1] } },
};

const stagger = {
  hidden:  {},
  visible: { transition: { staggerChildren: 0.1 } },
};

// ─── SUB-COMPONENTS ───────────────────────────────────────────────────────────

function CyberGrid() {
  return (
    <div
      aria-hidden
      className="absolute inset-0 pointer-events-none"
      style={{
        backgroundImage: `
          linear-gradient(rgba(0,245,255,0.03) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0,245,255,0.03) 1px, transparent 1px)
        `,
        backgroundSize: "52px 52px",
      }}
    />
  );
}

function SectionLabel({ text }: { text: string }) {
  return (
    <div className="flex items-center justify-center gap-3 mb-4">
      <div style={{ height: 1, width: 32, background: "#00f5ff" }} />
      <span style={{
        color: "#00f5ff", fontSize: 11,
        fontFamily: "'JetBrains Mono', monospace",
        letterSpacing: "0.3em", textTransform: "uppercase" as const,
      }}>
        {text}
      </span>
      <div style={{ height: 1, width: 32, background: "#00f5ff" }} />
    </div>
  );
}

function FeatureCard({ feature }: { feature: typeof features[0] }) {
  const Icon = feature.icon;
  const [hovered, setHovered] = useState(false);
  return (
    <motion.div
      variants={fadeUp}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: "#0c1120",
        border: `1px solid ${hovered ? feature.accent + "60" : "#1a2540"}`,
        borderRadius: 12, padding: 24, cursor: "default",
        transition: "border-color 0.25s, box-shadow 0.25s, transform 0.25s",
        transform: hovered ? "translateY(-6px)" : "translateY(0)",
        boxShadow: hovered ? `0 0 28px ${feature.glow}` : "none",
        position: "relative" as const, overflow: "hidden",
      }}
    >
      {/* Corner accents */}
      <div aria-hidden style={{ position: "absolute", top: 0, right: 0, width: 1, height: 48, background: `linear-gradient(to bottom, ${feature.accent}70, transparent)` }} />
      <div aria-hidden style={{ position: "absolute", top: 0, right: 0, height: 1, width: 48, background: `linear-gradient(to left, ${feature.accent}70, transparent)` }} />

      <div style={{
        width: 40, height: 40, borderRadius: 8, marginBottom: 16,
        display: "flex", alignItems: "center", justifyContent: "center",
        background: feature.accent + "18", border: `1px solid ${feature.accent}40`,
      }}>
        <Icon size={18} style={{ color: feature.accent }} />
      </div>
      <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 600, fontSize: 15, color: "#e8eaf0", marginBottom: 8 }}>
        {feature.title}
      </div>
      <div style={{ fontSize: 13, color: "#8892b0", lineHeight: 1.65 }}>
        {feature.desc}
      </div>
    </motion.div>
  );
}

// ─── MAIN PAGE ────────────────────────────────────────────────────────────────

export default function AboutPage() {
  /*
   * MOUNTED GUARD — the single most important fix.
   *
   * All framer-motion scroll hooks and any DOM-dependent code must only run
   * after the component has mounted on the client. During Vercel's static
   * pre-render (Node.js, no DOM), `mounted` is false and we return a minimal
   * HTML shell. This gives Next.js valid HTML to serve while preventing the
   * framer-motion crash that caused the blank page.
   *
   * The shell has a non-zero height so the page is not reported as empty by
   * Vercel's crawler, which would cause it to be de-indexed.
   */
  const [mounted, setMounted] = useState(false);
  useEffect(() => { setMounted(true); }, []);

  if (!mounted) {
    return <div style={{ minHeight: "100vh", background: "#050810" }} />;
  }

  return (
    <main style={{ minHeight: "100vh", background: "#050810", color: "#e8eaf0", overflowX: "hidden" }}>

      {/* ── 1. HERO ──────────────────────────────────────────────────────── */}
      <section style={{ position: "relative", minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: "80px 24px" }}>
        <CyberGrid />
        {/* Glow orb */}
        <div aria-hidden style={{
          position: "absolute", top: "38%", left: "50%",
          transform: "translate(-50%, -50%)",
          width: 560, height: 340, borderRadius: "50%",
          background: "radial-gradient(ellipse, rgba(0,245,255,0.07) 0%, transparent 70%)",
          filter: "blur(40px)", pointerEvents: "none",
        }} />

        <motion.div
          initial="hidden" animate="visible" variants={stagger}
          style={{ position: "relative", zIndex: 10, textAlign: "center", maxWidth: 720, margin: "0 auto" }}
        >
          <motion.div variants={fadeUp} style={{ display: "inline-flex", marginBottom: 32 }}>
            <div style={{
              width: 72, height: 72, borderRadius: 16,
              background: "rgba(0,245,255,0.08)", border: "1px solid rgba(0,245,255,0.3)",
              display: "flex", alignItems: "center", justifyContent: "center",
              boxShadow: "0 0 32px rgba(0,245,255,0.15)",
            }}>
              <Shield size={32} style={{ color: "#00f5ff" }} />
            </div>
          </motion.div>

          <motion.div variants={fadeUp}><SectionLabel text="Cybersecurity Platform" /></motion.div>

          <motion.h1
            variants={fadeUp}
            style={{
              fontFamily: "'Syne', 'Space Grotesk', sans-serif",
              fontSize: "clamp(2.4rem, 6vw, 4.5rem)",
              fontWeight: 900, lineHeight: 1.08, letterSpacing: "-0.02em",
              marginBottom: 24, color: "#e8eaf0",
            }}
          >
            About{" "}
            <span style={{
              background: "linear-gradient(135deg, #00f5ff 0%, #0ea5e9 60%)",
              WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
              filter: "drop-shadow(0 0 16px rgba(0,245,255,0.35))",
            }}>
              PhishGuard
            </span>
          </motion.h1>

          <motion.p variants={fadeUp} style={{ fontSize: 17, color: "#8892b0", lineHeight: 1.75, maxWidth: 580, margin: "0 auto 40px" }}>
            PhishGuard is an advanced phishing detection platform that analyzes{" "}
            <span style={{ color: "#00f5ff" }}>URLs</span>,{" "}
            <span style={{ color: "#00f5ff" }}>messages</span>, and{" "}
            <span style={{ color: "#00f5ff" }}>files</span>{" "}
            to detect malicious threats using machine learning and rule-based analysis.
          </motion.p>

          <motion.div variants={fadeUp} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4, color: "#1a2540" }}>
            <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.3em", textTransform: "uppercase" }}>Scroll</span>
            <motion.div animate={{ y: [0, 6, 0] }} transition={{ duration: 1.6, repeat: Infinity }}>
              <ChevronDown size={16} />
            </motion.div>
          </motion.div>
        </motion.div>
      </section>

      {/* ── 2. FEATURES ──────────────────────────────────────────────────── */}
      <section style={{ padding: "96px 24px" }}>
        <div style={{ maxWidth: 1100, margin: "0 auto" }}>
          <motion.div
            initial="hidden" whileInView="visible"
            viewport={{ once: true, margin: "-80px" }} variants={stagger}
            style={{ textAlign: "center", marginBottom: 56 }}
          >
            <motion.div variants={fadeUp}><SectionLabel text="Core Capabilities" /></motion.div>
            <motion.h2 variants={fadeUp} style={{ fontFamily: "'Syne', 'Space Grotesk', sans-serif", fontWeight: 900, fontSize: "clamp(1.8rem, 4vw, 3rem)", color: "#e8eaf0", marginBottom: 12 }}>
              Platform Features
            </motion.h2>
            <motion.p variants={fadeUp} style={{ color: "#8892b0", maxWidth: 480, margin: "0 auto" }}>
              Every component engineered to detect, analyze, and neutralize threats across multiple vectors.
            </motion.p>
          </motion.div>

          <motion.div
            initial="hidden" whileInView="visible"
            viewport={{ once: true, margin: "-60px" }} variants={stagger}
            style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: 20 }}
          >
            {features.map((f) => <FeatureCard key={f.title} feature={f} />)}
          </motion.div>
        </div>
      </section>

      {/* ── 3. CREATOR ───────────────────────────────────────────────────── */}
      <section style={{ padding: "80px 24px" }}>
        <div style={{ maxWidth: 760, margin: "0 auto" }}>
          <motion.div
            initial="hidden" whileInView="visible"
            viewport={{ once: true, margin: "-80px" }} variants={stagger}
            style={{ textAlign: "center", marginBottom: 48 }}
          >
            <motion.div variants={fadeUp}><SectionLabel text="The Builder" /></motion.div>
            <motion.h2 variants={fadeUp} style={{ fontFamily: "'Syne', 'Space Grotesk', sans-serif", fontWeight: 900, fontSize: "clamp(1.8rem, 4vw, 3rem)", color: "#e8eaf0" }}>
              About the Creator
            </motion.h2>
          </motion.div>

          <motion.div
            initial="hidden" whileInView="visible"
            viewport={{ once: true, margin: "-60px" }} variants={fadeUp}
            className="gradient-border-wrap"
          >
            <div style={{ background: "#0c1120", borderRadius: 15, padding: 40 }}>
              <div style={{ display: "flex", flexWrap: "wrap", alignItems: "flex-start", gap: 28 }}>
                {/* Avatar */}
                <div style={{
                  width: 80, height: 80, borderRadius: "50%", flexShrink: 0,
                  background: "linear-gradient(135deg, rgba(0,245,255,0.12), rgba(14,165,233,0.06))",
                  border: "2px solid rgba(0,245,255,0.3)",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontFamily: "'Syne', sans-serif", fontWeight: 900, fontSize: 26, color: "#00f5ff",
                  boxShadow: "0 0 24px rgba(0,245,255,0.15)",
                }}>
                  AM
                </div>
                {/* Bio */}
                <div style={{ flex: 1, minWidth: 220 }}>
                  <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10, marginBottom: 4 }}>
                    <h3 style={{ fontFamily: "'Syne', 'Space Grotesk', sans-serif", fontWeight: 900, fontSize: 22, color: "#e8eaf0", margin: 0 }}>
                      Arpit Mehrotra
                    </h3>
                    <span style={{
                      fontSize: 11, fontFamily: "'JetBrains Mono', monospace",
                      color: "#00f5ff", background: "rgba(0,245,255,0.08)",
                      border: "1px solid rgba(0,245,255,0.25)", borderRadius: 4, padding: "2px 8px",
                    }}>
                      B.Tech CSE · UPES · Sem 2
                    </span>
                  </div>
                  <p style={{ fontSize: 12, color: "#00f5ff", fontFamily: "'JetBrains Mono', monospace", marginBottom: 16 }}>
                    Cybersecurity Enthusiast · Ethical Hacking
                  </p>
                  <p style={{ fontSize: 14, color: "#8892b0", lineHeight: 1.75, marginBottom: 10 }}>
                    Arpit is a B.Tech Computer Science student at <span style={{ color: "#e8eaf0" }}>UPES</span>, currently in Semester 2,
                    with a strong passion for cybersecurity and ethical hacking.
                  </p>
                  <p style={{ fontSize: 14, color: "#8892b0", lineHeight: 1.75, marginBottom: 20 }}>
                    He built PhishGuard to explore <span style={{ color: "#e8eaf0" }}>phishing detection</span>,{" "}
                    <span style={{ color: "#e8eaf0" }}>secure authentication</span>, and{" "}
                    <span style={{ color: "#e8eaf0" }}>ML-based threat analysis</span>. His goal is a career in
                    threat intelligence, malware analysis, and security engineering.
                  </p>
                  <div style={{ display: "flex", gap: 10 }}>
                    {[{ Icon: Github, label: "GitHub" }, { Icon: Linkedin, label: "LinkedIn" }].map(({ Icon, label }) => (
                      <button
                        key={label}
                        style={{
                          display: "flex", alignItems: "center", gap: 6,
                          padding: "7px 14px", borderRadius: 8, cursor: "pointer",
                          background: "rgba(0,245,255,0.06)", border: "1px solid rgba(0,245,255,0.2)",
                          color: "#8892b0", fontSize: 13, fontFamily: "'JetBrains Mono', monospace",
                          transition: "all 0.2s",
                        }}
                        onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.color = "#00f5ff"; (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(0,245,255,0.4)"; }}
                        onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.color = "#8892b0"; (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(0,245,255,0.2)"; }}
                      >
                        <Icon size={14} />{label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ── 4. TECH STACK ────────────────────────────────────────────────── */}
      <section style={{ padding: "80px 24px", position: "relative" }}>
        <div aria-hidden style={{ position: "absolute", inset: 0, pointerEvents: "none", background: "radial-gradient(ellipse 60% 50% at 50% 50%, rgba(0,245,255,0.03) 0%, transparent 70%)" }} />
        <div style={{ maxWidth: 800, margin: "0 auto", textAlign: "center", position: "relative", zIndex: 1 }}>
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={stagger}>
            <motion.div variants={fadeUp}><SectionLabel text="Built With" /></motion.div>
            <motion.h2 variants={fadeUp} style={{ fontFamily: "'Syne', 'Space Grotesk', sans-serif", fontWeight: 900, fontSize: "clamp(1.8rem, 4vw, 3rem)", color: "#e8eaf0", marginBottom: 40 }}>
              Technology Stack
            </motion.h2>
            <motion.div variants={stagger} style={{ display: "flex", flexWrap: "wrap", justifyContent: "center", gap: 12 }}>
              {techStack.map((tech, i) => (
                <motion.div key={tech.name} variants={fadeUp} className="badge-float" style={{ animationDelay: `${i * 0.28}s` }} whileHover={{ scale: 1.08, y: -4 }}>
                  <div style={{
                    display: "flex", alignItems: "center", gap: 8,
                    padding: "9px 18px", borderRadius: 9999,
                    background: "#0c1120", border: "1px solid #1a2540",
                    cursor: "default",
                  }}>
                    <div style={{ width: 8, height: 8, borderRadius: "50%", background: tech.color, boxShadow: `0 0 8px ${tech.color}` }} />
                    <span style={{ fontSize: 13, color: "#e8eaf0", fontFamily: "'JetBrains Mono', monospace" }}>{tech.name}</span>
                  </div>
                </motion.div>
              ))}
            </motion.div>
          </motion.div>
        </div>
      </section>

      {/* ── 5. TERMS ─────────────────────────────────────────────────────── */}
      <section style={{ padding: "72px 24px" }}>
        <div style={{ maxWidth: 680, margin: "0 auto" }}>
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-80px" }} variants={stagger}>
            <div style={{ background: "#0c1120", border: "1px solid #1a2540", borderRadius: 16, padding: "32px 36px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 24 }}>
                <div style={{ width: 36, height: 36, borderRadius: 8, flexShrink: 0, background: "rgba(0,245,255,0.08)", border: "1px solid rgba(0,245,255,0.2)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <Lock size={16} style={{ color: "#00f5ff" }} />
                </div>
                <div>
                  <div style={{ fontSize: 10, color: "#00f5ff", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.3em", textTransform: "uppercase" as const }}>Legal</div>
                  <div style={{ fontFamily: "'Syne', 'Space Grotesk', sans-serif", fontWeight: 700, fontSize: 18, color: "#e8eaf0" }}>Terms of Service</div>
                </div>
              </div>
              {terms.map((t, i) => (
                <motion.div key={t.title} variants={fadeUp} style={{ display: "flex", gap: 16, padding: "14px 0", borderBottom: i < terms.length - 1 ? "1px solid #1a2540" : "none" }}>
                  <div style={{ width: 3, borderRadius: 2, flexShrink: 0, alignSelf: "stretch", background: "linear-gradient(to bottom, #00f5ff, #1a2540)" }} />
                  <div>
                    <div style={{ fontSize: 13, color: "#e8eaf0", fontWeight: 500, marginBottom: 4 }}>{t.title}</div>
                    <div style={{ fontSize: 12, color: "#8892b0", lineHeight: 1.65 }}>{t.desc}</div>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        </div>
      </section>

      {/* ── DISCLAIMER ───────────────────────────────────────────────────── */}
      <section style={{ padding: "0 24px 72px" }}>
        <div style={{ maxWidth: 680, margin: "0 auto" }}>
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUp}>
            <div className="disclaimer-card" style={{ padding: "24px 28px" }}>
              <div style={{ display: "flex", gap: 14, alignItems: "flex-start" }}>
                <div style={{ width: 36, height: 36, borderRadius: 8, flexShrink: 0, background: "rgba(255,214,10,0.08)", border: "1px solid rgba(255,214,10,0.25)", display: "flex", alignItems: "center", justifyContent: "center", marginTop: 2 }}>
                  <AlertTriangle size={16} style={{ color: "#ffd60a" }} />
                </div>
                <div>
                  <div style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700, color: "#ffd60a", fontSize: 16, marginBottom: 8 }}>Disclaimer</div>
                  <p style={{ fontSize: 13, color: "#8892b0", lineHeight: 1.75, margin: 0 }}>
                    PhishGuard is a <span style={{ color: "#ffd60a" }}>cybersecurity research and analysis tool</span>.
                    Detection results are informational and should not be considered guaranteed security advice.
                    Always verify suspicious content through multiple sources.
                  </p>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ── FOOTER ───────────────────────────────────────────────────────── */}
      <footer style={{ borderTop: "1px solid #1a2540", padding: "32px 24px", position: "relative" }}>
        <CyberGrid />
        <div style={{ position: "relative", zIndex: 1, maxWidth: 1100, margin: "0 auto", display: "flex", flexWrap: "wrap", alignItems: "center", justifyContent: "space-between", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 30, height: 30, borderRadius: 8, background: "rgba(0,245,255,0.08)", border: "1px solid rgba(0,245,255,0.25)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <Shield size={14} style={{ color: "#00f5ff" }} />
            </div>
            <span style={{ fontFamily: "'Syne', 'Space Grotesk', sans-serif", fontWeight: 700, fontSize: 16, color: "#e8eaf0" }}>
              Phish<span style={{ color: "#00f5ff" }}>Guard</span>
            </span>
          </div>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: 13, color: "#8892b0" }}>
              Created by <span style={{ color: "#00f5ff", fontWeight: 500 }}>Arpit Mehrotra</span>
            </div>
            <div style={{ fontSize: 11, color: "#1a2540", fontFamily: "'JetBrains Mono', monospace", marginTop: 2 }}>
              © 2026 PhishGuard · All rights reserved.
            </div>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            {[Github, Linkedin].map((Icon, i) => (
              <button key={i} style={{ width: 34, height: 34, borderRadius: 8, cursor: "pointer", background: "#0c1120", border: "1px solid #1a2540", display: "flex", alignItems: "center", justifyContent: "center", color: "#8892b0", transition: "all 0.2s" }}
                onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.color = "#00f5ff"; (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(0,245,255,0.3)"; }}
                onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.color = "#8892b0"; (e.currentTarget as HTMLButtonElement).style.borderColor = "#1a2540"; }}
              >
                <Icon size={14} />
              </button>
            ))}
          </div>
        </div>
      </footer>
    </main>
  );
}

"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import Link from "next/link";
import {
  Shield, Code2, Lock, Cpu, Github, Linkedin,
  Globe, ArrowLeft, Terminal, Zap, Database, Eye,
} from "lucide-react";

// ── Animation variants ──────────────────────────────────────────────────────
const fadeUp = {
  hidden:  { opacity: 0, y: 40 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.7, ease: [0.22, 1, 0.36, 1] } },
};
const stagger = {
  hidden:  {},
  visible: { transition: { staggerChildren: 0.13 } },
};
const scaleIn = {
  hidden:  { opacity: 0, scale: 0.85 },
  visible: { opacity: 1, scale: 1, transition: { duration: 0.6, ease: [0.22, 1, 0.36, 1] } },
};

// ── Data ────────────────────────────────────────────────────────────────────
const SKILLS = [
  { label: "Python / FastAPI",  pct: 85, color: "#00f5ff" },
  { label: "ML / scikit-learn", pct: 78, color: "#38bdf8" },
  { label: "Next.js / React",   pct: 80, color: "#14b8a6" },
  { label: "Cybersecurity",     pct: 72, color: "#a78bfa" },
  { label: "SQL / PostgreSQL",  pct: 70, color: "#34d399" },
];

const INTERESTS = [
  { icon: Lock,     label: "Ethical Hacking",       color: "#00f5ff" },
  { icon: Eye,      label: "Phishing Detection",    color: "#38bdf8" },
  { icon: Cpu,      label: "AI + Security Tools",   color: "#a78bfa" },
  { icon: Database, label: "Threat Intelligence",   color: "#34d399" },
  { icon: Terminal, label: "CTF Competitions",      color: "#fbbf24" },
  { icon: Globe,    label: "Open Source",           color: "#f472b6" },
];

const TIMELINE = [
  {
    year: "2025",
    title: "Started BTech CSE @ UPES",
    desc: "Enrolled in Computer Science at UPES Dehradun with a focus on cybersecurity.",
    color: "#00f5ff",
  },
  {
    year: "2025",
    title: "Discovered Phishing Research",
    desc: "Began studying ML-based threat detection and ethical hacking fundamentals.",
    color: "#38bdf8",
  },
  {
    year: "2026",
    title: "Built PhishGuard",
    desc: "Designed and developed a full-stack phishing detection platform combining FastAPI, ML models, and Next.js.",
    color: "#14b8a6",
  },
  {
    year: "Now",
    title: "Sem 2 — Growing Fast",
    desc: "Expanding into malware analysis, threat intelligence, and security engineering.",
    color: "#a78bfa",
  },
];

// ── Animated Skill Bar ────────────────────────────────────────────────────
function SkillBar({ label, pct, color, delay }: { label: string; pct: number; color: string; delay: number }) {
  const [width, setWidth] = useState(0);
  const [inView, setInView] = useState(false);

  useEffect(() => {
    if (inView) {
      const t = setTimeout(() => setWidth(pct), 100 + delay * 80);
      return () => clearTimeout(t);
    }
  }, [inView, pct, delay]);

  return (
    <motion.div
      variants={fadeUp}
      onViewportEnter={() => setInView(true)}
      style={{ marginBottom: 16 }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
        <span style={{ fontSize: 13, color: "#e8eaf0", fontFamily: "'JetBrains Mono', monospace" }}>{label}</span>
        <span style={{ fontSize: 12, color, fontFamily: "'JetBrains Mono', monospace" }}>{pct}%</span>
      </div>
      <div style={{ height: 6, background: "#1a2540", borderRadius: 9999, overflow: "hidden" }}>
        <div
          style={{
            height: "100%",
            width: `${width}%`,
            background: `linear-gradient(90deg, ${color}99, ${color})`,
            borderRadius: 9999,
            boxShadow: `0 0 8px ${color}60`,
            transition: "width 0.9s cubic-bezier(0.22,1,0.36,1)",
          }}
        />
      </div>
    </motion.div>
  );
}

// ── Floating cyber icons in background ───────────────────────────────────
function FloatingIcon({ icon: Icon, x, y, delay, color }: {
  icon: React.ElementType; x: string; y: string; delay: number; color: string;
}) {
  return (
    <motion.div
      aria-hidden
      initial={{ opacity: 0, scale: 0 }}
      animate={{ opacity: 0.12, scale: 1 }}
      transition={{ delay, duration: 1 }}
      style={{ position: "absolute", left: x, top: y, pointerEvents: "none" }}
    >
      <motion.div
        animate={{ y: [0, -12, 0], rotate: [0, 5, -5, 0] }}
        transition={{ duration: 5 + delay, repeat: Infinity, ease: "easeInOut" }}
      >
        <Icon size={40} style={{ color }} />
      </motion.div>
    </motion.div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────
export default function CreatorPage() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => { setMounted(true); }, []);

  if (!mounted) {
    return <div style={{ minHeight: "100vh", background: "#050810" }} />;
  }

  return (
    <main style={{ minHeight: "100vh", background: "#050810", color: "#e8eaf0", overflowX: "hidden" }}>

      {/* ── Background grid ── */}
      <div
        aria-hidden
        style={{
          position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none",
          backgroundImage: `
            linear-gradient(rgba(0,245,255,0.025) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,245,255,0.025) 1px, transparent 1px)
          `,
          backgroundSize: "52px 52px",
        }}
      />

      {/* ── Floating background icons ── */}
      <div style={{ position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none" }}>
        <FloatingIcon icon={Shield}   x="5%"  y="15%" delay={0.2} color="#00f5ff" />
        <FloatingIcon icon={Lock}     x="90%" y="20%" delay={0.5} color="#38bdf8" />
        <FloatingIcon icon={Code2}    x="8%"  y="70%" delay={0.8} color="#a78bfa" />
        <FloatingIcon icon={Cpu}      x="85%" y="65%" delay={0.3} color="#14b8a6" />
        <FloatingIcon icon={Terminal} x="50%" y="5%"  delay={1.0} color="#fbbf24" />
        <FloatingIcon icon={Database} x="75%" y="90%" delay={0.6} color="#34d399" />
        <FloatingIcon icon={Zap}      x="20%" y="90%" delay={0.9} color="#f472b6" />
      </div>

      {/* ── Ambient glow ── */}
      <div aria-hidden style={{
        position: "fixed", top: "30%", left: "50%", transform: "translate(-50%,-50%)",
        width: 700, height: 400, borderRadius: "50%", zIndex: 0, pointerEvents: "none",
        background: "radial-gradient(ellipse, rgba(0,245,255,0.05) 0%, transparent 70%)",
        filter: "blur(60px)",
      }} />
      <div aria-hidden style={{
        position: "fixed", bottom: "10%", right: "5%",
        width: 400, height: 300, borderRadius: "50%", zIndex: 0, pointerEvents: "none",
        background: "radial-gradient(ellipse, rgba(167,139,250,0.06) 0%, transparent 70%)",
        filter: "blur(60px)",
      }} />

      <div style={{ position: "relative", zIndex: 1 }}>

        {/* ── Navbar ── */}
        <nav style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "20px 32px", borderBottom: "1px solid #1a2540",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{
              width: 32, height: 32, borderRadius: 8, border: "1px solid rgba(0,245,255,0.3)",
              background: "rgba(0,245,255,0.08)", display: "flex", alignItems: "center", justifyContent: "center",
            }}>
              <Shield size={16} style={{ color: "#00f5ff" }} />
            </div>
            <span style={{ fontFamily: "'Space Grotesk',sans-serif", fontWeight: 700, fontSize: 17, color: "#e8eaf0" }}>
              Phish<span style={{ color: "#00f5ff" }}>Guard</span>
            </span>
          </div>
          <Link
            href="/"
            style={{
              display: "flex", alignItems: "center", gap: 7,
              padding: "8px 16px", borderRadius: 8, textDecoration: "none",
              background: "rgba(0,245,255,0.06)", border: "1px solid rgba(0,245,255,0.2)",
              color: "#8892b0", fontSize: 13, fontFamily: "'JetBrains Mono',monospace",
              transition: "all 0.2s",
            }}
          >
            <ArrowLeft size={14} />
            Back to Home
          </Link>
        </nav>

        {/* ── HERO ── */}
        <section style={{ padding: "80px 24px 60px", textAlign: "center" }}>
          <motion.div
            initial="hidden" animate="visible" variants={stagger}
            style={{ maxWidth: 720, margin: "0 auto" }}
          >
            {/* Label */}
            <motion.div variants={fadeUp} style={{ display: "flex", justifyContent: "center", marginBottom: 24 }}>
              <div style={{
                display: "flex", alignItems: "center", gap: 8,
                padding: "5px 16px", borderRadius: 9999,
                background: "rgba(0,245,255,0.06)", border: "1px solid rgba(0,245,255,0.2)",
              }}>
                <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#00f5ff", boxShadow: "0 0 8px #00f5ff" }} />
                <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono',monospace", letterSpacing: "0.3em", color: "#00f5ff", textTransform: "uppercase" as const }}>
                  The Creator
                </span>
              </div>
            </motion.div>

            {/* Avatar */}
            <motion.div variants={scaleIn} style={{ display: "flex", justifyContent: "center", marginBottom: 32 }}>
              <div style={{ position: "relative" }}>
                {/* Rotating gradient ring */}
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 8, repeat: Infinity, ease: "linear" }}
                  style={{
                    position: "absolute", inset: -4, borderRadius: "50%",
                    background: "conic-gradient(from 0deg, #00f5ff, #a78bfa, #14b8a6, #00f5ff)",
                    zIndex: 0,
                  }}
                />
                <div style={{
                  position: "relative", zIndex: 1,
                  width: 120, height: 120, borderRadius: "50%",
                  background: "linear-gradient(135deg, #0c1120, #050810)",
                  border: "3px solid #050810",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontFamily: "'Space Grotesk',sans-serif", fontWeight: 900,
                  fontSize: 36, color: "#00f5ff",
                  boxShadow: "0 0 40px rgba(0,245,255,0.2)",
                }}>
                  AM
                </div>
              </div>
            </motion.div>

            {/* Name */}
            <motion.h1 variants={fadeUp} style={{
              fontFamily: "'Space Grotesk',sans-serif", fontWeight: 900,
              fontSize: "clamp(2.4rem, 6vw, 4rem)", lineHeight: 1.1,
              letterSpacing: "-0.02em", marginBottom: 16,
            }}>
              <span style={{
                background: "linear-gradient(135deg, #e8eaf0 0%, #00f5ff 60%, #a78bfa 100%)",
                WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
                filter: "drop-shadow(0 0 20px rgba(0,245,255,0.3))",
              }}>
                Arpit Mehrotra
              </span>
            </motion.h1>

            {/* Tags */}
            <motion.div variants={fadeUp} style={{ display: "flex", flexWrap: "wrap", justifyContent: "center", gap: 8, marginBottom: 28 }}>
              {[
                { text: "BTech CSE · UPES", color: "#00f5ff" },
                { text: "Semester 2",        color: "#38bdf8" },
                { text: "Cybersecurity",     color: "#a78bfa" },
                { text: "Ethical Hacking",   color: "#34d399" },
              ].map(({ text, color }) => (
                <span key={text} style={{
                  padding: "4px 14px", borderRadius: 9999, fontSize: 12,
                  fontFamily: "'JetBrains Mono',monospace", letterSpacing: "0.05em",
                  color, background: `${color}12`, border: `1px solid ${color}35`,
                }}>
                  {text}
                </span>
              ))}
            </motion.div>

            {/* Bio */}
            <motion.p variants={fadeUp} style={{
              fontSize: 16, color: "#8892b0", lineHeight: 1.8, maxWidth: 580, margin: "0 auto 36px",
            }}>
              A passionate cybersecurity student building tools that matter. Currently studying
              Computer Science at{" "}
              <span style={{ color: "#e8eaf0", fontWeight: 500 }}>UPES Dehradun</span>, I
              created PhishGuard to explore the intersection of{" "}
              <span style={{ color: "#00f5ff" }}>machine learning</span> and{" "}
              <span style={{ color: "#a78bfa" }}>threat detection</span> — turning academic
              curiosity into real security tools.
            </motion.p>

            {/* Social buttons */}
            <motion.div variants={fadeUp} style={{ display: "flex", justifyContent: "center", gap: 12 }}>
              {[
                { icon: Github,   label: "GitHub",   href: "#" },
                { icon: Linkedin, label: "LinkedIn", href: "#" },
              ].map(({ icon: Icon, label, href }) => (
                <motion.a
                  key={label}
                  href={href}
                  whileHover={{ scale: 1.08, y: -2 }}
                  whileTap={{ scale: 0.96 }}
                  style={{
                    display: "flex", alignItems: "center", gap: 8,
                    padding: "10px 22px", borderRadius: 10, textDecoration: "none",
                    background: "rgba(0,245,255,0.06)", border: "1px solid rgba(0,245,255,0.2)",
                    color: "#8892b0", fontSize: 14, fontFamily: "'JetBrains Mono',monospace",
                    transition: "color 0.2s, border-color 0.2s",
                  }}
                  onMouseEnter={e => {
                    (e.currentTarget as HTMLAnchorElement).style.color = "#00f5ff";
                    (e.currentTarget as HTMLAnchorElement).style.borderColor = "rgba(0,245,255,0.5)";
                  }}
                  onMouseLeave={e => {
                    (e.currentTarget as HTMLAnchorElement).style.color = "#8892b0";
                    (e.currentTarget as HTMLAnchorElement).style.borderColor = "rgba(0,245,255,0.2)";
                  }}
                >
                  <Icon size={15} />{label}
                </motion.a>
              ))}
            </motion.div>
          </motion.div>
        </section>

        {/* ── ABOUT PHISHGUARD ── */}
        <section style={{ padding: "60px 24px", maxWidth: 900, margin: "0 auto" }}>
          <motion.div
            initial="hidden" whileInView="visible"
            viewport={{ once: true, margin: "-60px" }} variants={stagger}
          >
            <motion.div variants={fadeUp} style={{ textAlign: "center", marginBottom: 48 }}>
              <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: 12, marginBottom: 14 }}>
                <div style={{ height: 1, width: 32, background: "#00f5ff" }} />
                <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono',monospace", letterSpacing: "0.3em", color: "#00f5ff", textTransform: "uppercase" as const }}>Why PhishGuard?</span>
                <div style={{ height: 1, width: 32, background: "#00f5ff" }} />
              </div>
              <h2 style={{ fontFamily: "'Space Grotesk',sans-serif", fontWeight: 800, fontSize: "clamp(1.8rem,4vw,2.8rem)", color: "#e8eaf0", marginBottom: 12 }}>
                Built to Learn. Built to Protect.
              </h2>
              <p style={{ fontSize: 15, color: "#8892b0", lineHeight: 1.8, maxWidth: 580, margin: "0 auto" }}>
                PhishGuard started as a semester project and became something much bigger — a
                real-world exploration of how AI can make the internet safer, one scan at a time.
              </p>
            </motion.div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: 20 }}>
              {[
                {
                  icon: Cpu, color: "#00f5ff",
                  title: "ML-Powered Detection",
                  desc: "A RandomForest model trained on 68,000+ real phishing URLs extracts 23 structural and lexical features to classify threats with high accuracy.",
                },
                {
                  icon: Lock, color: "#a78bfa",
                  title: "Security by Design",
                  desc: "JWT auth, RBAC, bcrypt hashing, AES-256 file encryption, and per-IP rate limiting — every layer hardened from the ground up.",
                },
                {
                  icon: Code2, color: "#14b8a6",
                  title: "Full-Stack Build",
                  desc: "FastAPI backend with async routes, PostgreSQL, and a Next.js 14 App Router frontend with real-time detection dashboards.",
                },
                {
                  icon: Zap, color: "#fbbf24",
                  title: "Hybrid AI Engine",
                  desc: "ML probability combined with a rule-based scoring overlay for phishing URLs. NLP + OpenAI hybrid for SMS/message analysis.",
                },
              ].map((card) => (
                <motion.div
                  key={card.title}
                  variants={fadeUp}
                  whileHover={{ y: -6, boxShadow: `0 0 32px ${card.color}20` }}
                  style={{
                    background: "#0c1120", border: "1px solid #1a2540",
                    borderRadius: 14, padding: 24, transition: "border-color 0.25s",
                    cursor: "default",
                  }}
                  onMouseEnter={e => (e.currentTarget as HTMLDivElement).style.borderColor = `${card.color}50`}
                  onMouseLeave={e => (e.currentTarget as HTMLDivElement).style.borderColor = "#1a2540"}
                >
                  <div style={{
                    width: 44, height: 44, borderRadius: 10, marginBottom: 16,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    background: `${card.color}12`, border: `1px solid ${card.color}35`,
                  }}>
                    <card.icon size={20} style={{ color: card.color }} />
                  </div>
                  <h3 style={{ fontFamily: "'Space Grotesk',sans-serif", fontWeight: 700, fontSize: 15, color: "#e8eaf0", marginBottom: 8 }}>{card.title}</h3>
                  <p style={{ fontSize: 13, color: "#8892b0", lineHeight: 1.7 }}>{card.desc}</p>
                </motion.div>
              ))}
            </div>
          </motion.div>
        </section>

        {/* ── SKILLS ── */}
        <section style={{ padding: "60px 24px", maxWidth: 700, margin: "0 auto" }}>
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-60px" }} variants={stagger}>
            <motion.div variants={fadeUp} style={{ textAlign: "center", marginBottom: 40 }}>
              <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: 12, marginBottom: 14 }}>
                <div style={{ height: 1, width: 32, background: "#38bdf8" }} />
                <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono',monospace", letterSpacing: "0.3em", color: "#38bdf8", textTransform: "uppercase" as const }}>Tech Stack</span>
                <div style={{ height: 1, width: 32, background: "#38bdf8" }} />
              </div>
              <h2 style={{ fontFamily: "'Space Grotesk',sans-serif", fontWeight: 800, fontSize: "clamp(1.6rem,4vw,2.4rem)", color: "#e8eaf0" }}>
                Skills & Tools
              </h2>
            </motion.div>
            <div style={{ background: "#0c1120", border: "1px solid #1a2540", borderRadius: 16, padding: 32 }}>
              {SKILLS.map((s, i) => (
                <SkillBar key={s.label} {...s} delay={i} />
              ))}
            </div>
          </motion.div>
        </section>

        {/* ── INTERESTS ── */}
        <section style={{ padding: "60px 24px", maxWidth: 900, margin: "0 auto" }}>
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-60px" }} variants={stagger}>
            <motion.div variants={fadeUp} style={{ textAlign: "center", marginBottom: 40 }}>
              <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: 12, marginBottom: 14 }}>
                <div style={{ height: 1, width: 32, background: "#a78bfa" }} />
                <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono',monospace", letterSpacing: "0.3em", color: "#a78bfa", textTransform: "uppercase" as const }}>Passions</span>
                <div style={{ height: 1, width: 32, background: "#a78bfa" }} />
              </div>
              <h2 style={{ fontFamily: "'Space Grotesk',sans-serif", fontWeight: 800, fontSize: "clamp(1.6rem,4vw,2.4rem)", color: "#e8eaf0" }}>
                Interests
              </h2>
            </motion.div>
            <motion.div
              variants={stagger}
              style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(140px, 1fr))", gap: 14 }}
            >
              {INTERESTS.map((item) => (
                <motion.div
                  key={item.label}
                  variants={fadeUp}
                  whileHover={{ scale: 1.06, y: -4 }}
                  style={{
                    background: "#0c1120", border: "1px solid #1a2540",
                    borderRadius: 12, padding: "20px 16px", textAlign: "center",
                    cursor: "default", transition: "border-color 0.25s",
                  }}
                  onMouseEnter={e => (e.currentTarget as HTMLDivElement).style.borderColor = `${item.color}50`}
                  onMouseLeave={e => (e.currentTarget as HTMLDivElement).style.borderColor = "#1a2540"}
                >
                  <div style={{
                    width: 40, height: 40, borderRadius: 10, margin: "0 auto 10px",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    background: `${item.color}12`, border: `1px solid ${item.color}30`,
                  }}>
                    <item.icon size={18} style={{ color: item.color }} />
                  </div>
                  <div style={{ fontSize: 12, color: "#e8eaf0", fontFamily: "'JetBrains Mono',monospace" }}>{item.label}</div>
                </motion.div>
              ))}
            </motion.div>
          </motion.div>
        </section>

        {/* ── TIMELINE ── */}
        <section style={{ padding: "60px 24px", maxWidth: 700, margin: "0 auto" }}>
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-60px" }} variants={stagger}>
            <motion.div variants={fadeUp} style={{ textAlign: "center", marginBottom: 48 }}>
              <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: 12, marginBottom: 14 }}>
                <div style={{ height: 1, width: 32, background: "#34d399" }} />
                <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono',monospace", letterSpacing: "0.3em", color: "#34d399", textTransform: "uppercase" as const }}>Journey</span>
                <div style={{ height: 1, width: 32, background: "#34d399" }} />
              </div>
              <h2 style={{ fontFamily: "'Space Grotesk',sans-serif", fontWeight: 800, fontSize: "clamp(1.6rem,4vw,2.4rem)", color: "#e8eaf0" }}>My Story</h2>
            </motion.div>

            <div style={{ position: "relative" }}>
              {/* Vertical line */}
              <div style={{
                position: "absolute", left: 20, top: 0, bottom: 0,
                width: 2, background: "linear-gradient(to bottom, #00f5ff, #1a2540)",
                borderRadius: 1,
              }} />

              {TIMELINE.map((item, i) => (
                <motion.div
                  key={i}
                  variants={fadeUp}
                  style={{ display: "flex", gap: 24, marginBottom: 36, paddingLeft: 8 }}
                >
                  {/* Dot */}
                  <div style={{ flexShrink: 0, position: "relative", zIndex: 1 }}>
                    <div style={{
                      width: 24, height: 24, borderRadius: "50%",
                      background: "#050810", border: `2px solid ${item.color}`,
                      display: "flex", alignItems: "center", justifyContent: "center",
                      boxShadow: `0 0 12px ${item.color}50`,
                      marginTop: 2,
                    }}>
                      <div style={{ width: 8, height: 8, borderRadius: "50%", background: item.color }} />
                    </div>
                  </div>
                  {/* Content */}
                  <div style={{ flex: 1, background: "#0c1120", border: "1px solid #1a2540", borderRadius: 12, padding: "18px 20px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                      <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono',monospace", color: item.color, background: `${item.color}12`, border: `1px solid ${item.color}30`, padding: "2px 8px", borderRadius: 4 }}>
                        {item.year}
                      </span>
                      <h3 style={{ fontFamily: "'Space Grotesk',sans-serif", fontWeight: 700, fontSize: 15, color: "#e8eaf0", margin: 0 }}>
                        {item.title}
                      </h3>
                    </div>
                    <p style={{ fontSize: 13, color: "#8892b0", lineHeight: 1.7, margin: 0 }}>{item.desc}</p>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        </section>

        {/* ── CTA ── */}
        <section style={{ padding: "60px 24px 80px", textAlign: "center" }}>
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUp}>
            <div style={{
              maxWidth: 560, margin: "0 auto",
              background: "#0c1120", border: "1px solid #1a2540",
              borderRadius: 20, padding: 48,
              boxShadow: "0 0 60px rgba(0,245,255,0.07)",
            }}>
              <Shield size={40} style={{ color: "#00f5ff", marginBottom: 20 }} />
              <h2 style={{ fontFamily: "'Space Grotesk',sans-serif", fontWeight: 800, fontSize: "clamp(1.4rem,3vw,2rem)", color: "#e8eaf0", marginBottom: 14 }}>
                Try PhishGuard
              </h2>
              <p style={{ fontSize: 14, color: "#8892b0", lineHeight: 1.75, marginBottom: 28 }}>
                Scan URLs, messages, and files for phishing threats — free, fast, and powered by ML.
              </p>
              <Link href="/auth/register">
                <motion.button
                  whileHover={{ scale: 1.05, boxShadow: "0 0 32px rgba(0,245,255,0.4)" }}
                  whileTap={{ scale: 0.97 }}
                  style={{
                    padding: "12px 32px", borderRadius: 10, cursor: "pointer",
                    background: "linear-gradient(135deg, #00f5ff20, #00f5ff10)",
                    border: "1px solid rgba(0,245,255,0.4)",
                    color: "#00f5ff", fontSize: 14,
                    fontFamily: "'JetBrains Mono',monospace", letterSpacing: "0.05em",
                    fontWeight: 600,
                  }}
                >
                  Get Started Free →
                </motion.button>
              </Link>
            </div>
          </motion.div>
        </section>

        {/* ── Footer ── */}
        <footer style={{ borderTop: "1px solid #1a2540", padding: "24px 32px", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <span style={{ fontSize: 12, fontFamily: "'JetBrains Mono',monospace", color: "#8892b0" }}>
            Made with ❤️ by{" "}
            <span style={{ color: "#00f5ff" }}>Arpit Mehrotra</span>
            {" "}· © 2025 PhishGuard
          </span>
        </footer>

      </div>
    </main>
  );
}

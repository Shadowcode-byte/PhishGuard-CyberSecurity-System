"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Link2, MessageSquare, FileSearch, Shield } from "lucide-react";

// ─── ANIMATION VARIANTS ───────────────────────────────────────────────────────

const fadeUp = {
  hidden:  { opacity: 0, y: 28 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.6, ease: [0.22, 1, 0.36, 1] },
  },
};

const stagger = {
  hidden:  {},
  visible: { transition: { staggerChildren: 0.12 } },
};

// ─── FEATURE DATA ─────────────────────────────────────────────────────────────

const FEATURES = [
  {
    icon:    Link2,
    title:   "URL Detection",
    tagline: "Scan suspicious links",
    desc:    "AI-powered analysis using ML models trained on millions of URLs. Detects phishing patterns, typosquatting, and malicious redirects with 95%+ accuracy.",
    accent:  "#00f5ff",
    glow:    "rgba(0,245,255,0.18)",
    border:  "rgba(0,245,255,0.35)",
    tag:     "ML-POWERED",
  },
  {
    icon:    FileSearch,
    title:   "File Scanner",
    tagline: "Upload files",
    desc:    "Upload emails, documents, and logs for deep inspection. Malware and phishing signature extraction with AES-256 encrypted storage.",
    accent:  "#14b8a6",
    glow:    "rgba(20,184,166,0.18)",
    border:  "rgba(20,184,166,0.35)",
    tag:     "DEEP SCAN",
  },
  {
    icon:    MessageSquare,
    title:   "Message Analyzer",
    tagline: "Detect phishing emails/messages",
    desc:    "Hybrid rule-based and AI classification catches OTP theft, prize scams, social engineering attempts, and bank fraud patterns in SMS and text content.",
    accent:  "#38bdf8",
    glow:    "rgba(56,189,248,0.18)",
    border:  "rgba(56,189,248,0.35)",
    tag:     "NLP ENGINE",
  },
] as const;

// ─── FEATURE CARD ─────────────────────────────────────────────────────────────

function FeatureCard({
  feature,
}: {
  feature: (typeof FEATURES)[number];
}) {
  const Icon = feature.icon;
  const [hovered, setHovered] = useState(false);

  return (
    <motion.div
      variants={fadeUp}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        position:        "relative",
        background:      "#0c1120",
        border:          `1px solid ${hovered ? feature.border : "#1a2540"}`,
        borderRadius:    14,
        padding:         28,
        cursor:          "default",
        overflow:        "hidden",
        transition:      "border-color 0.25s, box-shadow 0.25s, transform 0.25s",
        transform:       hovered ? "translateY(-6px)" : "translateY(0)",
        boxShadow:       hovered ? `0 0 32px ${feature.glow}` : "0 4px 24px rgba(0,0,0,0.4)",
      }}
    >
      {/* Top-right corner accent lines */}
      <div
        aria-hidden
        style={{
          position:   "absolute", top: 0, right: 0,
          width: 1, height: 56,
          background: `linear-gradient(to bottom, ${feature.accent}80, transparent)`,
        }}
      />
      <div
        aria-hidden
        style={{
          position:   "absolute", top: 0, right: 0,
          height: 1, width: 56,
          background: `linear-gradient(to left, ${feature.accent}80, transparent)`,
        }}
      />

      {/* Tag badge */}
      <div
        style={{
          display:        "inline-flex",
          alignItems:     "center",
          marginBottom:   20,
          padding:        "3px 9px",
          borderRadius:   4,
          background:     `${feature.accent}12`,
          border:         `1px solid ${feature.accent}30`,
          fontSize:       10,
          fontFamily:     "'JetBrains Mono', monospace",
          letterSpacing:  "0.25em",
          color:          feature.accent,
        }}
      >
        {feature.tag}
      </div>

      {/* Icon */}
      <div
        style={{
          width:          44,
          height:         44,
          borderRadius:   10,
          marginBottom:   18,
          display:        "flex",
          alignItems:     "center",
          justifyContent: "center",
          background:     feature.glow,
          border:         `1px solid ${feature.border}`,
          boxShadow:      hovered ? `0 0 20px ${feature.glow}` : "none",
          transition:     "box-shadow 0.25s",
        }}
      >
        <Icon size={20} style={{ color: feature.accent }} />
      </div>

      {/* Text */}
      <h3
        style={{
          fontFamily:   "'Space Grotesk', sans-serif",
          fontWeight:   700,
          fontSize:     17,
          color:        "#e8eaf0",
          marginBottom: 6,
        }}
      >
        {feature.title}
      </h3>
      <p
        style={{
          fontSize:    12,
          fontFamily:  "'JetBrains Mono', monospace",
          color:       feature.accent,
          marginBottom: 14,
          letterSpacing: "0.04em",
        }}
      >
        {feature.tagline}
      </p>
      <p
        style={{
          fontSize:   13,
          color:      "#8892b0",
          lineHeight: 1.7,
        }}
      >
        {feature.desc}
      </p>

      {/* Bottom scan line on hover */}
      {hovered && (
        <div
          aria-hidden
          style={{
            position:   "absolute",
            bottom:     0, left: 0, right: 0,
            height:     2,
            background: `linear-gradient(90deg, transparent, ${feature.accent}60, transparent)`,
          }}
        />
      )}
    </motion.div>
  );
}

// ─── MAIN COMPONENT ───────────────────────────────────────────────────────────

export default function AboutSection() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => { setMounted(true); }, []);

  if (!mounted) {
    return (
      <section
        style={{ minHeight: 480, background: "#050810" }}
        aria-label="About PhishGuard"
      />
    );
  }

  return (
    <section
      style={{
        position:   "relative",
        padding:    "100px 24px",
        background: "#050810",
        overflow:   "hidden",
      }}
      aria-label="About PhishGuard"
    >
      {/* Subtle grid background */}
      <div
        aria-hidden
        style={{
          position:        "absolute",
          inset:           0,
          pointerEvents:   "none",
          backgroundImage: `
            linear-gradient(rgba(0,245,255,0.025) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,245,255,0.025) 1px, transparent 1px)
          `,
          backgroundSize:  "52px 52px",
        }}
      />

      {/* Ambient glow orbs */}
      <div
        aria-hidden
        style={{
          position:       "absolute",
          top:            "20%", left: "-5%",
          width:          480, height: 320,
          borderRadius:   "50%",
          background:     "radial-gradient(ellipse, rgba(0,245,255,0.055) 0%, transparent 70%)",
          filter:         "blur(60px)",
          pointerEvents:  "none",
        }}
      />
      <div
        aria-hidden
        style={{
          position:       "absolute",
          bottom:         "10%", right: "-5%",
          width:          420, height: 280,
          borderRadius:   "50%",
          background:     "radial-gradient(ellipse, rgba(20,184,166,0.05) 0%, transparent 70%)",
          filter:         "blur(60px)",
          pointerEvents:  "none",
        }}
      />

      {/* Content */}
      <div
        style={{
          position:  "relative",
          zIndex:    1,
          maxWidth:  1100,
          margin:    "0 auto",
        }}
      >
        {/* Header */}
        <motion.div
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: "-80px" }}
          variants={stagger}
          style={{ textAlign: "center", marginBottom: 64 }}
        >
          {/* Section label */}
          <motion.div
            variants={fadeUp}
            style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, marginBottom: 20 }}
          >
            <div style={{ height: 1, width: 36, background: "linear-gradient(to right, transparent, #00f5ff)" }} />
            <div
              style={{
                display:        "flex",
                alignItems:     "center",
                gap:            7,
                padding:        "4px 14px",
                borderRadius:   9999,
                background:     "rgba(0,245,255,0.06)",
                border:         "1px solid rgba(0,245,255,0.2)",
              }}
            >
              <Shield size={11} style={{ color: "#00f5ff" }} />
              <span
                style={{
                  fontSize:      10,
                  fontFamily:    "'JetBrains Mono', monospace",
                  letterSpacing: "0.3em",
                  color:         "#00f5ff",
                  textTransform: "uppercase" as const,
                }}
              >
                Cybersecurity Platform
              </span>
            </div>
            <div style={{ height: 1, width: 36, background: "linear-gradient(to left, transparent, #00f5ff)" }} />
          </motion.div>

          {/* Title */}
          <motion.h2
            variants={fadeUp}
            style={{
              fontFamily:    "'Space Grotesk', sans-serif",
              fontWeight:    800,
              fontSize:      "clamp(2rem, 4.5vw, 3.2rem)",
              lineHeight:    1.1,
              letterSpacing: "-0.02em",
              color:         "#e8eaf0",
              marginBottom:  20,
            }}
          >
            About{" "}
            <span
              style={{
                background:             "linear-gradient(135deg, #00f5ff 0%, #0ea5e9 60%)",
                WebkitBackgroundClip:   "text",
                WebkitTextFillColor:    "transparent",
                filter:                 "drop-shadow(0 0 18px rgba(0,245,255,0.4))",
              }}
            >
              PhishGuard
            </span>
          </motion.h2>

          {/* Description */}
          <motion.p
            variants={fadeUp}
            style={{
              fontSize:   16,
              color:      "#8892b0",
              lineHeight: 1.8,
              maxWidth:   560,
              margin:     "0 auto",
            }}
          >
            An advanced phishing detection platform that analyzes{" "}
            <span style={{ color: "#00f5ff" }}>URLs</span>,{" "}
            <span style={{ color: "#14b8a6" }}>files</span>, and{" "}
            <span style={{ color: "#38bdf8" }}>messages</span> to detect
            malicious threats using machine learning and rule-based analysis —
            delivering security insights you can act on instantly.
          </motion.p>
        </motion.div>

        {/* Feature cards grid */}
        <motion.div
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: "-60px" }}
          variants={stagger}
          style={{
            display:               "grid",
            gridTemplateColumns:   "repeat(auto-fill, minmax(300px, 1fr))",
            gap:                   22,
          }}
        >
          {FEATURES.map((f) => (
            <FeatureCard key={f.title} feature={f} />
          ))}
        </motion.div>
      </div>
    </section>
  );
}

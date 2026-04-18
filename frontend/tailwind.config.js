/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  // Do NOT set darkMode here — we manage the dark theme entirely via CSS vars.
  // Setting darkMode: false suppresses Tailwind's dark: utilities but the real
  // fix is ensuring we never rely on them. Omitting the key uses the default
  // ("media") which doesn't affect our custom color tokens at all.
  theme: {
    extend: {
      colors: {
        // Background palette
        "cyber-dark":   "#050810",
        "cyber-card":   "#0c1120",
        "cyber-border": "#1a2540",
        // Neon accent colors
        "neon-cyan":    "#00f5ff",
        "neon-green":   "#00ff88",
        "neon-red":     "#ff2d55",
        "neon-yellow":  "#ffd60a",
        "neon-purple":  "#bf5af2",
        // FIX: Renamed from "text-primary" / "text-secondary" to avoid the
        // double-prefix problem. Tailwind appends "text-" to generate the
        // utility class, so "text-primary" → "text-text-primary" works BUT
        // it's confusing and occasionally breaks in certain JIT environments.
        // We keep the same generated class names but add explicit CSS fallbacks.
        // "text-primary" color key → generates class "text-text-primary" ✓
        "text-primary":   "#e8eaf0",
        "text-secondary": "#8892b0",
      },
      fontFamily: {
        mono:    ["'JetBrains Mono'", "monospace"],
        display: ["'Space Grotesk'",  "sans-serif"],
        body:    ["'Inter'",           "sans-serif"],
        /*
         * FIX: Added Syne — used by the About page for all display headings
         * (hero title, section titles, creator name, feature card titles).
         * Without this entry, Tailwind won't generate the `font-syne` utility
         * class and the About page falls back to system fonts.
         */
        syne:    ["'Syne'",            "sans-serif"],
      },
      boxShadow: {
        "neon-cyan":  "0 0 20px rgba(0, 245, 255, 0.3)",
        "neon-green": "0 0 20px rgba(0, 255, 136, 0.3)",
        "neon-red":   "0 0 20px rgba(255, 45, 85, 0.3)",
        "neon-card":  "0 4px 24px rgba(0, 0, 0, 0.6), 0 0 1px rgba(0, 245, 255, 0.1)",
        /*
         * FIX: Added glow shadow variants used by About page feature cards
         * on hover. Without these, the box-shadow is applied only as an
         * inline framer-motion style — adding them here means Tailwind can
         * also generate them as utilities if needed elsewhere.
         */
        "glow-cyan":  "0 0 32px rgba(0, 245, 255, 0.25), 0 0 64px rgba(0, 245, 255, 0.1)",
        "glow-sky":   "0 0 32px rgba(56, 189, 248, 0.25), 0 0 64px rgba(56, 189, 248, 0.1)",
        "glow-teal":  "0 0 32px rgba(20, 184, 166, 0.25), 0 0 64px rgba(20, 184, 166, 0.1)",
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "scan-line":  "scanLine 2s linear infinite",
        "glow":       "glow 2s ease-in-out infinite alternate",
        "float":      "float 6s ease-in-out infinite",
        /*
         * FIX: Added rotate-border animation for the About page creator card
         * animated gradient border. Matches the CSS @keyframes rotateBorder
         * defined in globals.css so both the Tailwind utility and the CSS
         * class work interchangeably.
         */
        "rotate-border": "rotateBorder 4s linear infinite",
      },
      keyframes: {
        scanLine: {
          "0%":   { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        glow: {
          "0%":   { textShadow: "0 0 10px rgba(0, 245, 255, 0.5)" },
          "100%": { textShadow: "0 0 30px rgba(0, 245, 255, 1), 0 0 60px rgba(0, 245, 255, 0.5)" },
        },
        float: {
          "0%, 100%": { transform: "translateY(0)" },
          "50%":      { transform: "translateY(-10px)" },
        },
        // Matches @keyframes rotateBorder in globals.css
        rotateBorder: {
          "0%":   { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
      },
      backgroundImage: {
        "cyber-grid":    "linear-gradient(rgba(0, 245, 255, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 245, 255, 0.03) 1px, transparent 1px)",
        "hero-gradient": "radial-gradient(ellipse at top left, rgba(0, 245, 255, 0.08) 0%, transparent 60%), radial-gradient(ellipse at bottom right, rgba(191, 90, 242, 0.06) 0%, transparent 60%)",
      },
    },
  },
  plugins: [],
};
"use client";
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Shield, Eye, EyeOff, AlertCircle, Lock, ArrowRight, Zap } from "lucide-react";
import toast from "react-hot-toast";
import { useAuthStore } from "@/lib/store";
import { motion, AnimatePresence } from "framer-motion";

const DEMO_ACCOUNTS = [
  { label: "Analyst", email: "analyst@phishguard.io", password: "Analyst1!", color: "#c471ed" },
  { label: "User",    email: "user@phishguard.io",    password: "User1234!", color: "#00e5ff"  },
];

export default function LoginPage() {
  const router = useRouter();
  const { login, isLoading } = useAuthStore();
  const [email, setEmail]               = useState("");
  const [password, setPassword]         = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError]               = useState("");
  const [focusedField, setFocusedField] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (!email || !password) { setError("Please enter your email and password"); return; }
    try {
      await login(email, password);
      toast.success("Access granted", {
        style: { background: "#080e1c", color: "#e2e8f8", border: "1px solid rgba(0,230,118,0.3)" },
        icon: "🛡️",
      });
      router.push("/dashboard");
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      const msg = typeof detail === "string" ? detail : "Authentication failed";
      setError(msg);
    }
  };

  const loginAsDemo = async (demo: typeof DEMO_ACCOUNTS[0]) => {
    setError("");
    try {
      await login(demo.email, demo.password);
      toast.success(`Signed in as ${demo.label}`);
      router.push("/dashboard");
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      const msg = typeof detail === "string" ? detail : "Demo login failed — ensure server is running";
      setError(msg);
    }
  };

  return (
    <div
      className="min-h-screen grid-bg flex items-center justify-center px-4 py-12"
      style={{ background: "var(--bg-void)" }}
    >
      {/* Ambient bg */}
      <div className="fixed inset-0" style={{ zIndex: 0, pointerEvents: "none" }} aria-hidden>
        <div style={{
          position: "absolute", top: "20%", left: "30%",
          width: 400, height: 400,
          background: "radial-gradient(ellipse, rgba(0,229,255,0.07) 0%, transparent 60%)",
          filter: "blur(50px)",
        }} />
        <div style={{
          position: "absolute", bottom: "20%", right: "25%",
          width: 300, height: 300,
          background: "radial-gradient(ellipse, rgba(196,113,237,0.06) 0%, transparent 60%)",
          filter: "blur(60px)",
        }} />
      </div>

      <div className="w-full max-w-[400px] relative" style={{ zIndex: 10 }}>

        {/* Logo mark */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-8"
        >
          <Link href="/" style={{ textDecoration: "none" }}>
            <div
              className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4 relative"
              style={{ background: "rgba(0,229,255,0.08)", border: "1px solid rgba(0,229,255,0.2)" }}
            >
              <Shield size={28} style={{ color: "#00e5ff", filter: "drop-shadow(0 0 12px rgba(0,229,255,0.6))" }} />
              <div
                className="absolute -top-1 -right-1 w-3 h-3 rounded-full"
                style={{ background: "#00e676", boxShadow: "0 0 8px #00e676" }}
              />
            </div>
          </Link>
          <div className="font-display font-bold text-xl mb-1" style={{ color: "#e2e8f8", letterSpacing: "-0.02em" }}>
            Phish<span style={{ color: "#00e5ff" }}>Guard</span>
          </div>
          <div className="font-mono text-xs" style={{ color: "#7986a8" }}>Secure access portal</div>
        </motion.div>

        {/* Demo accounts */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="glass-card p-4 mb-4"
        >
          <div className="flex items-center gap-2 mb-3">
            <span className="pulse-dot" />
            <span className="font-mono text-xs uppercase tracking-widest" style={{ color: "#3d4d6e" }}>
              Demo Access
            </span>
          </div>
          <div className="grid grid-cols-2 gap-2">
            {DEMO_ACCOUNTS.map((demo) => (
              <motion.button
                key={demo.label}
                type="button"
                onClick={() => loginAsDemo(demo)}
                disabled={isLoading}
                whileHover={{ scale: 1.03, y: -1 }}
                whileTap={{ scale: 0.97 }}
                className="flex items-center gap-2.5 p-3 rounded-xl transition-colors"
                style={{
                  background: `${demo.color}08`,
                  border: `1px solid ${demo.color}20`,
                  cursor: isLoading ? "not-allowed" : "pointer",
                  opacity: isLoading ? 0.5 : 1,
                }}
              >
                <div
                  className="w-7 h-7 rounded-full flex items-center justify-center font-mono text-xs font-bold flex-shrink-0"
                  style={{ background: `${demo.color}14`, color: demo.color }}
                >
                  {demo.label[0]}
                </div>
                <div className="text-left">
                  <div className="font-mono text-xs font-semibold" style={{ color: demo.color }}>
                    {demo.label}
                  </div>
                  <div className="font-mono text-xs" style={{ color: "#3d4d6e", fontSize: 9 }}>
                    Instant login
                  </div>
                </div>
                <Zap size={11} style={{ color: demo.color, opacity: 0.5, marginLeft: "auto" }} />
              </motion.button>
            ))}
          </div>
        </motion.div>

        {/* Login form */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="glass-card p-6 relative overflow-hidden"
        >
          <div className="scanner-line-slow" />

          <h2 className="font-display font-bold text-xl mb-5" style={{ color: "#e2e8f8", letterSpacing: "-0.01em" }}>
            Sign in
          </h2>

          {/* Error */}
          <AnimatePresence>
            {error && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="flex items-center gap-2 p-3 mb-4 rounded-xl font-mono text-xs overflow-hidden"
                style={{ background: "rgba(255,61,90,0.08)", border: "1px solid rgba(255,61,90,0.2)", color: "#ff3d5a" }}
              >
                <AlertCircle size={13} style={{ flexShrink: 0 }} />
                {error}
              </motion.div>
            )}
          </AnimatePresence>

          <form onSubmit={handleSubmit} className="space-y-4" noValidate>
            {/* Email */}
            <div>
              <label className="block font-mono text-xs uppercase tracking-widest mb-2" style={{ color: "#3d4d6e" }}>
                Email
              </label>
              <input
                type="email"
                className="scan-input"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onFocus={() => setFocusedField("email")}
                onBlur={() => setFocusedField(null)}
                autoComplete="email"
                required
              />
            </div>

            {/* Password */}
            <div>
              <label className="block font-mono text-xs uppercase tracking-widest mb-2" style={{ color: "#3d4d6e" }}>
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  className="scan-input"
                  style={{ paddingRight: 44 }}
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onFocus={() => setFocusedField("password")}
                  onBlur={() => setFocusedField(null)}
                  autoComplete="current-password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((p) => !p)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 transition-colors"
                  style={{ color: "#3d4d6e", background: "none", border: "none", cursor: "pointer", padding: 4 }}
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            <motion.button
              type="submit"
              disabled={isLoading}
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.99 }}
              className="btn-primary w-full py-3 mt-2"
            >
              {isLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                    className="w-4 h-4 border-2 rounded-full"
                    style={{ borderColor: "rgba(2,7,16,0.3)", borderTopColor: "#020710" }}
                  />
                  Authenticating...
                </span>
              ) : (
                <>
                  <Lock size={14} />
                  Access System
                  <ArrowRight size={14} />
                </>
              )}
            </motion.button>
          </form>

          <div className="mt-5 text-center">
            <span className="font-body text-sm" style={{ color: "#7986a8" }}>No account? </span>
            <Link
              href="/auth/register"
              className="font-mono text-xs transition-colors"
              style={{ color: "#00e5ff", textDecoration: "none" }}
            >
              Create one →
            </Link>
          </div>
        </motion.div>

        {/* Trust bar */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.4 }}
          className="flex items-center justify-center gap-5 mt-5"
        >
          {["JWT Auth", "AES-256", "bcrypt"].map((item) => (
            <div key={item} className="flex items-center gap-1.5">
              <div className="w-1 h-1 rounded-full" style={{ background: "#3d4d6e" }} />
              <span className="font-mono text-xs" style={{ color: "#3d4d6e" }}>{item}</span>
            </div>
          ))}
        </motion.div>
      </div>
    </div>
  );
}

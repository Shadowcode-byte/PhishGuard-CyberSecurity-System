"use client";
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Shield, AlertCircle, Eye, EyeOff, CheckSquare, Square, Check, UserPlus, ArrowRight } from "lucide-react";
import toast from "react-hot-toast";
import { useAuthStore } from "@/lib/store";
import { useTranslations } from "next-intl";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";
import { motion, AnimatePresence } from "framer-motion";

function PasswordCheck({ label, met }: { label: string; met: boolean }) {
  return (
    <motion.span
      animate={{ color: met ? "#00e676" : "#3d4d6e" }}
      className="flex items-center gap-1.5 font-mono text-xs transition-colors"
    >
      <motion.div
        animate={{
          scale: met ? [1, 1.3, 1] : 1,
          background: met ? "#00e676" : "rgba(255,255,255,0.08)",
        }}
        transition={{ duration: 0.3 }}
        className="w-3 h-3 rounded-full flex items-center justify-center flex-shrink-0"
      >
        {met && <Check size={8} style={{ color: "#020710" }} />}
      </motion.div>
      {label}
    </motion.span>
  );
}

export default function RegisterPage() {
  const t       = useTranslations("auth.register");
  const tCommon = useTranslations("common");
  const router  = useRouter();
  const { register, isLoading } = useAuthStore();

  const [form, setForm]                   = useState({ email: "", username: "", password: "" });
  const [showPassword, setShowPassword]   = useState(false);
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [error, setError]                 = useState("");

  const pwChecks = {
    length:    form.password.length >= 8,
    uppercase: /[A-Z]/.test(form.password),
    digit:     /[0-9]/.test(form.password),
  };

  const pwStrength = Object.values(pwChecks).filter(Boolean).length;
  const strengthColors = ["#3d4d6e", "#ff3d5a", "#ffb300", "#00e676"];
  const strengthLabels = ["", "Weak", "Fair", "Strong"];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (!form.email || !form.username || !form.password) { setError(t("errors.allRequired")); return; }
    if (!pwChecks.length || !pwChecks.uppercase || !pwChecks.digit) { setError(t("errors.passwordRequirements")); return; }
    if (!termsAccepted) { setError(t("errors.acceptTerms")); return; }
    try {
      await register(form.email, form.username, form.password, termsAccepted);
      toast.success(t("accountCreated"), {
        style: { background: "#080e1c", color: "#e2e8f8", border: "1px solid rgba(0,230,118,0.3)" },
      });
      router.push("/auth/login");
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      let msg = t("errors.registrationFailed");
      if (typeof detail === "string") msg = detail;
      else if (Array.isArray(detail) && detail[0]?.msg) msg = detail[0].msg.replace("Value error, ", "");
      setError(msg);
    }
  };

  return (
    <div
      className="min-h-screen grid-bg flex items-center justify-center px-4 py-12"
      style={{ background: "var(--bg-void)" }}
    >
      {/* Ambient */}
      <div className="fixed inset-0" style={{ zIndex: 0, pointerEvents: "none" }} aria-hidden>
        <div style={{
          position: "absolute", top: "25%", right: "30%",
          width: 360, height: 360,
          background: "radial-gradient(ellipse, rgba(196,113,237,0.07) 0%, transparent 60%)",
          filter: "blur(60px)",
        }} />
      </div>

      <div className="w-full max-w-[400px] relative" style={{ zIndex: 10 }}>

        {/* Language switcher */}
        <div className="flex justify-end mb-4">
          <LanguageSwitcher />
        </div>

        {/* Logo */}
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
            </div>
          </Link>
          <div className="font-display font-bold text-xl mb-1" style={{ color: "#e2e8f8", letterSpacing: "-0.02em" }}>
            Phish<span style={{ color: "#00e5ff" }}>Guard</span>
          </div>
          <div className="font-mono text-xs" style={{ color: "#7986a8" }}>{t("subtitle")}</div>
        </motion.div>

        {/* Form card */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="glass-card p-6 relative overflow-hidden"
        >
          <div className="scanner-line-slow" />

          <h2 className="font-display font-bold text-xl mb-5" style={{ color: "#e2e8f8", letterSpacing: "-0.01em" }}>
            {t("title")}
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
                {t("email")}
              </label>
              <input
                type="email"
                className="scan-input"
                placeholder={t("emailPlaceholder")}
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
                autoComplete="email"
                required
              />
            </div>

            {/* Username */}
            <div>
              <label className="block font-mono text-xs uppercase tracking-widest mb-2" style={{ color: "#3d4d6e" }}>
                {t("username")}
              </label>
              <input
                type="text"
                className="scan-input"
                placeholder={t("usernamePlaceholder")}
                value={form.username}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
                autoComplete="username"
                required
              />
            </div>

            {/* Password */}
            <div>
              <label className="block font-mono text-xs uppercase tracking-widest mb-2" style={{ color: "#3d4d6e" }}>
                {t("password")}
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  className="scan-input"
                  style={{ paddingRight: 44 }}
                  placeholder={t("passwordPlaceholder")}
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  autoComplete="new-password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((p) => !p)}
                  className="absolute right-3 top-1/2 -translate-y-1/2"
                  style={{ color: "#3d4d6e", background: "none", border: "none", cursor: "pointer", padding: 4 }}
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>

              {/* Strength meter */}
              <AnimatePresence>
                {form.password.length > 0 && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    className="mt-3 overflow-hidden"
                  >
                    {/* Bar */}
                    <div className="flex gap-1 mb-2">
                      {[1, 2, 3].map((i) => (
                        <motion.div
                          key={i}
                          className="h-1 flex-1 rounded-full"
                          animate={{ background: pwStrength >= i ? strengthColors[pwStrength] : "rgba(255,255,255,0.06)" }}
                          transition={{ duration: 0.3 }}
                        />
                      ))}
                    </div>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex gap-3 flex-wrap">
                        <PasswordCheck label={t("passwordRequirements.length")}    met={pwChecks.length} />
                        <PasswordCheck label={t("passwordRequirements.uppercase")} met={pwChecks.uppercase} />
                        <PasswordCheck label={t("passwordRequirements.digit")}     met={pwChecks.digit} />
                      </div>
                      {pwStrength > 0 && (
                        <span className="font-mono text-xs flex-shrink-0 ml-2" style={{ color: strengthColors[pwStrength] }}>
                          {strengthLabels[pwStrength]}
                        </span>
                      )}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Terms */}
            <button
              type="button"
              onClick={() => setTermsAccepted((p) => !p)}
              className="flex items-start gap-2.5 text-left w-full mt-1"
              style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}
            >
              <motion.div
                className="mt-0.5 flex-shrink-0"
                animate={{ scale: termsAccepted ? [1, 1.2, 1] : 1 }}
                transition={{ duration: 0.2 }}
              >
                {termsAccepted
                  ? <CheckSquare size={15} style={{ color: "#00e5ff" }} />
                  : <Square      size={15} style={{ color: "#3d4d6e" }} />
                }
              </motion.div>
              <span className="font-mono text-xs leading-relaxed" style={{ color: "#7986a8" }}>
                {t("termsLabel")}{" "}
                <span style={{ color: "#00e5ff" }}>{t("termsLink")}</span>
              </span>
            </button>

            <motion.button
              type="submit"
              disabled={isLoading}
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.99 }}
              className="btn-primary w-full py-3 mt-1"
            >
              {isLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                    className="w-4 h-4 border-2 rounded-full"
                    style={{ borderColor: "rgba(2,7,16,0.3)", borderTopColor: "#020710" }}
                  />
                  {t("submitting")}
                </span>
              ) : (
                <>
                  <UserPlus size={14} />
                  {t("submit")}
                  <ArrowRight size={14} />
                </>
              )}
            </motion.button>
          </form>

          <div className="mt-5 text-center">
            <span className="font-body text-sm" style={{ color: "#7986a8" }}>{t("hasAccount")} </span>
            <Link
              href="/auth/login"
              className="font-mono text-xs"
              style={{ color: "#00e5ff", textDecoration: "none" }}
            >
              {t("signIn")} →
            </Link>
          </div>
        </motion.div>

        {/* Security badge */}
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
          className="text-center font-mono text-xs mt-4"
          style={{ color: "#3d4d6e" }}
        >
          {tCommon("protected")}
        </motion.p>
      </div>
    </div>
  );
}

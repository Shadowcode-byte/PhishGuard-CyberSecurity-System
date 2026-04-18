"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, Globe, MessageSquare, FileSearch,
  History, LogOut, BarChart3, Users, Activity,
  Network, ScrollText, Info, Menu, X, ChevronRight,
} from "lucide-react";
import { useAuthStore } from "@/lib/store";
import { useTranslations } from "next-intl";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";

// ── Nav structure ──────────────────────────────────────────────────────────────
const NAV_ITEMS = [
  { href: "/dashboard",         icon: BarChart3,     key: "dashboard"      },
  { href: "/dashboard/url",     icon: Globe,         key: "urlScanner"     },
  { href: "/dashboard/message", icon: MessageSquare, key: "messageScanner" },
  { href: "/dashboard/file",    icon: FileSearch,    key: "fileScanner"    },
  { href: "/dashboard/network", icon: Network,       key: "networkScanner" },
  { href: "/dashboard/history", icon: History,       key: "scanHistory"    },
];

const BOTTOM_ITEMS = [
  { href: "/dashboard/about", icon: Info,       key: "about"          },
  { href: "/dashboard/tos",   icon: ScrollText, key: "termsOfService" },
];

const ADMIN_ITEMS = [
  { href: "/dashboard/admin",      icon: Users,    key: "userManagement" },
  { href: "/dashboard/admin/logs", icon: Activity, key: "auditLogs"      },
];

// ── Role styling ───────────────────────────────────────────────────────────────
const ROLE_STYLES: Record<string, { bg: string; color: string; border: string }> = {
  admin:   { bg: "rgba(255,179,0,0.1)",  color: "#ffb300", border: "rgba(255,179,0,0.25)"  },
  analyst: { bg: "rgba(196,113,237,0.1)", color: "#c471ed", border: "rgba(196,113,237,0.25)" },
  user:    { bg: "rgba(0,229,255,0.1)",  color: "#00e5ff", border: "rgba(0,229,255,0.25)"  },
};

// ── NavItem component ──────────────────────────────────────────────────────────
function NavItem({
  href, icon: Icon, label, active, adminStyle = false, onClick,
}: {
  href: string; icon: React.ElementType; label: string;
  active: boolean; adminStyle?: boolean; onClick?: () => void;
}) {
  const activeColor = adminStyle ? "#ffb300" : "#00e5ff";
  const activeBg    = adminStyle ? "rgba(255,179,0,0.08)" : "rgba(0,229,255,0.08)";
  const activeBorder = adminStyle ? "rgba(255,179,0,0.18)" : "rgba(0,229,255,0.18)";

  return (
    <Link
      href={href}
      onClick={onClick}
      className="nav-item"
      style={active ? {
        background: activeBg,
        border: `1px solid ${activeBorder}`,
        color: activeColor,
      } : undefined}
    >
      {active && (
        <motion.div
          layoutId={adminStyle ? "admin-active-indicator" : "active-indicator"}
          className="absolute left-0 top-1/2"
          style={{
            width: 2,
            height: "55%",
            transform: "translateY(-50%)",
            background: activeColor,
            borderRadius: "0 2px 2px 0",
            boxShadow: `0 0 8px ${activeColor}`,
          }}
        />
      )}
      <Icon size={15} style={{ color: active ? activeColor : "#7986a8", flexShrink: 0 }} />
      <span style={{ color: active ? activeColor : "inherit" }}>{label}</span>
      {active && <ChevronRight size={12} style={{ marginLeft: "auto", color: activeColor, opacity: 0.6 }} />}
    </Link>
  );
}

// ── Sidebar content ────────────────────────────────────────────────────────────
function SidebarContent({
  pathname, user, t, tCommon, onLogout, onNavigate,
}: {
  pathname: string;
  user: any;
  t: any; tCommon: any;
  onLogout: () => void;
  onNavigate?: () => void;
}) {
  const rc = ROLE_STYLES[user?.role ?? "user"] ?? ROLE_STYLES.user;
  const isAdmin = user?.role === "admin" || user?.role === "analyst";

  // Strip locale prefix for matching
  const normalizedPath = "/" + pathname.split("/").slice(2).join("/");

  return (
    <div
      className="flex flex-col h-full overflow-hidden"
      style={{ background: "var(--bg-surface)", borderRight: "1px solid rgba(255,255,255,0.05)" }}
    >
      {/* Logo */}
      <div
        className="px-5 py-4 flex items-center gap-2.5 flex-shrink-0"
        style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}
      >
        <div className="relative">
          <div
            className="w-8 h-8 rounded-xl flex items-center justify-center"
            style={{ background: "rgba(0,229,255,0.08)", border: "1px solid rgba(0,229,255,0.2)" }}
          >
            <Shield size={15} style={{ color: "#00e5ff" }} />
          </div>
          {/* Live dot */}
          <div
            className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full"
            style={{ background: "#00e676", boxShadow: "0 0 6px #00e676" }}
          />
        </div>
        <div>
          <div
            className="font-display font-bold text-sm"
            style={{ color: "#e2e8f8", letterSpacing: "-0.01em" }}
          >
            Phish<span style={{ color: "#00e5ff" }}>Guard</span>
          </div>
          <div className="font-mono text-xs" style={{ color: "#3d4d6e" }}>v2.0 · Secure</div>
        </div>
      </div>

      {/* User profile */}
      {user && (
        <div className="px-4 py-3 flex-shrink-0" style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
          <div className="flex items-center gap-3">
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center font-mono text-xs font-bold flex-shrink-0"
              style={{
                background: `${rc.color}14`,
                border: `1px solid ${rc.border}`,
                color: rc.color,
              }}
            >
              {user.username?.[0]?.toUpperCase() ?? "?"}
            </div>
            <div className="min-w-0 flex-1">
              <div className="font-body text-xs font-medium truncate" style={{ color: "#e2e8f8" }}>
                {user.username}
              </div>
              <div
                className="badge inline-flex mt-0.5"
                style={{
                  background: rc.bg,
                  color: rc.color,
                  border: `1px solid ${rc.border}`,
                  fontSize: 9,
                  padding: "1px 7px",
                }}
              >
                {user.role?.toUpperCase()}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main navigation */}
      <nav className="flex-1 p-3 space-y-0.5 overflow-y-auto">
        {NAV_ITEMS.map((item) => (
          <NavItem
            key={item.href}
            href={item.href}
            icon={item.icon}
            label={t(item.key)}
            active={
              item.href === "/dashboard"
                ? normalizedPath === "/dashboard"
                : normalizedPath.startsWith(item.href)
            }
            onClick={onNavigate}
          />
        ))}

        {isAdmin && (
          <>
            <div className="pt-4 pb-1 px-3">
              <div
                className="font-mono text-xs uppercase tracking-widest"
                style={{ color: "#3d4d6e" }}
              >
                Admin
              </div>
            </div>
            {ADMIN_ITEMS.map((item) => (
              <NavItem
                key={item.href}
                href={item.href}
                icon={item.icon}
                label={t(item.key)}
                active={normalizedPath === item.href}
                adminStyle
                onClick={onNavigate}
              />
            ))}
          </>
        )}

        {/* Divider */}
        <div className="pt-3 pb-1">
          <div style={{ height: 1, background: "rgba(255,255,255,0.04)" }} />
        </div>

        {BOTTOM_ITEMS.map((item) => (
          <NavItem
            key={item.href}
            href={item.href}
            icon={item.icon}
            label={t(item.key)}
            active={normalizedPath === item.href}
            onClick={onNavigate}
          />
        ))}
      </nav>

      {/* Footer */}
      <div className="p-3 flex-shrink-0" style={{ borderTop: "1px solid rgba(255,255,255,0.05)" }}>
        <div className="mb-2 px-1">
          <LanguageSwitcher />
        </div>
        <button
          onClick={onLogout}
          className="nav-item w-full text-left"
          style={{ background: "none", border: "1px solid transparent", cursor: "pointer" }}
        >
          <LogOut size={15} style={{ color: "#7986a8", flexShrink: 0 }} />
          <span>{tCommon("signOut")}</span>
        </button>
      </div>
    </div>
  );
}

// ── Dashboard layout ───────────────────────────────────────────────────────────
export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const t       = useTranslations("nav");
  const tCommon = useTranslations("common");

  const { user, isAuthenticated, logout, fetchUser } = useAuthStore();
  const router   = useRouter();
  const pathname = usePathname();

  const [mounted,    setMounted]    = useState(false);
  const [checking,   setChecking]   = useState(true);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    setMounted(true);
    const token = localStorage.getItem("access_token");
    if (!token) { router.replace("/auth/login"); return; }
    fetchUser().finally(() => {
      setChecking(false);
      if (!useAuthStore.getState().isAuthenticated) router.replace("/auth/login");
    });
  }, []);

  useEffect(() => { setMobileOpen(false); }, [pathname]);

  if (!mounted) {
    return <div className="min-h-screen" style={{ background: "var(--bg-void)" }} />;
  }

  if (checking) {
    return (
      <div
        className="min-h-screen flex flex-col items-center justify-center gap-4"
        style={{ background: "var(--bg-void)" }}
      >
        <div className="relative">
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
            className="w-12 h-12 rounded-full"
            style={{ border: "2px solid rgba(0,229,255,0.1)", borderTopColor: "#00e5ff" }}
          />
          <Shield
            size={18}
            className="absolute inset-0 m-auto"
            style={{ color: "#00e5ff" }}
          />
        </div>
        <div className="font-mono text-xs" style={{ color: "#00e5ff" }}>
          {tCommon("authenticating")}
        </div>
      </div>
    );
  }

  if (!isAuthenticated) return null;

  const handleLogout = () => { logout(); router.push("/auth/login"); };

  const sidebarProps = {
    pathname,
    user,
    t,
    tCommon,
    onLogout: handleLogout,
  };

  return (
    <div className="min-h-screen flex" style={{ background: "var(--bg-void)" }}>

      {/* Desktop sidebar */}
      <aside
        className="hidden md:flex flex-col shrink-0 sticky top-0 h-screen"
        style={{ width: 236 }}
      >
        <SidebarContent {...sidebarProps} />
      </aside>

      {/* Mobile backdrop */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            key="backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-40 md:hidden"
            style={{ background: "rgba(2,4,10,0.85)", backdropFilter: "blur(6px)" }}
            onClick={() => setMobileOpen(false)}
          />
        )}
      </AnimatePresence>

      {/* Mobile slide-in sidebar */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.aside
            key="mobile-sidebar"
            initial={{ x: "-100%" }}
            animate={{ x: 0 }}
            exit={{ x: "-100%" }}
            transition={{ type: "spring", damping: 30, stiffness: 280 }}
            className="fixed inset-y-0 left-0 z-50 w-60 md:hidden"
          >
            <SidebarContent {...sidebarProps} onNavigate={() => setMobileOpen(false)} />
          </motion.aside>
        )}
      </AnimatePresence>

      {/* Main content area */}
      <div className="flex-1 flex flex-col min-w-0">

        {/* Mobile header */}
        <header
          className="md:hidden flex items-center justify-between px-4 py-3 sticky top-0 z-30"
          style={{
            background: "var(--bg-surface)",
            borderBottom: "1px solid rgba(255,255,255,0.05)",
          }}
        >
          <div className="flex items-center gap-2">
            <div
              className="w-7 h-7 rounded-lg flex items-center justify-center"
              style={{ background: "rgba(0,229,255,0.08)", border: "1px solid rgba(0,229,255,0.2)" }}
            >
              <Shield size={13} style={{ color: "#00e5ff" }} />
            </div>
            <span className="font-display font-bold text-sm" style={{ color: "#e2e8f8" }}>
              Phish<span style={{ color: "#00e5ff" }}>Guard</span>
            </span>
          </div>
          <div className="flex items-center gap-2">
            <LanguageSwitcher />
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className="p-2 rounded-lg"
              style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.07)", color: "#7986a8" }}
              aria-label="Toggle navigation"
            >
              {mobileOpen ? <X size={18} /> : <Menu size={18} />}
            </button>
          </div>
        </header>

        {/* Page content */}
        <main
          className="flex-1 overflow-auto"
          style={{ color: "#e2e8f8" }}
        >
          <motion.div
            key={pathname}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25, ease: "easeOut" }}
            className="h-full"
          >
            {children}
          </motion.div>
        </main>
      </div>
    </div>
  );
}

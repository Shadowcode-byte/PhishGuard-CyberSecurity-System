"use client";
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  Users, Shield, Activity, BarChart2, AlertTriangle, CheckCircle,
  Plus, Trash2, RotateCcw, Search, ChevronLeft, ChevronRight,
  X, Eye, EyeOff, UserCheck, UserX, Key,
} from "lucide-react";
import { adminApi } from "@/lib/api";
import toast from "react-hot-toast";
import { clsx } from "clsx";

// ── Stat card ─────────────────────────────────────────────────────────────────
function AdminStatCard({ icon: Icon, label, value, color }: {
  icon: React.ElementType; label: string; value: number; color: string;
}) {
  const colors: Record<string, string> = {
    cyan: "#00f5ff", green: "#00ff88", red: "#ff2d55", yellow: "#ffd60a", purple: "#bf5af2",
  };
  const c = colors[color] ?? colors.cyan;
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="cyber-card p-5"
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-text-secondary text-xs font-mono uppercase tracking-wider">{label}</span>
        <div
          className="w-7 h-7 rounded-lg flex items-center justify-center border"
          style={{ background: `${c}12`, borderColor: `${c}30` }}
        >
          <Icon className="w-3.5 h-3.5" style={{ color: c }} />
        </div>
      </div>
      <div className="font-display text-3xl font-bold" style={{ color: c }}>
        {value.toLocaleString()}
      </div>
    </motion.div>
  );
}

// ── Role badge ────────────────────────────────────────────────────────────────
const ROLE_COLORS: Record<string, { color: string; bg: string; border: string }> = {
  admin:   { color: "#ffd60a", bg: "rgba(255,214,10,0.1)",  border: "rgba(255,214,10,0.3)"  },
  analyst: { color: "#bf5af2", bg: "rgba(191,90,242,0.1)",  border: "rgba(191,90,242,0.3)"  },
  user:    { color: "#00f5ff", bg: "rgba(0,245,255,0.1)",   border: "rgba(0,245,255,0.3)"   },
};

function RoleBadge({ role }: { role: string }) {
  const rc = ROLE_COLORS[role] ?? ROLE_COLORS.user;
  return (
    <span
      className="text-xs font-mono px-2 py-0.5 rounded-full border"
      style={{ background: rc.bg, color: rc.color, borderColor: rc.border }}
    >
      {role.toUpperCase()}
    </span>
  );
}

// ── Create User Modal ─────────────────────────────────────────────────────────
function CreateUserModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({ email: "", username: "", password: "", role: "user" });
  const [showPw, setShowPw] = useState(false);

  const { mutate, isPending } = useMutation({
    mutationFn: () => adminApi.createUser(form),
    onSuccess: () => { toast.success("User created"); onCreated(); onClose(); },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? "Failed to create user"),
  });

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(5,8,16,0.85)", backdropFilter: "blur(6px)" }}
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.92, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.92, opacity: 0 }}
        className="cyber-card w-full max-w-md p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2">
            <Plus className="w-4 h-4" style={{ color: "#00f5ff" }} />
            <h2 className="font-display font-bold text-base" style={{ color: "#e8eaf0" }}>Create User</h2>
          </div>
          <button onClick={onClose} className="p-1 rounded hover:bg-white/5 transition-colors">
            <X className="w-4 h-4" style={{ color: "#8892b0" }} />
          </button>
        </div>

        <div className="space-y-4">
          {[
            { key: "email", label: "Email", type: "email", placeholder: "user@example.com" },
            { key: "username", label: "Username", type: "text", placeholder: "username" },
          ].map(({ key, label, type, placeholder }) => (
            <div key={key}>
              <label className="block text-xs font-mono mb-1.5" style={{ color: "#8892b0" }}>{label}</label>
              <input
                type={type}
                placeholder={placeholder}
                value={(form as any)[key]}
                onChange={(e) => setForm((f) => ({ ...f, [key]: e.target.value }))}
                className="w-full bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2.5 text-sm font-mono outline-none focus:border-neon-cyan/50"
                style={{ color: "#e8eaf0" }}
              />
            </div>
          ))}

          <div>
            <label className="block text-xs font-mono mb-1.5" style={{ color: "#8892b0" }}>Password</label>
            <div className="relative">
              <input
                type={showPw ? "text" : "password"}
                placeholder="Min 8 characters"
                value={form.password}
                onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
                className="w-full bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2.5 pr-10 text-sm font-mono outline-none focus:border-neon-cyan/50"
                style={{ color: "#e8eaf0" }}
              />
              <button
                type="button"
                onClick={() => setShowPw(!showPw)}
                className="absolute right-3 top-1/2 -translate-y-1/2"
                style={{ color: "#8892b0" }}
              >
                {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono mb-1.5" style={{ color: "#8892b0" }}>Role</label>
            <select
              value={form.role}
              onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))}
              className="w-full bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2.5 text-sm font-mono outline-none focus:border-neon-cyan/50"
              style={{ color: "#e8eaf0" }}
            >
              <option value="user">User</option>
              <option value="analyst">Analyst</option>
              <option value="admin">Admin</option>
            </select>
          </div>
        </div>

        <div className="flex gap-3 mt-6">
          <button
            onClick={onClose}
            className="flex-1 py-2.5 rounded-lg border font-mono text-sm transition-all"
            style={{ borderColor: "#1a2540", color: "#8892b0" }}
          >
            Cancel
          </button>
          <button
            onClick={() => mutate()}
            disabled={isPending || !form.email || !form.username || !form.password}
            className="flex-1 py-2.5 rounded-lg font-mono text-sm font-medium transition-all disabled:opacity-40"
            style={{ background: "rgba(0,245,255,0.15)", border: "1px solid rgba(0,245,255,0.3)", color: "#00f5ff" }}
          >
            {isPending ? "Creating…" : "Create User"}
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}

// ── Reset Password Modal ──────────────────────────────────────────────────────
function ResetPasswordModal({ user, onClose }: { user: any; onClose: () => void }) {
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);

  const { mutate, isPending } = useMutation({
    mutationFn: () => adminApi.resetPassword(user.id, password),
    onSuccess: () => { toast.success(`Password reset for ${user.username}`); onClose(); },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? "Failed to reset password"),
  });

  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(5,8,16,0.85)", backdropFilter: "blur(6px)" }}
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.92, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.92, opacity: 0 }}
        className="cyber-card w-full max-w-sm p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4" style={{ color: "#ffd60a" }} />
            <h2 className="font-display font-bold text-base" style={{ color: "#e8eaf0" }}>
              Reset Password
            </h2>
          </div>
          <button onClick={onClose}><X className="w-4 h-4" style={{ color: "#8892b0" }} /></button>
        </div>
        <p className="font-mono text-xs mb-4" style={{ color: "#8892b0" }}>
          Setting new password for <span style={{ color: "#ffd60a" }}>{user.username}</span>
        </p>
        <div className="relative mb-5">
          <input
            type={showPw ? "text" : "password"}
            placeholder="New password (min 8 chars)"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2.5 pr-10 text-sm font-mono outline-none focus:border-yellow-400/50"
            style={{ color: "#e8eaf0" }}
          />
          <button type="button" onClick={() => setShowPw(!showPw)} className="absolute right-3 top-1/2 -translate-y-1/2" style={{ color: "#8892b0" }}>
            {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          </button>
        </div>
        <div className="flex gap-3">
          <button onClick={onClose} className="flex-1 py-2.5 rounded-lg border font-mono text-sm" style={{ borderColor: "#1a2540", color: "#8892b0" }}>Cancel</button>
          <button
            onClick={() => mutate()}
            disabled={isPending || password.length < 8}
            className="flex-1 py-2.5 rounded-lg font-mono text-sm font-medium disabled:opacity-40"
            style={{ background: "rgba(255,214,10,0.12)", border: "1px solid rgba(255,214,10,0.3)", color: "#ffd60a" }}
          >
            {isPending ? "Resetting…" : "Reset"}
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function AdminPage() {
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [page, setPage] = useState(1);
  const [showCreate, setShowCreate] = useState(false);
  const [resetTarget, setResetTarget] = useState<any>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ["admin-stats"],
    queryFn: () => adminApi.stats().then((r) => r.data),
  });

  const { data: usersData, isLoading: usersLoading } = useQuery({
    queryKey: ["admin-users", page, search, roleFilter],
    queryFn: () =>
      adminApi.users(page, 15, {
        search: search || undefined,
        role: roleFilter || undefined,
      }).then((r) => r.data),
  });

  const roleUpdate = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: string }) =>
      adminApi.updateRole(userId, role),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["admin-users"] }); toast.success("Role updated"); },
    onError: () => toast.error("Failed to update role"),
  });

  const toggleUser = useMutation({
    mutationFn: (userId: string) => adminApi.toggleUser(userId),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["admin-users"] }); },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? "Failed"),
  });

  const deleteUser = useMutation({
    mutationFn: (userId: string) => adminApi.deleteUser(userId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-users"] });
      qc.invalidateQueries({ queryKey: ["admin-stats"] });
      toast.success("User deleted");
      setDeleteConfirm(null);
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? "Failed to delete user"),
  });

  const totalPages = usersData ? Math.ceil(usersData.total / 15) : 1;

  return (
    <div className="p-6 max-w-7xl">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-2 mb-1">
          <Shield className="w-4 h-4" style={{ color: "#ffd60a" }} />
          <span className="font-mono text-xs uppercase tracking-widest" style={{ color: "#ffd60a" }}>Admin Console</span>
        </div>
        <h1 className="font-display text-2xl font-bold" style={{ color: "#e8eaf0" }}>Platform Overview</h1>
      </div>

      {/* Stats */}
      {!statsLoading && stats && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <AdminStatCard icon={Users}         label="Total Users"    value={stats.total_users}                           color="cyan"   />
          <AdminStatCard icon={BarChart2}     label="Total Scans"    value={stats.total_scans}                           color="cyan"   />
          <AdminStatCard icon={Activity}      label="Scans Today"    value={stats.scans_today}                           color="green"  />
          <AdminStatCard icon={AlertTriangle} label="Threats"        value={stats.phishing_detected + stats.fraud_detected} color="red" />
          <AdminStatCard icon={CheckCircle}   label="Safe Scans"     value={stats.safe_scans}                            color="green"  />
          <AdminStatCard icon={Activity}      label="URL Scans"      value={stats.url_scans}                             color="cyan"   />
          <AdminStatCard icon={Activity}      label="Message Scans"  value={stats.message_scans}                         color="purple" />
          <AdminStatCard icon={Activity}      label="File Scans"     value={stats.file_scans}                            color="yellow" />
        </div>
      )}

      {/* User Management header */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
        <div>
          <h2 className="font-display font-semibold" style={{ color: "#e8eaf0" }}>User Management</h2>
          <p className="font-mono text-xs mt-0.5" style={{ color: "#8892b0" }}>
            {usersData?.total ?? "—"} users total
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg font-mono text-sm font-medium transition-all border"
          style={{ background: "rgba(0,245,255,0.1)", borderColor: "rgba(0,245,255,0.3)", color: "#00f5ff" }}
        >
          <Plus className="w-4 h-4" />
          Create User
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-5">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: "#8892b0" }} />
          <input
            placeholder="Search username or email…"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            className="w-full bg-cyber-dark border border-cyber-border rounded-lg pl-9 pr-3 py-2 text-sm font-mono outline-none focus:border-neon-cyan/40"
            style={{ color: "#e8eaf0" }}
          />
        </div>
        <select
          value={roleFilter}
          onChange={(e) => { setRoleFilter(e.target.value); setPage(1); }}
          className="bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-sm font-mono outline-none focus:border-neon-cyan/40"
          style={{ color: roleFilter ? "#e8eaf0" : "#8892b0" }}
        >
          <option value="">All roles</option>
          <option value="user">User</option>
          <option value="analyst">Analyst</option>
          <option value="admin">Admin</option>
        </select>
      </div>

      {/* Users table */}
      <div className="cyber-card overflow-hidden mb-4">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: "1px solid #1a2540" }}>
                {["User", "Email", "Role", "Status", "Last Login", "Joined", "Actions"].map((h) => (
                  <th key={h} className="px-4 py-3.5 text-left text-xs font-mono uppercase tracking-wider" style={{ color: "#8892b0" }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {usersLoading ? (
                Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid rgba(26,37,64,0.5)" }}>
                    {Array.from({ length: 7 }).map((_, j) => (
                      <td key={j} className="px-4 py-3.5">
                        <div className="h-3 bg-cyber-border rounded animate-pulse" style={{ width: `${40 + j * 8}%` }} />
                      </td>
                    ))}
                  </tr>
                ))
              ) : !usersData?.items?.length ? (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center font-mono text-sm" style={{ color: "#8892b0" }}>
                    No users found.
                  </td>
                </tr>
              ) : (
                usersData.items.map((user: any) => (
                  <motion.tr
                    key={user.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    style={{ borderBottom: "1px solid rgba(26,37,64,0.4)" }}
                    className="hover:bg-white/[0.015] transition-colors"
                  >
                    {/* User */}
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-2.5">
                        <div
                          className="w-7 h-7 rounded-full flex items-center justify-center border text-xs font-bold font-mono shrink-0"
                          style={{ background: "rgba(0,245,255,0.08)", borderColor: "rgba(0,245,255,0.2)", color: "#00f5ff" }}
                        >
                          {user.username?.[0]?.toUpperCase()}
                        </div>
                        <span className="text-xs font-mono" style={{ color: "#e8eaf0" }}>{user.username}</span>
                      </div>
                    </td>
                    {/* Email */}
                    <td className="px-4 py-3.5 text-xs font-mono" style={{ color: "#8892b0" }}>
                      {user.email}
                    </td>
                    {/* Role */}
                    <td className="px-4 py-3.5">
                      <select
                        value={user.role}
                        onChange={(e) => roleUpdate.mutate({ userId: user.id, role: e.target.value })}
                        className="text-xs font-mono bg-cyber-dark border border-cyber-border rounded px-2 py-1 outline-none focus:border-neon-cyan/40 cursor-pointer"
                        style={{ color: "#e8eaf0" }}
                      >
                        <option value="user">user</option>
                        <option value="analyst">analyst</option>
                        <option value="admin">admin</option>
                      </select>
                    </td>
                    {/* Status */}
                    <td className="px-4 py-3.5">
                      <span
                        className="text-xs font-mono px-2 py-0.5 rounded-full border"
                        style={
                          user.is_active
                            ? { background: "rgba(0,255,136,0.08)", color: "#00ff88", borderColor: "rgba(0,255,136,0.25)" }
                            : { background: "rgba(255,45,85,0.08)",  color: "#ff2d55", borderColor: "rgba(255,45,85,0.25)"  }
                        }
                      >
                        {user.is_active ? "Active" : "Disabled"}
                      </span>
                    </td>
                    {/* Last login */}
                    <td className="px-4 py-3.5 text-xs font-mono" style={{ color: "#8892b0" }}>
                      {user.last_login ? new Date(user.last_login).toLocaleDateString() : "Never"}
                    </td>
                    {/* Joined */}
                    <td className="px-4 py-3.5 text-xs font-mono" style={{ color: "#8892b0" }}>
                      {new Date(user.created_at).toLocaleDateString()}
                    </td>
                    {/* Actions */}
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-1.5">
                        {/* Toggle */}
                        <button
                          onClick={() => toggleUser.mutate(user.id)}
                          title={user.is_active ? "Disable account" : "Enable account"}
                          className="p-1.5 rounded-lg border transition-all hover:opacity-80"
                          style={
                            user.is_active
                              ? { borderColor: "rgba(255,45,85,0.3)",  color: "#ff2d55",  background: "rgba(255,45,85,0.06)" }
                              : { borderColor: "rgba(0,255,136,0.3)",  color: "#00ff88",  background: "rgba(0,255,136,0.06)" }
                          }
                        >
                          {user.is_active ? <UserX className="w-3.5 h-3.5" /> : <UserCheck className="w-3.5 h-3.5" />}
                        </button>
                        {/* Reset password */}
                        <button
                          onClick={() => setResetTarget(user)}
                          title="Reset password"
                          className="p-1.5 rounded-lg border transition-all hover:opacity-80"
                          style={{ borderColor: "rgba(255,214,10,0.3)", color: "#ffd60a", background: "rgba(255,214,10,0.06)" }}
                        >
                          <Key className="w-3.5 h-3.5" />
                        </button>
                        {/* Delete */}
                        <button
                          onClick={() => setDeleteConfirm(user.id)}
                          title="Delete user"
                          className="p-1.5 rounded-lg border transition-all hover:opacity-80"
                          style={{ borderColor: "rgba(255,45,85,0.2)", color: "#ff2d55", background: "rgba(255,45,85,0.04)" }}
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </motion.tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="p-2 rounded-lg border border-cyber-border disabled:opacity-30 transition-all hover:border-neon-cyan/30"
            style={{ color: "#8892b0" }}
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="font-mono text-xs" style={{ color: "#8892b0" }}>
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="p-2 rounded-lg border border-cyber-border disabled:opacity-30 transition-all hover:border-neon-cyan/30"
            style={{ color: "#8892b0" }}
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Delete confirm inline */}
      <AnimatePresence>
        {deleteConfirm && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            style={{ background: "rgba(5,8,16,0.85)", backdropFilter: "blur(6px)" }}
          >
            <motion.div
              initial={{ scale: 0.92 }} animate={{ scale: 1 }} exit={{ scale: 0.92 }}
              className="cyber-card p-6 w-full max-w-sm"
              style={{ borderColor: "rgba(255,45,85,0.3)" }}
            >
              <div className="flex items-center gap-3 mb-4">
                <div className="w-9 h-9 rounded-lg flex items-center justify-center border" style={{ background: "rgba(255,45,85,0.1)", borderColor: "rgba(255,45,85,0.3)" }}>
                  <Trash2 className="w-4 h-4" style={{ color: "#ff2d55" }} />
                </div>
                <div>
                  <h3 className="font-display font-bold" style={{ color: "#e8eaf0" }}>Delete User</h3>
                  <p className="font-mono text-xs" style={{ color: "#8892b0" }}>This action cannot be undone</p>
                </div>
              </div>
              <p className="font-mono text-sm mb-5" style={{ color: "#8892b0" }}>
                All scans, files and data belonging to this user will also be permanently deleted.
              </p>
              <div className="flex gap-3">
                <button
                  onClick={() => setDeleteConfirm(null)}
                  className="flex-1 py-2.5 rounded-lg border font-mono text-sm"
                  style={{ borderColor: "#1a2540", color: "#8892b0" }}
                >
                  Cancel
                </button>
                <button
                  onClick={() => deleteUser.mutate(deleteConfirm)}
                  disabled={deleteUser.isPending}
                  className="flex-1 py-2.5 rounded-lg font-mono text-sm font-medium disabled:opacity-40"
                  style={{ background: "rgba(255,45,85,0.15)", border: "1px solid rgba(255,45,85,0.4)", color: "#ff2d55" }}
                >
                  {deleteUser.isPending ? "Deleting…" : "Delete"}
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Create user modal */}
      <AnimatePresence>
        {showCreate && (
          <CreateUserModal
            onClose={() => setShowCreate(false)}
            onCreated={() => { qc.invalidateQueries({ queryKey: ["admin-users"] }); qc.invalidateQueries({ queryKey: ["admin-stats"] }); }}
          />
        )}
      </AnimatePresence>

      {/* Reset password modal */}
      <AnimatePresence>
        {resetTarget && (
          <ResetPasswordModal user={resetTarget} onClose={() => setResetTarget(null)} />
        )}
      </AnimatePresence>
    </div>
  );
}

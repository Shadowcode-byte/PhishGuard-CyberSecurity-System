import axios from "axios";

// ✅ Clean base URL (remove trailing slash if exists)
const BASE_URL = (process.env.NEXT_PUBLIC_API_URL ?? "").replace(/\/$/, "");

export const api = axios.create({
  baseURL: BASE_URL,
  headers: { "Content-Type": "application/json" },
  withCredentials: false,
});

// ─────────────────────────────────────────
// Request interceptor — attach token
// ─────────────────────────────────────────

api.interceptors.request.use((config) => {
  const token =
    typeof window !== "undefined"
      ? localStorage.getItem("access_token")
      : null;

  if (token) {
    config.headers = config.headers ?? {};
    config.headers.Authorization = `Bearer ${token}`;
  }

  return config;
});

// ─────────────────────────────────────────
// Response interceptor — refresh token
// ─────────────────────────────────────────

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const refreshToken = localStorage.getItem("refresh_token");
        if (!refreshToken) throw new Error("No refresh token");

        const { data } = await axios.post(
          `${BASE_URL}/api/v1/auth/refresh`,
          { refresh_token: refreshToken }
        );

        localStorage.setItem("access_token", data.access_token);
        localStorage.setItem("refresh_token", data.refresh_token);

        originalRequest.headers = originalRequest.headers ?? {};
        originalRequest.headers.Authorization = `Bearer ${data.access_token}`;

        return api(originalRequest);
      } catch (_) {
        localStorage.clear();
        window.location.href = "/auth/login";
      }
    }

    return Promise.reject(error);
  }
);

// ─────────────────────────────────────────
// Auth
// ─────────────────────────────────────────

export const authApi = {
  register: (data: {
    email: string;
    username: string;
    password: string;
    terms_accepted: boolean;
  }) =>
    api.post("/api/v1/auth/register", data),

  login: (data: { email: string; password: string }) =>
    api.post("/api/v1/auth/login", {
      email: data.email,
      password: data.password,
    }),

  refresh: (refresh_token: string) =>
    api.post("/api/v1/auth/refresh", { refresh_token }),

  me: () => api.get("/api/v1/auth/me"),
};

// ─────────────────────────────────────────
// Scans
// ─────────────────────────────────────────

export const scanApi = {
  url: (url: string) =>
    api.post("/api/v1/scan/url", { url }),

  message: (message: string) =>
    api.post("/api/v1/scan/message", { message }),

  file: (file: File) => {
    const fd = new FormData();
    fd.append("file", file);

    return api.post("/api/v1/scan/file", fd, {
      headers: { "Content-Type": undefined },
    });
  },

  fileStatus: (fileId: string) =>
    api.get(`/api/v1/scan/file/${fileId}/status`),
};

// ─────────────────────────────────────────
// User
// ─────────────────────────────────────────

export const userApi = {
  history: (page = 1, per_page = 20, scan_type?: string) => {
    const params: Record<string, unknown> = { page, per_page };
    if (scan_type) params.scan_type = scan_type;

    return api.get("/api/v1/user/history", { params });
  },

  profile: () => api.get("/api/v1/user/profile"),
  stats: () => api.get("/api/v1/user/stats"),
};

// ─────────────────────────────────────────
// Threat Detection
// ─────────────────────────────────────────

export const threatApi = {
  analyze: (domain: string, port?: number, ip?: string) =>
    api.post("/api/v1/threat/analyze", { domain, port, ip }),

  networkScan: () =>
    api.get("/api/v1/threat/network-scan"),
};

// ─────────────────────────────────────────
// Admin
// ─────────────────────────────────────────

export const adminApi = {
  stats: () => api.get("/api/v1/admin/stats"),

  users: (page = 1, per_page = 20, params?: Record<string, unknown>) =>
    api.get("/api/v1/admin/users", {
      params: { page, per_page, ...params },
    }),

  createUser: (data: {
    email: string;
    username: string;
    password: string;
    role: string;
  }) =>
    api.post("/api/v1/admin/users", data),

  deleteUser: (userId: string) =>
    api.delete(`/api/v1/admin/users/${userId}`),

  updateRole: (userId: string, role: string) =>
    api.patch(`/api/v1/admin/users/${userId}/role`, { role }),

  toggleUser: (userId: string) =>
    api.patch(`/api/v1/admin/users/${userId}/toggle`),

  resetPassword: (userId: string, new_password: string) =>
    api.post(`/api/v1/admin/users/${userId}/reset-password`, {
      new_password,
    }),

  logs: (page = 1, params?: Record<string, unknown>) =>
    api.get("/api/v1/admin/logs", {
      params: { page, per_page: 50, ...params },
    }),

  scans: (page = 1, label?: string) => {
    const params: Record<string, unknown> = { page };
    if (label) params.label = label;

    return api.get("/api/v1/admin/scans", { params });
  },
};

// ─────────────────────────────────────────
// Agent
// ─────────────────────────────────────────

export const agentApi = {
  list: () => api.get("/api/v1/agent"),
  status: (agentId: string) =>
    api.get(`/api/v1/agent/${agentId}/status`),
};
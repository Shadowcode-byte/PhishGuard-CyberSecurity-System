import { create } from "zustand";
import { authApi } from "./api";

interface User {
  id: string;
  email: string;
  username: string;
  role: string;
  created_at: string;
}

interface AuthState {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  // FIX: Added termsAccepted parameter to register signature
  register: (email: string, username: string, password: string, termsAccepted: boolean) => Promise<void>;
  logout: () => void;
  fetchUser: () => Promise<void>;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isLoading: false,
  isAuthenticated: false,

  login: async (email, password) => {
    set({ isLoading: true, isAuthenticated: false });
    try {
      const { data } = await authApi.login({ email, password });

      // Persist tokens BEFORE calling /auth/me so the request interceptor
      // can attach the Authorization header on that immediately-following call.
      localStorage.setItem("access_token", data.access_token);
      localStorage.setItem("refresh_token", data.refresh_token);

      const { data: user } = await authApi.me();
      set({ user, isAuthenticated: true, isLoading: false });
    } catch (err) {
      // Clean up any partial state
      localStorage.removeItem("access_token");
      localStorage.removeItem("refresh_token");
      set({ user: null, isAuthenticated: false, isLoading: false });
      // Re-throw so the login page catch block can read err.response.data.detail
      throw err;
    }
  },

  // FIX: Accept and forward termsAccepted to the API call
  register: async (email, username, password, termsAccepted) => {
    set({ isLoading: true });
    try {
      await authApi.register({ email, username, password, terms_accepted: termsAccepted });
    } finally {
      set({ isLoading: false });
    }
  },

  logout: () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    set({ user: null, isAuthenticated: false });
  },

  fetchUser: async () => {
    const token = localStorage.getItem("access_token");
    if (!token) return;
    try {
      const { data } = await authApi.me();
      set({ user: data, isAuthenticated: true });
    } catch {
      localStorage.removeItem("access_token");
      localStorage.removeItem("refresh_token");
      set({ user: null, isAuthenticated: false });
    }
  },
}));

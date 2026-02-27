/**
 * AuthContext — JWT authentication state for Shadow AI Hunter
 *
 * Provides:
 *   user         — decoded user profile (username, role, email, …) or null
 *   api          — axios instance with Bearer token auto-attached
 *   login()      — POST /api/auth/login, store token, fetch /api/auth/me
 *   logout()     — clear token + user state
 *   loading      — true while validating a stored token on mount
 *   isAuthenticated — shorthand for !!user
 */

import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
} from 'react';
import axios from 'axios';

const API_BASE_URL =
  process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

export const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true); // true while validating stored token

  // Single stable axios instance — never recreated across renders
  const apiRef = useRef(
    axios.create({ baseURL: API_BASE_URL, timeout: 15000 })
  );
  const api = apiRef.current;

  const logout = useCallback(() => {
    localStorage.removeItem('shadow_ai_token');
    setUser(null);
  }, []);

  // ── Interceptors ─────────────────────────────────────────────────────────
  useEffect(() => {
    // Attach token to every outgoing request
    const reqId = api.interceptors.request.use((config) => {
      const token = localStorage.getItem('shadow_ai_token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // Auto-logout on 401 (skip the auth endpoints themselves to avoid loops)
    const resId = api.interceptors.response.use(
      (response) => response,
      (error) => {
        const isAuthEndpoint = error.config?.url?.includes('/api/auth/');
        if (error.response?.status === 401 && !isAuthEndpoint) {
          logout();
        }
        return Promise.reject(error);
      }
    );

    return () => {
      api.interceptors.request.eject(reqId);
      api.interceptors.response.eject(resId);
    };
  }, [api, logout]);

  // ── Login ─────────────────────────────────────────────────────────────────
  const login = async (username, password) => {
    // FastAPI's OAuth2PasswordRequestForm expects form-encoded data
    const body = new URLSearchParams();
    body.append('username', username);
    body.append('password', password);

    const tokenRes = await axios.post(`${API_BASE_URL}/api/auth/login`, body);
    const { access_token } = tokenRes.data;
    localStorage.setItem('shadow_ai_token', access_token);

    // Fetch full user profile with the new token
    const meRes = await axios.get(`${API_BASE_URL}/api/auth/me`, {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    setUser(meRes.data);
    return meRes.data;
  };

  // ── Validate stored token on mount ────────────────────────────────────────
  useEffect(() => {
    const validate = async () => {
      const token = localStorage.getItem('shadow_ai_token');
      if (!token) {
        setLoading(false);
        return;
      }
      try {
        const res = await axios.get(`${API_BASE_URL}/api/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
          timeout: 5000,
        });
        setUser(res.data);
      } catch {
        // Token expired or invalid — clear it silently
        localStorage.removeItem('shadow_ai_token');
      } finally {
        setLoading(false);
      }
    };
    validate();
  }, []);

  return (
    <AuthContext.Provider
      value={{ user, api, login, logout, loading, isAuthenticated: !!user }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}

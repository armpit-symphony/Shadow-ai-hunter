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
    axios.create({ baseURL: API_BASE_URL, timeout: 15000, withCredentials: true })
  );
  const api = apiRef.current;

  const getCookie = (name) => {
    const match = document.cookie.match(new RegExp(`(^| )${name}=([^;]+)`));
    return match ? decodeURIComponent(match[2]) : '';
  };

  const logout = useCallback(() => {
    api.post('/api/auth/logout').catch(() => {});
    setUser(null);
  }, [api]);

  // ── Interceptors ─────────────────────────────────────────────────────────
  useEffect(() => {
    // Attach token to every outgoing request
    const reqId = api.interceptors.request.use((config) => {
      const method = (config.method || 'get').toLowerCase();
      if (['post', 'put', 'patch', 'delete'].includes(method)) {
        const csrf = getCookie('csrf_token');
        if (csrf) {
          config.headers['X-CSRF-Token'] = csrf;
        }
      }
      return config;
    });

    // Auto-logout on 401 (skip the auth endpoints themselves to avoid loops)
    let refreshing = false;
    const resId = api.interceptors.response.use(
      (response) => response,
      async (error) => {
        const isAuthEndpoint = error.config?.url?.includes('/api/auth/');
        if (error.response?.status === 401 && !isAuthEndpoint && !refreshing) {
          try {
            refreshing = true;
            await api.post('/api/auth/refresh');
            refreshing = false;
            return api.request(error.config);
          } catch {
            refreshing = false;
            logout();
          }
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

    await api.post('/api/auth/login', body);
    const meRes = await api.get('/api/auth/me');
    setUser(meRes.data);
    return meRes.data;
  };

  // ── Validate stored token on mount ────────────────────────────────────────
  useEffect(() => {
    const validate = async () => {
      try {
        const res = await api.get('/api/auth/me', { timeout: 5000 });
        setUser(res.data);
      } catch {
        // Token expired or invalid — clear state
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

import React, { useState, useEffect, useCallback } from 'react';
import { smartCreateScan, smartListScans, smartGetScan, getReport } from './services/api';
import {
  Shield, Activity, AlertTriangle, Search, Lock,
  Network, Zap, TrendingUp, BarChart3, LogOut,
  User, ChevronDown, ChevronUp, RefreshCw, Plus,
  CheckCircle, XCircle, Eye, EyeOff, Clock,
  FileText, Terminal, Wifi,
} from 'lucide-react';
import { AuthProvider, useAuth } from './AuthContext';

// ─────────────────────────────────────────────────────────────────────────────
// Root — wraps everything in AuthProvider then decides Login vs App
// ─────────────────────────────────────────────────────────────────────────────

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

function AppContent() {
  const { isAuthenticated, loading } = useAuth();

  if (loading) return <LoadingScreen />;
  if (!isAuthenticated) return <LoginPage />;
  return <ProtectedLayout />;
}

// ─────────────────────────────────────────────────────────────────────────────
// Loading screen (shown while validating stored token on mount)
// ─────────────────────────────────────────────────────────────────────────────

function LoadingScreen() {
  return (
    <div className="min-h-screen flex items-center justify-center"
      style={{ background: 'linear-gradient(135deg, #1e1b4b 0%, #312e81 50%, #4c1d95 100%)' }}>
      <div className="text-center text-white">
        <Shield className="w-16 h-16 mx-auto mb-4 animate-pulse" />
        <p className="text-lg font-medium opacity-80">Loading Shadow AI Hunter…</p>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Login Page
// ─────────────────────────────────────────────────────────────────────────────

function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError('Username and password are required.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await login(username.trim(), password);
    } catch (err) {
      const detail = err?.response?.data?.detail;
      setError(
        detail === 'Incorrect username or password'
          ? 'Incorrect username or password. Check your credentials.'
          : detail || 'Login failed. Is the backend running?'
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="min-h-screen flex items-center justify-center px-4"
      style={{ background: 'linear-gradient(135deg, #1e1b4b 0%, #312e81 50%, #4c1d95 100%)' }}
    >
      {/* Decorative blobs */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-96 h-96 rounded-full opacity-10"
          style={{ background: 'radial-gradient(circle, #7c3aed, transparent)' }} />
        <div className="absolute -bottom-40 -left-40 w-96 h-96 rounded-full opacity-10"
          style={{ background: 'radial-gradient(circle, #2563eb, transparent)' }} />
      </div>

      <div className="relative w-full max-w-md">
        {/* Brand header */}
        <div className="text-center mb-8">
          <div className="w-20 h-20 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-2xl"
            style={{ background: 'linear-gradient(135deg, #7c3aed, #2563eb)' }}>
            <Shield className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Shadow AI Hunter</h1>
          <p className="text-indigo-200 mt-2 text-sm">Enterprise AI Detection Platform</p>
        </div>

        {/* Card */}
        <div className="bg-white rounded-2xl shadow-2xl p-8">
          <h2 className="text-xl font-bold text-gray-900 mb-6">Sign in to your account</h2>

          {error && (
            <div className="mb-4 p-3 rounded-lg bg-red-50 border border-red-200 flex items-start gap-2">
              <XCircle className="w-4 h-4 text-red-500 mt-0.5 shrink-0" />
              <p className="text-sm text-red-700">{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Username
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin"
                  autoComplete="username"
                  autoFocus
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg text-sm
                    focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent
                    transition-colors"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete="current-password"
                  className="w-full pl-10 pr-10 py-3 border border-gray-300 rounded-lg text-sm
                    focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent
                    transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full py-3 px-4 rounded-lg font-semibold text-white text-sm
                transition-all focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500
                disabled:opacity-60 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              style={{ background: submitting ? '#6366f1' : 'linear-gradient(135deg, #6366f1, #4f46e5)' }}
            >
              {submitting ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Signing in…
                </>
              ) : (
                'Sign In'
              )}
            </button>
          </form>

          <div className="mt-6 p-3 rounded-lg bg-amber-50 border border-amber-200">
            <p className="text-xs text-amber-700 text-center">
              Default credentials are set via <code className="font-mono bg-amber-100 px-1 rounded">DEFAULT_ADMIN_PASSWORD</code> env var.
              Change before production use.
            </p>
          </div>
        </div>

        <p className="text-center text-indigo-300 text-xs mt-6">
          Shadow AI Hunter v2.0 · Enterprise Edition
        </p>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Protected layout — sidebar + page content
// ─────────────────────────────────────────────────────────────────────────────

const NAV_ITEMS = [
  { id: 'dashboard',  label: 'Dashboard',     icon: BarChart3 },
  { id: 'devices',    label: 'Devices',        icon: Network },
  { id: 'alerts',     label: 'Alerts',         icon: AlertTriangle },
  { id: 'policies',   label: 'Policies',       icon: Lock },
  { id: 'scan',       label: 'Audit',          icon: Search },
];

function ProtectedLayout() {
  const [page, setPage] = useState('dashboard');
  const { user } = useAuth();
  const adminNav = [
    { id: 'lists',     label: 'Allow/Deny Lists', icon: FileText },
    { id: 'users',     label: 'User Management',  icon: User },
    { id: 'adminops',  label: 'Admin Ops',        icon: Shield },
  ];
  const analystNav = [
    { id: 'baselines', label: 'Baselines',        icon: Terminal },
  ];
  const navItems = user?.role === 'admin'
    ? [...NAV_ITEMS, ...analystNav, ...adminNav]
    : user?.role === 'analyst'
      ? [...NAV_ITEMS, ...analystNav]
      : NAV_ITEMS;

  const renderPage = () => {
    switch (page) {
      case 'dashboard': return <Dashboard />;
      case 'devices':   return <DevicesPage />;
      case 'alerts':    return <AlertsPage />;
      case 'policies':  return <PoliciesPage />;
      case 'scan':      return <ScanPage />;
      case 'scan_detail': return <ScanDetailPage />;
      case 'baselines': return <BaselinesPage />;
      case 'lists':     return <ListsPage />;
      case 'users':     return <UsersPage />;
      case 'adminops':  return <AdminOpsPage />;
      default:          return <Dashboard />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex">
      <Sidebar page={page} setPage={setPage} navItems={navItems} />
      <main className="flex-1 ml-64 p-8 overflow-auto">
        {renderPage()}
      </main>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sidebar
// ─────────────────────────────────────────────────────────────────────────────

function Sidebar({ page, setPage, navItems }) {
  const { user, logout } = useAuth();

  const roleBadgeColor = {
    admin:   'bg-red-100 text-red-700',
    analyst: 'bg-blue-100 text-blue-700',
    viewer:  'bg-gray-100 text-gray-700',
    worker:  'bg-green-100 text-green-700',
  }[user?.role] || 'bg-gray-100 text-gray-700';

  const initials = (user?.full_name || user?.username || '?')
    .split(' ')
    .map((w) => w[0])
    .join('')
    .toUpperCase()
    .slice(0, 2);

  return (
    <aside className="w-64 fixed left-0 top-0 h-full bg-white shadow-lg flex flex-col z-20">
      {/* Logo */}
      <div className="p-6 border-b border-gray-100">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
            style={{ background: 'linear-gradient(135deg, #6366f1, #4f46e5)' }}>
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div className="min-w-0">
            <p className="font-bold text-gray-900 text-sm leading-tight">Shadow AI Hunter</p>
            <p className="text-xs text-gray-500">Enterprise Detection</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4 overflow-y-auto">
        {navItems.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setPage(id)}
            className={`w-full flex items-center gap-3 px-6 py-3 text-sm font-medium transition-colors
              ${page === id
                ? 'bg-indigo-50 text-indigo-600 border-r-2 border-indigo-600'
                : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
              }`}
          >
            <Icon className="w-5 h-5 shrink-0" />
            {label}
          </button>
        ))}
      </nav>

      {/* User info + logout */}
      <div className="border-t border-gray-100 p-4">
        <div className="flex items-center gap-3 mb-3">
          <div className="w-9 h-9 rounded-full bg-indigo-600 flex items-center justify-center shrink-0">
            <span className="text-white text-xs font-bold">{initials}</span>
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-gray-900 truncate">
              {user?.full_name || user?.username}
            </p>
            <span className={`inline-block text-xs px-2 py-0.5 rounded-full font-medium ${roleBadgeColor}`}>
              {user?.role}
            </span>
          </div>
        </div>
        <button
          onClick={logout}
          className="w-full flex items-center gap-2 px-3 py-2 text-sm text-gray-600
            hover:bg-red-50 hover:text-red-600 rounded-lg transition-colors"
        >
          <LogOut className="w-4 h-4" />
          Sign out
        </button>
      </div>
    </aside>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared UI primitives
// ─────────────────────────────────────────────────────────────────────────────

function PageHeader({ title, subtitle, children }) {
  return (
    <div className="flex items-start justify-between mb-8">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">{title}</h1>
        {subtitle && <p className="text-gray-500 mt-1 text-sm">{subtitle}</p>}
      </div>
      {children && <div className="flex items-center gap-3">{children}</div>}
    </div>
  );
}

function Card({ children, className = '' }) {
  return (
    <div className={`bg-white rounded-xl shadow-sm border border-gray-100 ${className}`}>
      {children}
    </div>
  );
}

function Badge({ label, color = 'gray' }) {
  const classes = {
    red:    'bg-red-100 text-red-700',
    orange: 'bg-orange-100 text-orange-700',
    yellow: 'bg-yellow-100 text-yellow-700',
    green:  'bg-green-100 text-green-700',
    blue:   'bg-blue-100 text-blue-700',
    purple: 'bg-purple-100 text-purple-700',
    gray:   'bg-gray-100 text-gray-700',
  };
  return (
    <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium ${classes[color] || classes.gray}`}>
      {label}
    </span>
  );
}

function SeverityBadge({ severity }) {
  const map = {
    critical: { color: 'red',    label: 'Critical' },
    high:     { color: 'orange', label: 'High' },
    medium:   { color: 'yellow', label: 'Medium' },
    low:      { color: 'blue',   label: 'Low' },
  };
  const { color, label } = map[severity?.toLowerCase()] || { color: 'gray', label: severity };
  return <Badge label={label} color={color} />;
}

function RiskBadge({ score }) {
  if (score >= 0.8) return <Badge label="High Risk" color="red" />;
  if (score >= 0.5) return <Badge label="Med Risk" color="orange" />;
  return <Badge label="Low Risk" color="green" />;
}

function EmptyState({ icon: Icon, title, subtitle }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <Icon className="w-12 h-12 text-gray-300 mb-4" />
      <p className="text-gray-600 font-medium">{title}</p>
      {subtitle && <p className="text-gray-400 text-sm mt-1">{subtitle}</p>}
    </div>
  );
}

function Spinner() {
  return (
    <div className="flex items-center justify-center py-16">
      <RefreshCw className="w-8 h-8 text-indigo-400 animate-spin" />
    </div>
  );
}

function FilterTabs({ tabs, value, onChange }) {
  return (
    <div className="flex gap-1 bg-gray-100 p-1 rounded-lg">
      {tabs.map((tab) => (
        <button
          key={tab.value}
          onClick={() => onChange(tab.value)}
          className={`flex-1 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
            value === tab.value
              ? 'bg-white text-gray-900 shadow-sm'
              : 'text-gray-500 hover:text-gray-700'
          }`}
        >
          {tab.label}
          {tab.count != null && (
            <span className={`ml-1.5 px-1.5 py-0.5 rounded-full text-xs
              ${value === tab.value ? 'bg-indigo-100 text-indigo-700' : 'bg-gray-200 text-gray-600'}`}>
              {tab.count}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard
// ─────────────────────────────────────────────────────────────────────────────

function Dashboard() {
  const { api } = useAuth();
  const [stats, setStats] = useState(null);
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [quickTarget, setQuickTarget] = useState('');
  const [toast, setToast] = useState('');

  const showToast = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(''), 3000);
  };

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const [s, d, a] = await Promise.all([
        api.get('/api/dashboard/stats'),
        api.get('/api/devices'),
        api.get('/api/alerts'),
      ]);
      setStats(s.data);
      setDevices(d.data.devices || []);
      setAlerts(a.data.alerts || []);
    } catch (e) {
      console.error('Dashboard load error:', e);
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => { load(); }, [load]);

  const startScan = async (overrideTarget) => {
    const target = overrideTarget || quickTarget || '192.168.1.0/24';
    setScanning(true);
    try {
      await api.post('/api/scan', {
        network_range: target,
        scan_type: 'comprehensive',
        deep_scan: true,
      });
      showToast('Audit queued — results will appear shortly.');
      setTimeout(load, 5000);
    } catch {
      showToast('Audit failed. Check that the worker is running.');
    } finally {
      setScanning(false);
    }
  };

  const populateDemo = async () => {
    try {
      await api.get('/api/demo/populate');
      await load();
      showToast('Demo data loaded.');
    } catch {
      showToast('Could not load demo data (admin role required).');
    }
  };

  if (loading) return <Spinner />;

  const statCards = stats
    ? [
        { title: 'Total Devices',     value: stats.total_devices,     icon: Network,       color: '#6366f1' },
        { title: 'High Risk Devices', value: stats.high_risk_devices,  icon: AlertTriangle, color: '#ef4444' },
        { title: 'Active Threats',    value: stats.active_threats,     icon: Shield,        color: '#f97316' },
        { title: 'Compliance Score',  value: `${Math.round(stats.compliance_score * 100)}%`, icon: TrendingUp, color: '#22c55e' },
      ]
    : [];

  return (
    <div className="space-y-8">
      {toast && (
        <div className="fixed top-4 right-4 z-50 bg-gray-900 text-white px-4 py-2 rounded-lg shadow-lg text-sm">
          {toast}
        </div>
      )}

      <PageHeader title="Dashboard" subtitle="AI Risk Auditing Platform">
        <button onClick={populateDemo}
          className="px-4 py-2 text-sm font-medium text-green-700 bg-green-50 border border-green-200
            rounded-lg hover:bg-green-100 transition-colors">
          Seed Demo Data
        </button>
        <button onClick={startScan} disabled={scanning}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white rounded-lg
            transition-all disabled:opacity-60"
          style={{ background: 'linear-gradient(135deg, #6366f1, #4f46e5)' }}>
          {scanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          {scanning ? 'Auditing…' : 'Quick Audit'}
        </button>
      </PageHeader>

      {/* Quick Audit — hero input */}
      <div className="rounded-2xl p-6 text-white"
        style={{ background: 'linear-gradient(135deg, #1e1b4b 0%, #312e81 50%, #1e3a5f 100%)' }}>
        <div className="max-w-2xl mx-auto text-center">
          <h2 className="text-xl font-bold mb-1">Quick Audit</h2>
          <p className="text-indigo-200 text-sm mb-5">Enter a URL or repository to auto-detect AI services and surface risk findings instantly.</p>
          <form onSubmit={async (e) => {
            e.preventDefault();
            if (!quickTarget.trim()) return;
            setScanning(true);
            try {
              const target = quickTarget.trim();
              const isRepo = target.includes('github.com') || target.includes('gitlab.com');
              const r = await smartCreateScan({
                target_type: isRepo ? 'repo' : 'url',
                target_value: target,
                modules_enabled: ['target_scanner', 'ai_usage_detector'],
                job_name: `Quick Audit: ${target.slice(0, 60)}`,
              });
              const id = r.job_id || r.scan_id;
              setQuickTarget('');
              showToast(`Audit queued (${id?.slice(0, 8)}…) — results will appear in Audit History.`);
              setTimeout(load, 4000);
            } catch (err) {
              showToast(err?.response?.data?.detail || 'Audit failed. Check that the worker is running.');
            } finally {
              setScanning(false);
            }
          }}
            className="flex gap-3 max-w-xl mx-auto">
            <input
              type="text"
              value={quickTarget}
              onChange={(e) => setQuickTarget(e.target.value)}
              placeholder="https://github.com/user/repo  or  https://api.example.com"
              className="flex-1 px-4 py-3 rounded-xl text-gray-900 text-sm font-mono placeholder-gray-400
                focus:outline-none focus:ring-2 focus:ring-indigo-300"
            />
            <button type="submit"
              className="px-6 py-3 bg-white text-indigo-700 font-semibold text-sm rounded-xl
                hover:bg-indigo-50 transition-colors flex items-center gap-2 whitespace-nowrap">
              <Zap className="w-4 h-4" /> Run Audit
            </button>
          </form>
          <p className="text-indigo-300 text-xs mt-3">Auto-selects modules · Runs full AI service detection · Ready in minutes</p>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {statCards.map(({ title, value, icon: Icon, color }) => (
          <Card key={title} className="p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">{title}</p>
                <p className="text-3xl font-bold text-gray-900 mt-1">{value}</p>
              </div>
              <div className="w-12 h-12 rounded-xl flex items-center justify-center"
                style={{ backgroundColor: `${color}18` }}>
                <Icon className="w-6 h-6" style={{ color }} />
              </div>
            </div>
          </Card>
        ))}
      </div>

      {/* Two-column: devices + alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <div className="flex items-center justify-between p-5 border-b border-gray-100">
            <h2 className="font-semibold text-gray-900 flex items-center gap-2">
              <Network className="w-4 h-4 text-indigo-500" /> Network Devices
            </h2>
            <Badge label={`${devices.length} detected`} color="blue" />
          </div>
          <div className="divide-y divide-gray-50 max-h-80 overflow-y-auto">
            {devices.length === 0 ? (
              <EmptyState icon={Network} title="No devices yet" subtitle="Run a scan to discover devices." />
            ) : (
              devices.slice(0, 6).map((d, i) => <MiniDeviceRow key={i} device={d} />)
            )}
          </div>
        </Card>

        <Card>
          <div className="flex items-center justify-between p-5 border-b border-gray-100">
            <h2 className="font-semibold text-gray-900 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-orange-500" /> Recent Alerts
            </h2>
            <Badge label={`${alerts.filter((a) => !a.resolved).length} active`} color="red" />
          </div>
          <div className="divide-y divide-gray-50 max-h-80 overflow-y-auto">
            {alerts.length === 0 ? (
              <EmptyState icon={Shield} title="No alerts" subtitle="Your network looks clean." />
            ) : (
              alerts.slice(0, 6).map((a, i) => <MiniAlertRow key={i} alert={a} />)
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}

function MiniDeviceRow({ device }) {
  return (
    <div className="flex items-center justify-between px-5 py-3 hover:bg-gray-50">
      <div className="flex items-center gap-3 min-w-0">
        <div className="w-2 h-2 rounded-full bg-green-400 shrink-0" />
        <div className="min-w-0">
          <p className="text-sm font-medium text-gray-900 truncate">
            {device.hostname || device.ip_address}
          </p>
          <p className="text-xs text-gray-500">{device.ip_address}</p>
        </div>
      </div>
      <div className="flex items-center gap-2 shrink-0 ml-2">
        {device.ai_services_detected?.length > 0 && (
          <Badge label={`${device.ai_services_detected.length} AI`} color="purple" />
        )}
        <RiskBadge score={device.ai_risk_score} />
      </div>
    </div>
  );
}

function MiniAlertRow({ alert }) {
  const colors = { critical: 'red', high: 'orange', medium: 'yellow', low: 'blue' };
  const dot = { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-400', low: 'bg-blue-400' };
  return (
    <div className="px-5 py-3 hover:bg-gray-50">
      <div className="flex items-start gap-2">
        <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${dot[alert.severity] || 'bg-gray-400'}`} />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-gray-900 truncate">{alert.title}</p>
          <p className="text-xs text-gray-500">{alert.device_ip}</p>
        </div>
        <SeverityBadge severity={alert.severity} />
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Devices Page
// ─────────────────────────────────────────────────────────────────────────────

function DevicesPage() {
  const { api } = useAuth();
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState(null);

  useEffect(() => {
    api.get('/api/devices')
      .then((r) => setDevices(r.data.devices || []))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [api]);

  const counts = {
    all:    devices.length,
    high:   devices.filter((d) => d.ai_risk_score >= 0.8).length,
    medium: devices.filter((d) => d.ai_risk_score >= 0.5 && d.ai_risk_score < 0.8).length,
    low:    devices.filter((d) => d.ai_risk_score < 0.5).length,
  };

  const visible = devices
    .filter((d) => {
      if (filter === 'high')   return d.ai_risk_score >= 0.8;
      if (filter === 'medium') return d.ai_risk_score >= 0.5 && d.ai_risk_score < 0.8;
      if (filter === 'low')    return d.ai_risk_score < 0.5;
      return true;
    })
    .filter((d) => {
      if (!search) return true;
      const q = search.toLowerCase();
      return (
        d.ip_address?.toLowerCase().includes(q) ||
        d.hostname?.toLowerCase().includes(q) ||
        d.device_type?.toLowerCase().includes(q) ||
        d.ai_services_detected?.some((s) => s.toLowerCase().includes(q))
      );
    });

  const tabs = [
    { value: 'all',    label: 'All',     count: counts.all },
    { value: 'high',   label: 'High',    count: counts.high },
    { value: 'medium', label: 'Medium',  count: counts.medium },
    { value: 'low',    label: 'Low',     count: counts.low },
  ];

  return (
    <div>
      <PageHeader title="Devices" subtitle="All network devices with AI risk assessment" />

      <div className="flex flex-wrap items-center gap-4 mb-6">
        <div className="flex-1 min-w-48">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by IP, hostname, service…"
              className="w-full pl-9 pr-4 py-2 border border-gray-200 rounded-lg text-sm
                focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>
        </div>
        <FilterTabs tabs={tabs} value={filter} onChange={setFilter} />
      </div>

      {loading ? <Spinner /> : (
        <div className="space-y-3">
          {visible.length === 0 ? (
            <Card className="p-4">
              <EmptyState icon={Network} title="No devices match" subtitle="Try adjusting your filters." />
            </Card>
          ) : (
            visible.map((device, i) => (
              <DeviceRow
                key={i}
                device={device}
                expanded={expanded === i}
                onToggle={() => setExpanded(expanded === i ? null : i)}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
}

function DeviceRow({ device, expanded, onToggle }) {
  const borderColor = device.ai_risk_score >= 0.8
    ? 'border-red-200'
    : device.ai_risk_score >= 0.5
    ? 'border-orange-200'
    : 'border-green-200';

  return (
    <Card className={`border-l-4 ${borderColor} overflow-hidden`}>
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between p-4 text-left hover:bg-gray-50 transition-colors"
      >
        <div className="flex items-center gap-4 min-w-0">
          <div className="w-2 h-2 rounded-full bg-green-400 shrink-0" />
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-semibold text-gray-900">
                {device.hostname || device.ip_address}
              </span>
              {device.hostname && (
                <span className="text-gray-500 text-sm">{device.ip_address}</span>
              )}
              <Badge label={device.device_type} color="gray" />
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0 ml-4">
          {device.ai_services_detected?.length > 0 && (
            <Badge label={`${device.ai_services_detected.length} AI service${device.ai_services_detected.length > 1 ? 's' : ''}`} color="purple" />
          )}
          <RiskBadge score={device.ai_risk_score} />
          <span className="text-sm font-medium text-gray-500 w-10 text-right">
            {Math.round(device.ai_risk_score * 100)}%
          </span>
          {expanded ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-gray-100 p-4 bg-gray-50 space-y-4">
          {/* AI Services */}
          {device.ai_services_detected?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
                Detected AI Services
              </p>
              <div className="flex flex-wrap gap-2">
                {device.ai_services_detected.map((svc, i) => (
                  <span key={i}
                    className="px-2 py-1 bg-purple-50 text-purple-700 border border-purple-200 rounded text-xs font-medium">
                    {svc}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Open ports */}
          {device.open_ports?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
                Open Ports
              </p>
              <div className="flex flex-wrap gap-1">
                {device.open_ports.map((p) => (
                  <code key={p} className="px-2 py-0.5 bg-gray-200 text-gray-700 rounded text-xs">{p}</code>
                ))}
              </div>
            </div>
          )}

          {/* Evidence bundle */}
          {device.evidence?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
                Evidence ({device.evidence.length} finding{device.evidence.length > 1 ? 's' : ''})
              </p>
              <div className="space-y-1">
                {device.evidence.map((ev, i) => (
                  <div key={i}
                    className="flex items-center gap-3 text-xs bg-white border border-gray-100 rounded px-3 py-2">
                    <SeverityBadge severity={ev.severity} />
                    <span className="text-gray-600 font-mono">{ev.type}</span>
                    {ev.service && <span className="text-gray-500">{ev.service}</span>}
                    {ev.port && <span className="text-gray-400">:{ev.port}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Last seen + scan ID */}
          <div className="flex flex-wrap gap-4 text-xs text-gray-400 pt-1">
            {device.last_seen && (
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3" />
                Last seen {new Date(device.last_seen).toLocaleString()}
              </span>
            )}
            {device.scan_id && (
              <span className="flex items-center gap-1">
                <Terminal className="w-3 h-3" />
                Scan {device.scan_id.slice(0, 8)}
              </span>
            )}
          </div>
        </div>
      )}
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Alerts Page
// ─────────────────────────────────────────────────────────────────────────────

function AlertsPage() {
  const { api, user } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [unresolvedOnly, setUnresolvedOnly] = useState(true);
  const [resolving, setResolving] = useState(null);
  const [toast, setToast] = useState('');

  const showToast = (msg) => { setToast(msg); setTimeout(() => setToast(''), 3000); };

  const load = useCallback(() => {
    setLoading(true);
    api.get('/api/alerts?limit=100')
      .then((r) => setAlerts(r.data.alerts || []))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [api]);

  useEffect(() => { load(); }, [load]);

  const resolve = async (alertId) => {
    if (!alertId) { showToast('Alert has no ID — cannot resolve.'); return; }
    setResolving(alertId);
    try {
      await api.patch(`/api/alerts/${alertId}/resolve`);
      setAlerts((prev) => prev.map((a) => a.id === alertId ? { ...a, resolved: true } : a));
      showToast('Alert resolved.');
    } catch {
      showToast('Could not resolve alert.');
    } finally {
      setResolving(null);
    }
  };

  const canResolve = ['admin', 'analyst'].includes(user?.role);

  const sevOrder = ['critical', 'high', 'medium', 'low'];
  const counts = Object.fromEntries(
    sevOrder.map((s) => [s, alerts.filter((a) => a.severity === s).length])
  );

  const visible = alerts
    .filter((a) => unresolvedOnly ? !a.resolved : true)
    .filter((a) => filter === 'all' || a.severity === filter)
    .sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));

  const tabs = [
    { value: 'all',      label: 'All',      count: alerts.length },
    { value: 'critical', label: 'Critical', count: counts.critical },
    { value: 'high',     label: 'High',     count: counts.high },
    { value: 'medium',   label: 'Medium',   count: counts.medium },
  ];

  return (
    <div>
      {toast && (
        <div className="fixed top-4 right-4 z-50 bg-gray-900 text-white px-4 py-2 rounded-lg shadow-lg text-sm">
          {toast}
        </div>
      )}

      <PageHeader title="Alerts" subtitle={`${alerts.filter((a) => !a.resolved).length} unresolved alerts`}>
        <button onClick={load}
          className="flex items-center gap-2 px-3 py-2 text-sm text-gray-600 border border-gray-200
            rounded-lg hover:bg-gray-50 transition-colors">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </PageHeader>

      <div className="flex flex-wrap items-center gap-4 mb-6">
        <FilterTabs tabs={tabs} value={filter} onChange={setFilter} />
        <label className="flex items-center gap-2 text-sm text-gray-600 cursor-pointer">
          <input
            type="checkbox"
            checked={unresolvedOnly}
            onChange={(e) => setUnresolvedOnly(e.target.checked)}
            className="rounded"
          />
          Unresolved only
        </label>
      </div>

      {loading ? <Spinner /> : (
        <div className="space-y-3">
          {visible.length === 0 ? (
            <Card className="p-4">
              <EmptyState icon={CheckCircle} title="No alerts match" subtitle="All clear!" />
            </Card>
          ) : (
            visible.map((alert, i) => (
              <AlertRow
                key={i}
                alert={alert}
                canResolve={canResolve && !alert.resolved}
                resolving={resolving === alert.id}
                onResolve={() => resolve(alert.id)}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
}

function AlertRow({ alert, canResolve, resolving, onResolve }) {
  const [expanded, setExpanded] = useState(false);
  const borderColor = {
    critical: 'border-red-400', high: 'border-orange-400',
    medium: 'border-yellow-400', low: 'border-blue-400',
  }[alert.severity] || 'border-gray-300';

  return (
    <Card className={`border-l-4 ${borderColor} ${alert.resolved ? 'opacity-60' : ''}`}>
      <div className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <SeverityBadge severity={alert.severity} />
              {alert.resolved && <Badge label="Resolved" color="green" />}
              <span className="text-xs text-gray-400">
                {alert.alert_type?.replace(/_/g, ' ')}
              </span>
            </div>
            <p className="font-semibold text-gray-900 text-sm">{alert.title}</p>
            <p className="text-sm text-gray-600 mt-1 line-clamp-2">{alert.description}</p>
            <div className="flex flex-wrap gap-3 mt-2 text-xs text-gray-400">
              <span>IP: {alert.device_ip}</span>
              {alert.created_at && <span>{new Date(alert.created_at).toLocaleString()}</span>}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {canResolve && (
              <button
                onClick={onResolve}
                disabled={resolving}
                className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium
                  text-green-700 bg-green-50 border border-green-200 rounded-lg
                  hover:bg-green-100 transition-colors disabled:opacity-50"
              >
                {resolving
                  ? <RefreshCw className="w-3 h-3 animate-spin" />
                  : <CheckCircle className="w-3 h-3" />}
                Resolve
              </button>
            )}
            {alert.evidence && (
              <button onClick={() => setExpanded((v) => !v)}
                className="text-gray-400 hover:text-gray-600 p-1">
                {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
            )}
          </div>
        </div>

        {expanded && alert.evidence && (
          <div className="mt-3 pt-3 border-t border-gray-100">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
              Evidence Bundle
            </p>
            {Array.isArray(alert.evidence) ? (
              <div className="space-y-1">
                {alert.evidence.map((ev, i) => (
                  <div key={i} className="flex items-center gap-3 text-xs bg-gray-50 rounded px-3 py-2">
                    <SeverityBadge severity={ev.severity} />
                    <code className="text-gray-600">{ev.type}</code>
                    {ev.indicator && <span className="text-gray-500">{ev.indicator}</span>}
                    {ev.port && <span className="text-gray-400">:{ev.port}</span>}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs font-mono space-y-1">
                {alert.evidence.evidence_hash && (
                  <p className="text-gray-400">Hash: <span className="text-gray-600">{alert.evidence.evidence_hash}</span></p>
                )}
                {alert.evidence.findings?.slice(0, 3).map((f, i) => (
                  <p key={i} className="text-gray-600">{f.type}: {f.indicator}</p>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Policies Page
// ─────────────────────────────────────────────────────────────────────────────

const RULE_TYPES = ['block', 'monitor', 'audit', 'allow'];
const ACTIONS = ['block_network', 'send_alert', 'log_activity', 'require_approval', 'quarantine'];

function PoliciesPage() {
  const { api, user } = useAuth();
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [toast, setToast] = useState('');

  const showToast = (msg) => { setToast(msg); setTimeout(() => setToast(''), 3000); };
  const canWrite = ['admin', 'analyst'].includes(user?.role);

  useEffect(() => {
    api.get('/api/policies')
      .then((r) => setPolicies(r.data.policies || []))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [api]);

  const handleCreate = async (data) => {
    try {
      await api.post('/api/policies', data);
      const r = await api.get('/api/policies');
      setPolicies(r.data.policies || []);
      setShowForm(false);
      showToast('Policy created.');
    } catch {
      showToast('Could not create policy.');
    }
  };

  return (
    <div>
      {toast && (
        <div className="fixed top-4 right-4 z-50 bg-gray-900 text-white px-4 py-2 rounded-lg shadow-lg text-sm">
          {toast}
        </div>
      )}

      <PageHeader title="Policies" subtitle="Security enforcement rules for AI service access">
        {canWrite && (
          <button
            onClick={() => setShowForm((v) => !v)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white rounded-lg transition-all"
            style={{ background: 'linear-gradient(135deg, #6366f1, #4f46e5)' }}
          >
            <Plus className="w-4 h-4" />
            New Policy
          </button>
        )}
      </PageHeader>

      {showForm && (
        <Card className="p-6 mb-6">
          <h3 className="font-semibold text-gray-900 mb-4">Create Policy</h3>
          <PolicyForm onSubmit={handleCreate} onCancel={() => setShowForm(false)} />
        </Card>
      )}

      {loading ? <Spinner /> : (
        <div className="space-y-3">
          {policies.length === 0 ? (
            <Card className="p-4">
              <EmptyState icon={Lock} title="No policies" subtitle="Create your first policy rule." />
            </Card>
          ) : (
            policies.map((p, i) => <PolicyRow key={i} policy={p} />)
          )}
        </div>
      )}
    </div>
  );
}

function PolicyForm({ onSubmit, onCancel }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [ruleType, setRuleType] = useState('monitor');
  const [selectedActions, setSelectedActions] = useState(['send_alert']);
  const [submitting, setSubmitting] = useState(false);

  const toggleAction = (a) =>
    setSelectedActions((prev) =>
      prev.includes(a) ? prev.filter((x) => x !== a) : [...prev, a]
    );

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!name.trim()) return;
    setSubmitting(true);
    await onSubmit({
      name: name.trim(),
      description: description.trim(),
      rule_type: ruleType,
      conditions: {},
      actions: selectedActions,
      enabled: true,
    });
    setSubmitting(false);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Name *</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Block External LLM APIs"
            required
            className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm
              focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Rule Type</label>
          <select
            value={ruleType}
            onChange={(e) => setRuleType(e.target.value)}
            className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm
              focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            {RULE_TYPES.map((t) => (
              <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>
            ))}
          </select>
        </div>
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
        <input
          type="text"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="What does this policy do?"
          className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm
            focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">Actions</label>
        <div className="flex flex-wrap gap-2">
          {ACTIONS.map((a) => (
            <button
              key={a}
              type="button"
              onClick={() => toggleAction(a)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
                selectedActions.includes(a)
                  ? 'bg-indigo-600 text-white border-indigo-600'
                  : 'text-gray-600 border-gray-200 hover:border-indigo-400'
              }`}
            >
              {a.replace(/_/g, ' ')}
            </button>
          ))}
        </div>
      </div>
      <div className="flex justify-end gap-3 pt-2">
        <button type="button" onClick={onCancel}
          className="px-4 py-2 text-sm text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-50">
          Cancel
        </button>
        <button type="submit" disabled={submitting || !name.trim()}
          className="px-4 py-2 text-sm font-medium text-white rounded-lg disabled:opacity-60"
          style={{ background: 'linear-gradient(135deg, #6366f1, #4f46e5)' }}>
          {submitting ? 'Creating…' : 'Create Policy'}
        </button>
      </div>
    </form>
  );
}

const ruleTypeColors = { block: 'red', monitor: 'orange', audit: 'blue', allow: 'green' };

function PolicyRow({ policy }) {
  return (
    <Card className="p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <Badge label={policy.rule_type} color={ruleTypeColors[policy.rule_type] || 'gray'} />
            {!policy.enabled && <Badge label="Disabled" color="gray" />}
          </div>
          <p className="font-semibold text-gray-900 text-sm">{policy.name}</p>
          {policy.description && (
            <p className="text-sm text-gray-500 mt-0.5">{policy.description}</p>
          )}
          {policy.actions?.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {policy.actions.map((a) => (
                <code key={a} className="px-2 py-0.5 bg-gray-100 text-gray-600 rounded text-xs">
                  {a}
                </code>
              ))}
            </div>
          )}
        </div>
        <div className={`w-2 h-2 rounded-full mt-2 shrink-0 ${policy.enabled ? 'bg-green-400' : 'bg-gray-300'}`} />
      </div>
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Allowlist / Denylist Page
// ─────────────────────────────────────────────────────────────────────────────

function ListsPage() {
  const { api } = useAuth();
  const [allowText, setAllowText] = useState('');
  const [denyText, setDenyText] = useState('');
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState('');

  const showToast = (msg) => { setToast(msg); setTimeout(() => setToast(''), 3000); };

  useEffect(() => {
    api.get('/api/lists')
      .then((r) => {
        setAllowText((r.data.allowlist || []).join('\n'));
        setDenyText((r.data.denylist || []).join('\n'));
      })
      .catch(() => showToast('Failed to load lists.'))
      .finally(() => setLoading(false));
  }, [api]);

  const parseLines = (text) =>
    text.split('\n').map((l) => l.trim()).filter(Boolean);

  const saveAllowlist = async () => {
    try {
      const items = parseLines(allowText);
      await api.put('/api/lists/allowlist', { items });
      showToast('Allowlist updated.');
    } catch (e) {
      const detail = e?.response?.data?.detail || 'Failed to update allowlist.';
      showToast(detail);
    }
  };

  const saveDenylist = async () => {
    try {
      const items = parseLines(denyText);
      await api.put('/api/lists/denylist', { items });
      showToast('Denylist updated.');
    } catch (e) {
      const detail = e?.response?.data?.detail || 'Failed to update denylist.';
      showToast(detail);
    }
  };

  return (
    <div>
      {toast && (
        <div className="fixed top-4 right-4 z-50 bg-gray-900 text-white px-4 py-2 rounded-lg shadow-lg text-sm">
          {toast}
        </div>
      )}

      <PageHeader title="Allowlist & Denylist" subtitle="Control AI service signatures per deployment" />

      {loading ? <Spinner /> : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="p-6">
            <h3 className="font-semibold text-gray-900 mb-2">Allowlist</h3>
            <p className="text-sm text-gray-500 mb-4">
              Domains here will be ignored by detection. One domain per line. Wildcards allowed: <code className="bg-gray-100 px-1 rounded">*.example.com</code>
            </p>
            <textarea
              value={allowText}
              onChange={(e) => setAllowText(e.target.value)}
              rows={10}
              className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm font-mono
                focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
            <div className="flex justify-end mt-4">
              <button
                onClick={saveAllowlist}
                className="px-4 py-2 text-sm font-medium text-white rounded-lg"
                style={{ background: 'linear-gradient(135deg, #6366f1, #4f46e5)' }}
              >
                Save Allowlist
              </button>
            </div>
          </Card>

          <Card className="p-6">
            <h3 className="font-semibold text-gray-900 mb-2">Denylist</h3>
            <p className="text-sm text-gray-500 mb-4">
              Domains here always generate critical alerts. One domain per line.
            </p>
            <textarea
              value={denyText}
              onChange={(e) => setDenyText(e.target.value)}
              rows={10}
              className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm font-mono
                focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
            <div className="flex justify-end mt-4">
              <button
                onClick={saveDenylist}
                className="px-4 py-2 text-sm font-medium text-white rounded-lg"
                style={{ background: 'linear-gradient(135deg, #ef4444, #dc2626)' }}
              >
                Save Denylist
              </button>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Users Page (admin)
// ─────────────────────────────────────────────────────────────────────────────

function UsersPage() {
  const { api, user: currentUser } = useAuth();
  const [users, setUsers] = useState([]);
  const [edits, setEdits] = useState({});
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState('');
  const [form, setForm] = useState({
    username: '',
    password: '',
    email: '',
    full_name: '',
    role: 'viewer',
    disabled: false,
  });

  const showToast = (msg) => { setToast(msg); setTimeout(() => setToast(''), 3000); };

  const loadUsers = useCallback(() => {
    setLoading(true);
    api.get('/api/users')
      .then((r) => setUsers(r.data.users || []))
      .catch(() => showToast('Failed to load users.'))
      .finally(() => setLoading(false));
  }, [api]);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  useEffect(() => {
    const next = {};
    users.forEach((u) => {
      next[u.id] = {
        email: u.email || '',
        full_name: u.full_name || '',
        role: u.role || 'viewer',
        disabled: !!u.disabled,
        password: '',
      };
    });
    setEdits(next);
  }, [users]);

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!form.username.trim() || !form.password.trim()) {
      showToast('Username and password are required.');
      return;
    }
    try {
      await api.post('/api/users', {
        username: form.username.trim(),
        password: form.password,
        email: form.email || undefined,
        full_name: form.full_name || undefined,
        role: form.role,
        disabled: form.disabled,
      });
      setForm({ username: '', password: '', email: '', full_name: '', role: 'viewer', disabled: false });
      showToast('User created.');
      loadUsers();
    } catch (e2) {
      const detail = e2?.response?.data?.detail || 'Failed to create user.';
      showToast(detail);
    }
  };

  const updateEdit = (id, patch) => {
    setEdits((prev) => ({ ...prev, [id]: { ...prev[id], ...patch } }));
  };

  const saveUser = async (u) => {
    const edit = edits[u.id];
    if (!edit) return;
    const payload = {};
    if (edit.email !== (u.email || '')) payload.email = edit.email;
    if (edit.full_name !== (u.full_name || '')) payload.full_name = edit.full_name;
    if (edit.role !== u.role) payload.role = edit.role;
    if (edit.disabled !== !!u.disabled) payload.disabled = edit.disabled;
    if (edit.password && edit.password.trim()) payload.password = edit.password.trim();
    if (Object.keys(payload).length === 0) {
      showToast('No changes to save.');
      return;
    }
    try {
      await api.patch(`/api/users/${u.id}`, payload);
      showToast('User updated.');
      loadUsers();
    } catch (e) {
      const detail = e?.response?.data?.detail || 'Failed to update user.';
      showToast(detail);
    }
  };

  return (
    <div>
      {toast && (
        <div className="fixed top-4 right-4 z-50 bg-gray-900 text-white px-4 py-2 rounded-lg shadow-lg text-sm">
          {toast}
        </div>
      )}

      <PageHeader title="User Management" subtitle="Create and manage platform users" />

      <Card className="p-6 mb-6">
        <h3 className="font-semibold text-gray-900 mb-4">Create User</h3>
        <form onSubmit={handleCreate} className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Username *</label>
            <input
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Password *</label>
            <input
              type="password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Full name</label>
            <input
              value={form.full_name}
              onChange={(e) => setForm({ ...form, full_name: e.target.value })}
              className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
            <input
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
              className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Role</label>
            <select
              value={form.role}
              onChange={(e) => setForm({ ...form, role: e.target.value })}
              className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
            >
              {['admin', 'analyst', 'viewer', 'worker'].map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-2 mt-6">
            <input
              type="checkbox"
              checked={form.disabled}
              onChange={(e) => setForm({ ...form, disabled: e.target.checked })}
            />
            <span className="text-sm text-gray-600">Disabled</span>
          </div>
          <div className="md:col-span-2 flex justify-end">
            <button
              type="submit"
              className="px-4 py-2 text-sm font-medium text-white rounded-lg"
              style={{ background: 'linear-gradient(135deg, #6366f1, #4f46e5)' }}
            >
              Create User
            </button>
          </div>
        </form>
      </Card>

      {loading ? <Spinner /> : (
        <Card className="p-4">
          {users.length === 0 ? (
            <EmptyState icon={User} title="No users" subtitle="Create the first user above." />
          ) : (
            <div className="space-y-4">
              {users.map((u) => {
                const edit = edits[u.id] || {};
                const isSelf = u.username === currentUser?.username;
                return (
                  <div key={u.id} className="grid grid-cols-1 md:grid-cols-6 gap-3 items-center">
                    <div className="md:col-span-1">
                      <p className="text-sm font-medium text-gray-900">{u.username}</p>
                      <p className="text-xs text-gray-500">{u.id.slice(-6)}</p>
                    </div>
                    <input
                      className="md:col-span-1 px-3 py-2 border border-gray-200 rounded-lg text-sm"
                      value={edit.full_name || ''}
                      onChange={(e) => updateEdit(u.id, { full_name: e.target.value })}
                      placeholder="Full name"
                    />
                    <input
                      className="md:col-span-1 px-3 py-2 border border-gray-200 rounded-lg text-sm"
                      value={edit.email || ''}
                      onChange={(e) => updateEdit(u.id, { email: e.target.value })}
                      placeholder="Email"
                    />
                    <select
                      className="md:col-span-1 px-3 py-2 border border-gray-200 rounded-lg text-sm"
                      value={edit.role || 'viewer'}
                      onChange={(e) => updateEdit(u.id, { role: e.target.value })}
                      disabled={isSelf}
                    >
                      {['admin', 'analyst', 'viewer', 'worker'].map((r) => (
                        <option key={r} value={r}>{r}</option>
                      ))}
                    </select>
                    <input
                      className="md:col-span-1 px-3 py-2 border border-gray-200 rounded-lg text-sm"
                      value={edit.password || ''}
                      onChange={(e) => updateEdit(u.id, { password: e.target.value })}
                      placeholder="New password"
                      type="password"
                    />
                    <div className="md:col-span-1 flex items-center gap-3 justify-end">
                      <label className="flex items-center gap-2 text-sm text-gray-600">
                        <input
                          type="checkbox"
                          checked={!!edit.disabled}
                          onChange={(e) => updateEdit(u.id, { disabled: e.target.checked })}
                          disabled={isSelf}
                        />
                        Disabled
                      </label>
                      <button
                        onClick={() => saveUser(u)}
                        className="px-3 py-2 text-xs font-medium text-white rounded-lg"
                        style={{ background: 'linear-gradient(135deg, #6366f1, #4f46e5)' }}
                      >
                        Save
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Baselines Page (analyst/admin)
// ─────────────────────────────────────────────────────────────────────────────

function BaselinesPage() {
  const { api } = useAuth();
  const [baselines, setBaselines] = useState([]);
  const [segment, setSegment] = useState('default');
  const [domainsText, setDomainsText] = useState('');
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState('');

  const showToast = (msg) => { setToast(msg); setTimeout(() => setToast(''), 3000); };

  const loadBaselines = useCallback(() => {
    setLoading(true);
    api.get('/api/baselines')
      .then((r) => setBaselines(r.data.baselines || []))
      .catch(() => showToast('Failed to load baselines.'))
      .finally(() => setLoading(false));
  }, [api]);

  useEffect(() => {
    loadBaselines();
  }, [loadBaselines]);

  const parseLines = (text) =>
    text.split('\n').map((l) => l.trim()).filter(Boolean);

  const saveBaseline = async (e) => {
    e.preventDefault();
    if (!segment.trim()) {
      showToast('Segment is required.');
      return;
    }
    try {
      const items = parseLines(domainsText);
      await api.put(`/api/baselines/${encodeURIComponent(segment.trim())}`, {
        known_ai_domains: items,
      });
      showToast('Baseline saved.');
      loadBaselines();
    } catch (e2) {
      const detail = e2?.response?.data?.detail || 'Failed to save baseline.';
      showToast(detail);
    }
  };

  const loadIntoForm = (b) => {
    setSegment(b.segment || '');
    setDomainsText((b.known_ai_domains || []).join('\n'));
  };

  return (
    <div>
      {toast && (
        <div className="fixed top-4 right-4 z-50 bg-gray-900 text-white px-4 py-2 rounded-lg shadow-lg text-sm">
          {toast}
        </div>
      )}

      <PageHeader title="Baselines" subtitle="Known AI domains per network segment" />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-1 p-6">
          <h3 className="font-semibold text-gray-900 mb-4">Create / Update Baseline</h3>
          <form onSubmit={saveBaseline} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Segment *</label>
              <input
                value={segment}
                onChange={(e) => setSegment(e.target.value)}
                placeholder="default or 10.0.0.0/24"
                className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm font-mono"
              />
              <p className="text-xs text-gray-400 mt-1">Use a CIDR, VLAN name, or "default".</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Known AI Domains</label>
              <textarea
                value={domainsText}
                onChange={(e) => setDomainsText(e.target.value)}
                rows={10}
                className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm font-mono
                  focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>
            <div className="flex justify-end">
              <button
                type="submit"
                className="px-4 py-2 text-sm font-medium text-white rounded-lg"
                style={{ background: 'linear-gradient(135deg, #6366f1, #4f46e5)' }}
              >
                Save Baseline
              </button>
            </div>
          </form>
        </Card>

        <div className="lg:col-span-2">
          <h3 className="font-semibold text-gray-900 mb-3">Existing Baselines</h3>
          {loading ? <Spinner /> : (
            <Card className="p-4">
              {baselines.length === 0 ? (
                <EmptyState icon={Terminal} title="No baselines" subtitle="Add a baseline to reduce false positives." />
              ) : (
                <div className="space-y-3">
                  {baselines.map((b) => (
                    <div key={b.segment} className="flex items-center justify-between gap-4">
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-gray-900">{b.segment}</p>
                        <p className="text-xs text-gray-500">
                          {(b.known_ai_domains || []).length} domains
                        </p>
                      </div>
                      <button
                        onClick={() => loadIntoForm(b)}
                        className="px-3 py-2 text-xs font-medium text-gray-700 border border-gray-200 rounded-lg hover:bg-gray-50"
                      >
                        Edit
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin Ops Page (admin)
// ─────────────────────────────────────────────────────────────────────────────

function AdminOpsPage() {
  const { api } = useAuth();
  const [auditLogs, setAuditLogs] = useState([]);
  const [siemDeliveries, setSiemDeliveries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState('');
  const [siemFilter, setSiemFilter] = useState('all');
  const [auditQuery, setAuditQuery] = useState('');

  const showToast = (msg) => { setToast(msg); setTimeout(() => setToast(''), 3000); };

  const loadAll = useCallback(() => {
    setLoading(true);
    Promise.all([
      api.get('/api/admin/audit-logs?limit=50'),
      api.get('/api/admin/siem-deliveries?limit=50'),
    ])
      .then(([a, s]) => {
        setAuditLogs(a.data.logs || []);
        setSiemDeliveries(s.data.deliveries || []);
      })
      .catch(() => showToast('Failed to load admin ops data.'))
      .finally(() => setLoading(false));
  }, [api]);

  useEffect(() => { loadAll(); }, [loadAll]);

  const filteredAudit = auditLogs.filter((l) => {
    const q = auditQuery.trim().toLowerCase();
    if (!q) return true;
    return [
      l.action,
      l.actor,
      l.target,
    ].some((v) => (v || '').toLowerCase().includes(q));
  });

  const filteredSiem = siemDeliveries.filter((d) => (
    siemFilter === 'all' ? true : d.status === siemFilter
  ));

  return (
    <div>
      {toast && (
        <div className="fixed top-4 right-4 z-50 bg-gray-900 text-white px-4 py-2 rounded-lg shadow-lg text-sm">
          {toast}
        </div>
      )}

      <PageHeader title="Admin Ops" subtitle="Audit trail and SIEM delivery status">
        <div className="flex items-center gap-2">
          <input
            value={auditQuery}
            onChange={(e) => setAuditQuery(e.target.value)}
            placeholder="Search audit logs…"
            className="px-3 py-2 text-xs border border-gray-200 rounded-lg"
          />
          <select
            value={siemFilter}
            onChange={(e) => setSiemFilter(e.target.value)}
            className="px-3 py-2 text-xs border border-gray-200 rounded-lg"
          >
            <option value="all">All SIEM</option>
            <option value="queued">Queued</option>
            <option value="delivered">Delivered</option>
            <option value="failed">Failed</option>
          </select>
          <button onClick={loadAll}
            className="flex items-center gap-2 px-3 py-2 text-xs text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-50">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
        </div>
      </PageHeader>

      {loading ? <Spinner /> : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="p-4">
            <h3 className="font-semibold text-gray-900 mb-3">Audit Logs</h3>
            {filteredAudit.length === 0 ? (
              <EmptyState icon={Shield} title="No audit logs" subtitle="Admin actions will appear here." />
            ) : (
              <div className="space-y-3">
                {filteredAudit.map((l) => (
                  <div key={l.id} className="text-xs text-gray-600 flex items-center gap-2">
                    <span className="font-mono text-gray-800">{(l.action || '').padEnd(16, ' ')}</span>
                    <span className="text-gray-500">by {l.actor}</span>
                    {l.target && <span className="text-gray-400">→ {l.target}</span>}
                    <span className="ml-auto text-gray-400">
                      {l.timestamp ? new Date(l.timestamp).toLocaleString() : ''}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card className="p-4">
            <h3 className="font-semibold text-gray-900 mb-3">SIEM Deliveries</h3>
            {filteredSiem.length === 0 ? (
              <EmptyState icon={FileText} title="No SIEM deliveries" subtitle="Report exports will appear here." />
            ) : (
              <div className="space-y-3">
                {filteredSiem.map((d) => (
                  <div key={d.id} className="text-xs text-gray-600 flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded-full text-xs ${
                      d.status === 'delivered' ? 'bg-green-100 text-green-700' :
                      d.status === 'failed' ? 'bg-red-100 text-red-700' :
                      'bg-gray-100 text-gray-700'
                    }`}>{d.status}</span>
                    <span className="font-mono text-gray-800">{(d.report_id || '').slice(0, 8)}</span>
                    <span className="text-gray-500">{d.scan_id?.slice(0, 8)}</span>
                    <span className="ml-auto text-gray-400">
                      {d.timestamp ? new Date(d.timestamp).toLocaleString() : ''}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan Page
// ─────────────────────────────────────────────────────────────────────────────

function ScanPage() {
  const { api } = useAuth();
  const [networkRange, setNetworkRange] = useState('192.168.1.0/24');
  const [scanType, setScanType] = useState('basic');
  const [deepScan, setDeepScan] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState('');
  const [wsConnected, setWsConnected] = useState(false);
  const [liveEvents, setLiveEvents] = useState([]);

  const showToast = (msg) => { setToast(msg); setTimeout(() => setToast(''), 4000); };

  const loadHistory = useCallback(() => {
    smartListScans({ page: 1, page_size: 20 })
      .then((r) => {
        // Support both new format (jobs[]) and legacy format (scans[])
        const items = r.data?.jobs || r.data?.scans || [];
        setScans(items);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { loadHistory(); }, [loadHistory]);

  useEffect(() => {
    const base = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
    const wsUrl = `${base.replace(/^http/, 'ws')}/api/ws`;
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onerror = () => setWsConnected(false);
    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (!msg?.type || !msg?.scan_id) return;
        setLiveEvents((prev) => [msg, ...prev].slice(0, 6));
        if (msg.type.startsWith('scan_')) {
          setScans((prev) => {
            const idx = prev.findIndex((s) => s.id === msg.scan_id);
            const next = [...prev];
            const patch = {
              id: msg.scan_id,
              network_range: msg.network_range,
              status: msg.status,
              devices_found: msg.devices_found,
              ai_services_detected: msg.ai_services_detected,
              alerts_created: msg.alerts_created,
              timestamp: new Date().toISOString(),
            };
            if (idx >= 0) {
              next[idx] = { ...next[idx], ...patch };
            } else {
              next.unshift(patch);
            }
            return next;
          });
        }
      } catch {
        // ignore malformed events
      }
    };

    return () => ws.close();
  }, []);

  const startScan = async (e) => {
    e.preventDefault();
    if (!networkRange.trim()) return;
    setScanning(true);
    try {
      const r = await smartCreateScan({
        target_type: 'network',
        target_value: networkRange.trim(),
        modules_enabled: ['target_scanner'],
        job_name: `Scan of ${networkRange.trim()}`,
      });
      const id = r.job_id || r.scan_id;
      showToast(`Scan queued (ID: ${id?.slice(0, 8)}…). Results will appear in history.`);
      setTimeout(loadHistory, 3000);
      setTimeout(loadHistory, 8000);
    } catch (err) {
      showToast(err?.response?.data?.detail || 'Scan failed. Analyst role required.');
    } finally {
      setScanning(false);
    }
  };

  const scanStatusColor = {
    queued:    'bg-yellow-100 text-yellow-700',
    running:   'bg-blue-100 text-blue-700',
    completed: 'bg-green-100 text-green-700',
    failed:    'bg-red-100 text-red-700',
  };

  return (
    <div>
      {toast && (
        <div className="fixed top-4 right-4 z-50 bg-gray-900 text-white px-4 py-2 rounded-lg shadow-lg text-sm max-w-sm">
          {toast}
        </div>
      )}

      <PageHeader title="Audit" subtitle="Discover, assess, and report on AI service risks across your network" />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scan form */}
        <Card className="lg:col-span-1 p-6">
          <h3 className="font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <Wifi className="w-4 h-4 text-indigo-500" /> Audit Configuration
          </h3>
          <form onSubmit={startScan} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Network Range (CIDR)
              </label>
              <input
                type="text"
                value={networkRange}
                onChange={(e) => setNetworkRange(e.target.value)}
                placeholder="192.168.1.0/24"
                className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm font-mono
                  focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
              <p className="text-xs text-gray-400 mt-1">e.g. 10.0.0.0/24 or 192.168.1.5/32</p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Scan Type</label>
              <div className="space-y-2">
                {[
                  { value: 'basic',         label: 'Basic',         desc: 'Host discovery + AI ports' },
                  { value: 'comprehensive', label: 'Comprehensive', desc: 'Full port scan + banners' },
                ].map(({ value, label, desc }) => (
                  <label key={value} className="flex items-start gap-3 cursor-pointer p-2 rounded-lg hover:bg-gray-50">
                    <input
                      type="radio"
                      name="scanType"
                      value={value}
                      checked={scanType === value}
                      onChange={() => setScanType(value)}
                      className="mt-0.5"
                    />
                    <div>
                      <p className="text-sm font-medium text-gray-700">{label}</p>
                      <p className="text-xs text-gray-400">{desc}</p>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={deepScan}
                onChange={(e) => setDeepScan(e.target.checked)}
                className="rounded"
              />
              <div>
                <p className="text-sm font-medium text-gray-700">Deep scan</p>
                <p className="text-xs text-gray-400">Include OS detection (slower)</p>
              </div>
            </label>

            <button
              type="submit"
              disabled={scanning || !networkRange.trim()}
              className="w-full flex items-center justify-center gap-2 py-3 text-sm font-medium
                text-white rounded-lg transition-all disabled:opacity-60"
              style={{ background: 'linear-gradient(135deg, #6366f1, #4f46e5)' }}
            >
              {scanning
                ? <><RefreshCw className="w-4 h-4 animate-spin" /> Running audit…</>
                : <><Search className="w-4 h-4" /> Run Audit</>}
            </button>
          </form>

          <div className="mt-4 p-3 bg-amber-50 border border-amber-200 rounded-lg">
            <p className="text-xs text-amber-700">
              <strong>Note:</strong> Network scanning requires <code className="bg-amber-100 px-1 rounded">nmap</code> to
              be installed in the worker container. The worker needs{' '}
              <code className="bg-amber-100 px-1 rounded">NET_RAW</code> capability.
            </p>
          </div>
        </Card>

        {/* Scan history */}
        <div className="lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-gray-900 flex items-center gap-2">
              <Clock className="w-4 h-4 text-gray-400" /> Audit History
            </h3>
            <button onClick={loadHistory}
              className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-700">
              <RefreshCw className="w-3 h-3" /> Refresh
            </button>
          </div>

          <Card className="p-4 mb-4">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium text-gray-900">Live Progress</p>
              <span className={`text-xs px-2 py-0.5 rounded-full ${
                wsConnected ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'
              }`}>
                {wsConnected ? 'WebSocket connected' : 'WebSocket offline'}
              </span>
            </div>
            {liveEvents.length === 0 ? (
              <p className="text-xs text-gray-500 mt-2">No live scan events yet.</p>
            ) : (
              <div className="mt-3 space-y-2">
                {liveEvents.map((ev, idx) => (
                  <div key={`${ev.scan_id}-${idx}`} className="text-xs text-gray-600 flex items-center gap-2">
                    <span className="font-mono text-gray-800">{ev.scan_id.slice(0, 6)}…</span>
                    <span className="px-2 py-0.5 rounded-full bg-gray-100 text-gray-700">{ev.type.replace(/_/g, ' ')}</span>
                    {ev.device_ip && <span className="text-gray-500">{ev.device_ip}</span>}
                    {ev.host && <span className="text-gray-500">{ev.host}</span>}
                    {ev.devices_found != null && (
                      <span className="text-gray-500">{ev.devices_found} devices</span>
                    )}
                    {ev.hosts_scanned != null && ev.hosts_total != null && (
                      <span className="text-gray-500">
                        {ev.hosts_scanned}/{ev.hosts_total} hosts
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </Card>

          {loading ? <Spinner /> : (
            <div className="space-y-3">
              {scans.length === 0 ? (
                <Card className="p-4">
                  <EmptyState icon={Search} title="No scans yet" subtitle="Start your first scan." />
                </Card>
              ) : (
                scans.map((scan, i) => (
                  <Card key={scan.id || i} className="p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2 mb-1">
                          <code className="text-sm font-mono font-semibold text-gray-900">
                            {scan.network_range || 'N/A'}
                          </code>
                          {scan.id && (
                            <span className="text-xs text-gray-400 font-mono">
                              {scan.id.slice(0, 6)}…
                            </span>
                          )}
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium
                            ${scanStatusColor[scan.status] || 'bg-gray-100 text-gray-700'}`}>
                            {scan.status}
                          </span>
                        </div>
                        <div className="flex flex-wrap gap-4 text-xs text-gray-500">
                          {scan.devices_found != null && (
                            <span>{scan.devices_found} devices found</span>
                          )}
                          {scan.ai_services_detected != null && (
                            <span>{scan.ai_services_detected} AI services</span>
                          )}
                          {scan.initiated_by && <span>by {scan.initiated_by}</span>}
                        </div>
                      </div>
                      <div className="text-right text-xs text-gray-400 shrink-0">
                        {scan.timestamp && new Date(scan.timestamp).toLocaleString()}
                      </div>
                    </div>
                  </Card>
                ))
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan Detail Page — Phase 8: orchestrated scan + report view
// ─────────────────────────────────────────────────────────────────────────────

function ScanDetailPage() {
  const [jobId, setJobId] = useState('');
  const [job, setJob] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [report, setReport] = useState(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [toast, setToast] = useState('');

  const showToast = (msg) => { setToast(msg); setTimeout(() => setToast(''), 4000); };

  const loadJob = useCallback(async (id) => {
    setLoading(true);
    setError('');
    setJob(null);
    setReport(null);
    try {
      const data = await smartGetScan(id);
      // Support both new (flat) and legacy (wrapped {scan:...}) formats
      const resolved = data.data || data;
      setJob(resolved.scan || resolved);
    } catch (e) {
      setError(e?.detail || e?.message || 'Failed to load scan');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadReport = useCallback(async (id) => {
    setReportLoading(true);
    try {
      // Try new endpoint first
      const data = await getReport(id);
      setReport(data.report || data);
    } catch {
      try {
        // Fallback: generate legacy report
        const { generateLegacyReport } = await import('./services/api');
        const r = await generateLegacyReport({ scan_id: id, fmt: 'json' });
        setReport(r);
      } catch (e2) {
        setReport({ error: e2?.detail || 'No report available' });
      }
    } finally {
      setReportLoading(false);
    }
  }, []);

  const handleLookup = (e) => {
    e.preventDefault();
    if (!jobId.trim()) return;
    loadJob(jobId.trim());
    loadReport(jobId.trim());
  };

  const scanStatusColor = {
    queued:    'bg-yellow-100 text-yellow-700',
    running:   'bg-blue-100 text-blue-700',
    completed: 'bg-green-100 text-green-700',
    failed:    'bg-red-100 text-red-700',
    cancelled: 'bg-gray-100 text-gray-700',
  };

  const severityColor = {
    critical: 'bg-red-100 text-red-700',
    high:     'bg-orange-100 text-orange-700',
    medium:   'bg-yellow-100 text-yellow-700',
    low:      'bg-green-100 text-green-700',
  };

  const ts = (v) => v ? new Date(v).toLocaleString() : '—';

  const exportReport = async (fmt) => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `shadow-ai-audit-${(job.job_id || job._id || 'report').slice(0, 8)}.${fmt}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      {toast && (
        <div className="fixed top-4 right-4 z-50 bg-gray-900 text-white px-4 py-2 rounded-lg shadow-lg text-sm max-w-sm">
          {toast}
        </div>
      )}

      <PageHeader title="Audit Detail" subtitle="View job status, findings, severity, and remediation" />

      {/* Lookup form */}
      <Card className="p-6 mb-6">
        <form onSubmit={handleLookup} className="flex gap-3 items-end">
          <div className="flex-1">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Audit / Job ID
            </label>
            <input
              type="text"
              value={jobId}
              onChange={(e) => setJobId(e.target.value)}
              placeholder="e.g. 67fbc3a2e4b3..."
              className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm font-mono"
            />
          </div>
          <button type="submit" disabled={loading || !jobId.trim()}
            className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm disabled:opacity-50">
            {loading ? 'Loading…' : 'Look up'}
          </button>
        </form>
      </Card>

      {/* Job metadata */}
      {loading && <div className="text-center py-8 text-gray-400"><RefreshCw className="w-6 h-6 animate-spin mx-auto" /></div>}

      {error && (
        <Card className="p-6 mb-6">
          <p className="text-red-600 text-sm">{error}</p>
          <p className="text-xs text-gray-400 mt-2">
            Note: scan IDs from before the Phase 3 upgrade are in legacy format.
            Legacy IDs still work — the API layer handles fallback automatically.
          </p>
        </Card>
      )}

      {job && !loading && (
        <div className="space-y-6">
          {/* Status card */}
          <Card className="p-6">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-3 mb-3">
                  <span className={`text-sm px-3 py-1 rounded-full font-medium ${
                    scanStatusColor[job.status] || 'bg-gray-100 text-gray-700'}`}>
                    {job.status || 'unknown'}
                  </span>
                  {job.job_id && (
                    <span className="text-xs text-gray-400 font-mono">ID: {job.job_id.slice(0, 12)}…</span>
                  )}
                  {job._id && !job.job_id && (
                    <span className="text-xs text-gray-400 font-mono">ID: {String(job._id).slice(0, 12)}…</span>
                  )}
                </div>
                <table className="text-sm">
                  <tbody>
                    {[
                      ['Target', job.target_value || job.network_range || '—'],
                      ['Type', job.target_type || job.scan_type || 'network'],
                      ['Modules', (job.modules_enabled || []).join(', ') || 'target_scanner'],
                      ['Tenant', job.tenant_id || 'default'],
                      ['Created', ts(job.created_at || job.timestamp)],
                      ['Started', ts(job.started_at)],
                      ['Completed', ts(job.completed_at)],
                    ].map(([k, v]) => v !== '—' && v && (
                      <tr key={k}><td className="pr-6 py-1 text-gray-500">{k}</td>
                        <td className="font-medium text-gray-900 font-mono text-xs">{String(v)}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="text-right text-sm text-gray-500 space-y-1">
                <p>{job.devices_found != null ? `${job.devices_found} devices` : '—'}</p>
                <p>{job.ai_services_detected != null ? `${job.ai_services_detected} AI services` : '—'}</p>
                {job.initiated_by && <p>by {job.initiated_by}</p>}
                {job.error && <p className="text-red-500 text-xs">Error: {job.error}</p>}
              </div>
            </div>
          </Card>

          {/* Report */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-semibold text-gray-900 flex items-center gap-2">
                <FileText className="w-4 h-4 text-indigo-500" /> Findings & Report
              </h3>
              {!report && !reportLoading && job.status === 'completed' && (
                <button onClick={() => loadReport(job.job_id || job._id)}
                  className="text-xs text-indigo-600 hover:text-indigo-800">
                  Load report →
                </button>
              )}
            </div>

            {reportLoading && <div className="text-center py-6 text-gray-400"><RefreshCw className="w-5 h-5 animate-spin mx-auto" /></div>}

            {report?.error && <p className="text-sm text-gray-500">{report.error}</p>}

            {report && !report.error && (
              <div className="space-y-4">
                {/* Summary */}
                <Card className="p-4">
                  {/* Header with risk level + export */}
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <p className="text-xs text-gray-500 mb-1">Overall Risk Level</p>
                      <span className={`text-lg font-bold px-3 py-1 rounded-full ${
                        report.summary?.risk_level === 'critical' ? 'bg-red-100 text-red-700' :
                        report.summary?.risk_level === 'high' ? 'bg-orange-100 text-orange-700' :
                        report.summary?.risk_level === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                        'bg-green-100 text-green-700'
                      }`}>
                        {(report.summary?.risk_level || 'unknown').toUpperCase()}
                      </span>
                    </div>
                    <div className="flex gap-2">
                      <button onClick={() => exportReport('json')}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-indigo-700
                          bg-indigo-50 border border-indigo-200 rounded-lg hover:bg-indigo-100">
                        <FileText className="w-3.5 h-3.5" /> Export JSON
                      </button>
                      <button onClick={() => exportReport('json')}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-700
                          bg-red-50 border border-red-200 rounded-lg hover:bg-red-100">
                        <FileText className="w-3.5 h-3.5" /> Export PDF
                      </button>
                    </div>
                  </div>

                  {/* Stats row */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                    {[
                      ['Total Findings', report.summary?.findings_count ?? report.findings?.length ?? 0],
                      ['Critical', report.findings?.filter(f => f.severity === 'critical').length ?? 0],
                      ['High', report.findings?.filter(f => f.severity === 'high').length ?? 0],
                      ['Medium / Low', report.findings?.filter(f => ['medium','low'].includes(f.severity)).length ?? 0],
                    ].map(([k, v]) => (
                      <div key={k} className="bg-gray-50 rounded-lg p-2">
                        <p className="text-xs text-gray-500">{k}</p>
                        <p className="text-lg font-bold text-gray-900">{v}</p>
                      </div>
                    ))}
                  </div>
                </Card>

                {/* Recommendations */}
                {report.recommendations?.length > 0 && (
                  <Card className="p-4">
                    <p className="text-xs text-gray-500 mb-2 font-medium uppercase">Recommendations</p>
                    <ol className="space-y-1">
                      {report.recommendations.map((r, i) => (
                        <li key={i} className="text-sm text-gray-700 flex gap-2">
                          <span className="text-indigo-500 font-bold shrink-0">{i + 1}.</span>
                          {r}
                        </li>
                      ))}
                    </ol>
                  </Card>
                )}

                {/* Findings table */}
                {report.findings?.length > 0 && (
                  <Card className="p-4">
                    <p className="text-xs text-gray-500 mb-3 font-medium uppercase">
                      Findings ({report.findings.length})
                    </p>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="text-gray-500 border-b">
                            <th className="text-left pb-2 pr-3">Severity</th>
                            <th className="text-left pb-2 pr-3">Type</th>
                            <th className="text-left pb-2 pr-3">Indicator</th>
                            <th className="text-left pb-2">Remediation</th>
                          </tr>
                        </thead>
                        <tbody>
                          {report.findings.slice(0, 20).map((f, i) => (
                            <tr key={i} className="border-b border-gray-50">
                              <td className="py-2 pr-3">
                                <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                                  severityColor[f.severity] || 'bg-gray-100 text-gray-600'
                                }`}>
                                  {(f.severity || '?').toUpperCase()}
                                </span>
                              </td>
                              <td className="py-2 pr-3 text-gray-600">{f.type || f.category || '—'}</td>
                              <td className="py-2 pr-3 font-mono text-gray-800 truncate max-w-xs"
                                title={f.indicator}>
                                {f.indicator || '—'}
                              </td>
                              <td className="py-2 text-gray-600 text-xs"
                                title={f.remediation}>
                                {f.remediation ? f.remediation.slice(0, 60) + (f.remediation.length > 60 ? '…' : '') : '—'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      {report.findings.length > 20 && (
                        <p className="text-xs text-gray-400 mt-2">
                          +{report.findings.length - 20} more findings (see full JSON report for complete list)
                        </p>
                      )}
                    </div>
                  </Card>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

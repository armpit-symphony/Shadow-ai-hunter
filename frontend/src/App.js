import React, { useState, useEffect, useCallback } from 'react';
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
  { id: 'scan',       label: 'Network Scan',   icon: Search },
];

function ProtectedLayout() {
  const [page, setPage] = useState('dashboard');
  const { user } = useAuth();
  const adminNav = [
    { id: 'lists',     label: 'Allow/Deny Lists', icon: FileText },
    { id: 'users',     label: 'User Management',  icon: User },
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
      case 'baselines': return <BaselinesPage />;
      case 'lists':     return <ListsPage />;
      case 'users':     return <UsersPage />;
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

  const startScan = async () => {
    setScanning(true);
    try {
      await api.post('/api/scan', {
        network_range: '192.168.1.0/24',
        scan_type: 'comprehensive',
        deep_scan: true,
      });
      showToast('Scan queued — results will appear shortly.');
      setTimeout(load, 5000);
    } catch {
      showToast('Scan failed. Check that the worker is running.');
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

      <PageHeader title="Dashboard" subtitle="Enterprise AI Detection & Network Security">
        <button onClick={populateDemo}
          className="px-4 py-2 text-sm font-medium text-green-700 bg-green-50 border border-green-200
            rounded-lg hover:bg-green-100 transition-colors">
          Load Demo Data
        </button>
        <button onClick={startScan} disabled={scanning}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white rounded-lg
            transition-all disabled:opacity-60"
          style={{ background: 'linear-gradient(135deg, #6366f1, #4f46e5)' }}>
          {scanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          {scanning ? 'Scanning…' : 'Start Scan'}
        </button>
      </PageHeader>

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
    api.get('/api/scans?limit=20')
      .then((r) => setScans(r.data.scans || []))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [api]);

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
      const r = await api.post('/api/scan', {
        network_range: networkRange.trim(),
        scan_type: scanType,
        deep_scan: deepScan,
      });
      showToast(`Scan queued (ID: ${r.data.scan_id?.slice(0, 8)}…). Results will appear in history.`);
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

      <PageHeader title="Network Scan" subtitle="Discover devices running local AI services" />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scan form */}
        <Card className="lg:col-span-1 p-6">
          <h3 className="font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <Wifi className="w-4 h-4 text-indigo-500" /> Scan Configuration
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
                ? <><RefreshCw className="w-4 h-4 animate-spin" /> Queuing scan…</>
                : <><Search className="w-4 h-4" /> Start Scan</>}
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
              <Clock className="w-4 h-4 text-gray-400" /> Scan History
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

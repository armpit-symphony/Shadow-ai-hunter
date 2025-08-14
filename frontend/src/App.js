import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink } from 'react-router-dom';
import axios from 'axios';
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  Search, 
  Settings, 
  Users, 
  BarChart3,
  Network,
  Zap,
  Eye,
  Lock,
  TrendingUp
} from 'lucide-react';

// API Configuration
const API_BASE_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
});

// Dashboard Component
function Dashboard() {
  const [stats, setStats] = useState(null);
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanLoading, setScanLoading] = useState(false);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const [statsRes, devicesRes, alertsRes] = await Promise.all([
        api.get('/api/dashboard/stats'),
        api.get('/api/devices'),
        api.get('/api/alerts')
      ]);
      
      setStats(statsRes.data);
      setDevices(devicesRes.data.devices || []);
      setAlerts(alertsRes.data.alerts || []);
    } catch (error) {
      console.error('Error loading dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const startScan = async () => {
    try {
      setScanLoading(true);
      await api.post('/api/scan', {
        network_range: '192.168.1.0/24',
        scan_type: 'comprehensive',
        deep_scan: true
      });
      
      // Wait a moment then reload data
      setTimeout(() => {
        loadDashboardData();
        setScanLoading(false);
      }, 3000);
    } catch (error) {
      console.error('Error starting scan:', error);
      setScanLoading(false);
    }
  };

  const populateDemoData = async () => {
    try {
      await api.get('/api/demo/populate');
      await loadDashboardData();
    } catch (error) {
      console.error('Error populating demo data:', error);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Shadow AI Hunter Dashboard</h1>
          <p className="text-gray-600 mt-2">Enterprise AI Detection & Network Security</p>
        </div>
        <div className="flex space-x-4">
          <button
            onClick={populateDemoData}
            className="px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors"
          >
            Load Demo Data
          </button>
          <button
            onClick={startScan}
            disabled={scanLoading}
            className={`px-6 py-2 rounded-lg font-medium transition-all ${
              scanLoading
                ? 'bg-gray-400 cursor-not-allowed'
                : 'bg-primary-500 hover:bg-primary-600'
            } text-white flex items-center space-x-2`}
          >
            <Search className="w-4 h-4" />
            <span>{scanLoading ? 'Scanning...' : 'Start Network Scan'}</span>
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <StatsCard
            title="Total Devices"
            value={stats.total_devices}
            icon={<Network className="w-8 h-8" />}
            color="blue"
          />
          <StatsCard
            title="High Risk Devices"
            value={stats.high_risk_devices}
            icon={<AlertTriangle className="w-8 h-8" />}
            color="red"
          />
          <StatsCard
            title="Active Threats"
            value={stats.active_threats}
            icon={<Shield className="w-8 h-8" />}
            color="orange"
          />
          <StatsCard
            title="Compliance Score"
            value={`${Math.round(stats.compliance_score * 100)}%`}
            icon={<TrendingUp className="w-8 h-8" />}
            color="green"
          />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Devices Section */}
        <div className="bg-white rounded-xl shadow-lg p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-bold text-gray-900 flex items-center">
              <Network className="w-5 h-5 mr-2 text-primary-500" />
              Network Devices
            </h2>
            <span className="bg-primary-100 text-primary-800 px-3 py-1 rounded-full text-sm font-medium">
              {devices.length} detected
            </span>
          </div>
          <div className="space-y-4 max-h-96 overflow-y-auto">
            {devices.length > 0 ? (
              devices.map((device, index) => (
                <DeviceCard key={index} device={device} />
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">
                <Network className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No devices detected yet. Start a network scan to discover devices.</p>
              </div>
            )}
          </div>
        </div>

        {/* Alerts Section */}
        <div className="bg-white rounded-xl shadow-lg p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-bold text-gray-900 flex items-center">
              <AlertTriangle className="w-5 h-5 mr-2 text-orange-500" />
              Security Alerts
            </h2>
            <span className="bg-red-100 text-red-800 px-3 py-1 rounded-full text-sm font-medium">
              {alerts.filter(a => !a.resolved).length} active
            </span>
          </div>
          <div className="space-y-4 max-h-96 overflow-y-auto">
            {alerts.length > 0 ? (
              alerts.map((alert, index) => (
                <AlertCard key={index} alert={alert} />
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">
                <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No security alerts. Your network appears secure.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// Stats Card Component
function StatsCard({ title, value, icon, color }) {
  const colorClasses = {
    blue: 'from-blue-500 to-blue-600',
    red: 'from-red-500 to-red-600',
    green: 'from-green-500 to-green-600',
    orange: 'from-orange-500 to-orange-600'
  };

  return (
    <div className="bg-white rounded-xl shadow-lg p-6 card-hover">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-gray-600 text-sm font-medium">{title}</p>
          <p className="text-3xl font-bold text-gray-900 mt-1">{value}</p>
        </div>
        <div className={`p-3 rounded-lg bg-gradient-to-r ${colorClasses[color]} text-white`}>
          {icon}
        </div>
      </div>
    </div>
  );
}

// Device Card Component
function DeviceCard({ device }) {
  const getRiskLevel = (score) => {
    if (score >= 0.8) return { level: 'High', color: 'red', bgClass: 'risk-high' };
    if (score >= 0.5) return { level: 'Medium', color: 'orange', bgClass: 'risk-medium' };
    return { level: 'Low', color: 'green', bgClass: 'risk-low' };
  };

  const risk = getRiskLevel(device.ai_risk_score);

  return (
    <div className={`p-4 rounded-lg ${risk.bgClass}`}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center space-x-3">
          <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
          <div>
            <p className="font-semibold text-gray-900">{device.hostname || device.ip_address}</p>
            <p className="text-sm text-gray-600">{device.ip_address}</p>
          </div>
        </div>
        <span className={`px-2 py-1 rounded text-xs font-medium bg-${risk.color}-100 text-${risk.color}-800`}>
          {risk.level} Risk
        </span>
      </div>
      <div className="flex items-center justify-between text-sm">
        <span className="text-gray-600 capitalize">{device.device_type}</span>
        <div className="flex items-center space-x-2">
          {device.ai_services_detected && device.ai_services_detected.length > 0 && (
            <span className="bg-purple-100 text-purple-800 px-2 py-1 rounded text-xs">
              {device.ai_services_detected.length} AI services
            </span>
          )}
        </div>
      </div>
      {device.ai_services_detected && device.ai_services_detected.length > 0 && (
        <div className="mt-2">
          <p className="text-xs text-gray-600 mb-1">Detected AI Services:</p>
          <div className="flex flex-wrap gap-1">
            {device.ai_services_detected.map((service, idx) => (
              <span key={idx} className="bg-gray-100 text-gray-700 px-2 py-1 rounded text-xs">
                {service}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// Alert Card Component
function AlertCard({ alert }) {
  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'red';
      case 'high': return 'orange';
      case 'medium': return 'yellow';
      case 'low': return 'blue';
      default: return 'gray';
    }
  };

  const color = getSeverityColor(alert.severity);

  return (
    <div className={`p-4 rounded-lg border-l-4 border-${color}-500 bg-${color}-50`}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center space-x-2 mb-1">
            <AlertTriangle className={`w-4 h-4 text-${color}-500`} />
            <p className="font-semibold text-gray-900">{alert.title}</p>
          </div>
          <p className="text-sm text-gray-600 mb-2">{alert.description}</p>
          <div className="flex items-center space-x-4 text-xs text-gray-500">
            <span>Device: {alert.device_ip}</span>
            <span>Type: {alert.alert_type}</span>
            {alert.created_at && (
              <span>
                {new Date(alert.created_at).toLocaleDateString()}
              </span>
            )}
          </div>
        </div>
        <span className={`px-2 py-1 rounded text-xs font-medium bg-${color}-100 text-${color}-800 capitalize`}>
          {alert.severity}
        </span>
      </div>
    </div>
  );
}

// Sidebar Navigation Component
function Sidebar({ activeTab, setActiveTab }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: <BarChart3 className="w-5 h-5" /> },
    { id: 'devices', label: 'Devices', icon: <Network className="w-5 h-5" /> },
    { id: 'alerts', label: 'Alerts', icon: <AlertTriangle className="w-5 h-5" /> },
    { id: 'policies', label: 'Policies', icon: <Lock className="w-5 h-5" /> },
    { id: 'scanning', label: 'Network Scan', icon: <Search className="w-5 h-5" /> },
  ];

  return (
    <div className="bg-white shadow-lg h-full w-64 fixed left-0 top-0 z-10">
      <div className="p-6 border-b">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 bg-gradient-to-r from-primary-500 to-primary-600 rounded-lg flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-gray-900">Shadow AI</h1>
            <p className="text-sm text-gray-600">Hunter</p>
          </div>
        </div>
      </div>
      <nav className="mt-6">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={`w-full text-left px-6 py-3 flex items-center space-x-3 hover:bg-gray-50 transition-colors ${
              activeTab === item.id
                ? 'bg-primary-50 text-primary-600 border-r-2 border-primary-600'
                : 'text-gray-700'
            }`}
          >
            {item.icon}
            <span className="font-medium">{item.label}</span>
          </button>
        ))}
      </nav>
    </div>
  );
}

// Main App Component
function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard />;
      case 'devices':
        return <div className="text-center py-20"><Network className="w-16 h-16 mx-auto mb-4 text-gray-400" /><p className="text-xl text-gray-600">Device Management - Coming Soon</p></div>;
      case 'alerts':
        return <div className="text-center py-20"><AlertTriangle className="w-16 h-16 mx-auto mb-4 text-gray-400" /><p className="text-xl text-gray-600">Alert Management - Coming Soon</p></div>;
      case 'policies':
        return <div className="text-center py-20"><Lock className="w-16 h-16 mx-auto mb-4 text-gray-400" /><p className="text-xl text-gray-600">Policy Management - Coming Soon</p></div>;
      case 'scanning':
        return <div className="text-center py-20"><Search className="w-16 h-16 mx-auto mb-4 text-gray-400" /><p className="text-xl text-gray-600">Advanced Scanning - Coming Soon</p></div>;
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      <main className="ml-64 p-8">
        {renderContent()}
      </main>
    </div>
  );
}

export default App;
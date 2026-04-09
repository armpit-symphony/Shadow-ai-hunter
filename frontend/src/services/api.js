/**
 * Shadow AI Hunter — API Service Layer
 * Centralizes all backend calls with graceful fallback from new
 * orchestrated endpoints → legacy endpoints.
 *
 * New flow (preferred):  POST /scan → GET /scans → GET /scan/:id → GET /reports/:id
 * Legacy fallback:        POST /api/scan → GET /api/scans → GET /api/scans/:id → GET /api/reports/:id
 */

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8001';

/** Build full URL, handling the new (no /api prefix) and legacy routes */
function url(path) {
  // New orchestrated endpoints have no /api prefix
  if (path.startsWith('/scan') || path.startsWith('/scans') || path.startsWith('/report')) {
    return `${API_BASE}${path}`;
  }
  return `${API_BASE}/api${path}`;
}

/** Generic fetch wrapper */
async function apiFetch(path, options = {}) {
  const token = localStorage.getItem('shadow_token');
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };
  const res = await fetch(url(path), { ...options, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw err;
  }
  return res.json();
}

// ─── New Orchestrated Endpoints (preferred) ──────────────────────────────────

/**
 * Create a new scan job.
 * @param {{ target_type, target_value, modules_enabled, job_name, tenant_id }} data
 */
export async function createScan(data) {
  return apiFetch('/scan', { method: 'POST', body: JSON.stringify(data) });
}

/**
 * List scan jobs with optional pagination.
 * @param {{ page?: number, page_size?: number }} opts
 */
export async function listScans(opts = {}) {
  const qs = new URLSearchParams(opts).toString();
  return apiFetch(`/scans${qs ? '?' + qs : ''}`);
}

/**
 * Get a single scan job by ID.
 * @param {string} jobId
 */
export async function getScan(jobId) {
  return apiFetch(`/scan/${jobId}`);
}

/**
 * Get a report by ID.
 * @param {string} reportId
 */
export async function getReport(reportId) {
  return apiFetch(`/reports/${reportId}`);
}

// ─── Legacy Fallbacks ─────────────────────────────────────────────────────────

/**
 * Create a scan via legacy endpoint (network scan only).
 * @param {{ network_range, scan_type, deep_scan }} data
 */
export async function createLegacyScan(data) {
  return apiFetch('/scan', { method: 'POST', body: JSON.stringify(data) });
}

/**
 * List scans via legacy endpoint.
 * @param {number} limit
 */
export async function listLegacyScans(limit = 50) {
  return apiFetch(`/scans?limit=${limit}`);
}

/**
 * Get a scan via legacy endpoint.
 * @param {string} scanId
 */
export async function getLegacyScan(scanId) {
  return apiFetch(`/scans/${scanId}`);
}

/**
 * Get scan devices via legacy endpoint.
 * @param {string} scanId
 */
export async function getLegacyScanDevices(scanId) {
  return apiFetch(`/scans/${scanId}/devices`);
}

/**
 * List reports via legacy endpoint.
 */
export async function listLegacyReports() {
  return apiFetch('/reports');
}

/**
 * Generate report via legacy endpoint.
 * @param {{ scan_id, fmt }} data
 */
export async function generateLegacyReport(data) {
  return apiFetch('/reports/generate', { method: 'POST', body: JSON.stringify(data) });
}

/**
 * Smart scan: tries new endpoint first, falls back to legacy.
 * @param {{ target_type, target_value, modules_enabled }} data
 */
export async function smartCreateScan(data) {
  try {
    return await createScan(data);
  } catch (e) {
    // Fallback to legacy if new endpoint returns 404/422
    if (e?.detail?.includes('not found') || e?.detail?.includes('validation')) {
      return createLegacyScan({
        network_range: data.target_value,
        scan_type: data.target_type === 'network' ? 'basic' : 'basic',
        deep_scan: false,
      });
    }
    throw e;
  }
}

/**
 * Smart scan list: tries new endpoint first, falls back to legacy.
 */
export async function smartListScans(opts = {}) {
  try {
    return await listScans(opts);
  } catch (e) {
    return listLegacyScans(opts.page_size || 50);
  }
}

/**
 * Smart scan get: tries new endpoint first, falls back to legacy.
 */
export async function smartGetScan(jobId) {
  try {
    return await getScan(jobId);
  } catch (e) {
    return getLegacyScan(jobId);
  }
}

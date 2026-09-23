/**
 * api.js — Centralized API client for MailForenSIX
 * All backend calls go through this module.
 * Base URL is read from Vite env (proxied to localhost:8000 in dev).
 */

import axios from 'axios'

const RAW_BASE = import.meta.env.VITE_API_BASE ?? '/api/v1'
// If VITE_API_BASE is e.g. "https://mailforensix-backend.onrender.com/api/v1", root is "https://mailforensix-backend.onrender.com"
export const BACKEND_ROOT = RAW_BASE.startsWith('http')
  ? RAW_BASE.replace(/\/api\/v1\/?$/, '')
  : ''

export const api = axios.create({
  baseURL: RAW_BASE,
  timeout: 90_000,   // 90s — full pipeline can take up to 60s
})

/**
 * POST /analyze
 * @param {File|null} emlFile    — .eml file object
 * @param {string|null} rawText  — pasted raw header/source
 * @returns {Promise<AnalysisResponse>}
 */
export async function analyzeEmail(emlFile, rawText) {
  const form = new FormData()
  if (emlFile) form.append('eml_file', emlFile)
  if (rawText) form.append('raw_headers', rawText)

  const { data } = await api.post('/analyze', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

/**
 * GET /health — used by the frontend to show backend connectivity status
 */
export async function checkHealth() {
  const url = BACKEND_ROOT ? `${BACKEND_ROOT}/health` : '/health'
  const { data } = await axios.get(url, { timeout: 10_000 })
  return data
}

/**
 * POST /api/v1/export/pdf
 * Accepts the full AnalysisResponse JSON, returns a PDF blob.
 * @param {object} analysisData — the full analysis result object
 * @returns {Promise<Blob>}
 */
export async function exportPDF(analysisData) {
  const { data } = await api.post('/export/pdf', analysisData, {
    headers: { 'Content-Type': 'application/json' },
    responseType: 'blob',
    timeout: 60_000,
  })
  return data
}

/**
 * POST /api/v1/export/anchor
 * Anchors a SHA-256 hash to OpenTimestamps.
 * @param {string} sha256 — hex SHA-256 string
 * @returns {Promise<{tx_id, status, backend, ts}>}
 */
export async function anchorHash(sha256) {
  const { data } = await api.post('/export/anchor', { sha256 })
  return data
}

// ── Mode 2: Campaign Intelligence ─────────────────────────────────────────────

/**
 * POST /api/v1/campaign/analyze
 * Upload a zip of .eml files for batch campaign analysis.
 * @param {File} zipFile  — .zip archive of .eml files
 * @param {File[]} emlFiles — individual .eml files (alternative)
 * @returns {Promise<{campaign_id, status, n_files}>}
 */
export async function submitCampaign(zipFile, emlFiles) {
  const form = new FormData()
  if (zipFile)   form.append('zip_file', zipFile)
  if (emlFiles)  emlFiles.forEach(f => form.append('eml_files', f))
  const { data } = await api.post('/campaign/analyze', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 300_000,   // 5 min for large batches
  })
  return data
}

/**
 * GET /api/v1/campaign/{id}/results
 * Poll for campaign analysis results.
 */
export async function pollCampaignResults(campaignId) {
  const { data } = await api.get(`/campaign/${campaignId}/results`)
  return data
}

/**
 * GET /api/v1/campaign/{id}/export/{format}
 * Export campaign in the specified format.
 * @param {string} campaignId
 * @param {string} format — stix|sigma|suricata|postfix|exchange|dnsbl
 * @param {string} tlp — amber|green|white|red
 */
export async function exportCampaign(campaignId, format, tlp = 'amber') {
  const { data } = await api.get(
    `/campaign/${campaignId}/export/${format}`,
    { params: { tlp }, responseType: 'text', timeout: 30_000 }
  )
  return data
}

/**
 * POST /api/v1/campaign/{id}/adjust
 * Merge or split clusters with audit logging.
 */
export async function adjustCampaignCluster(campaignId, action, clusterIds, reason, analystId) {
  const form = new FormData()
  form.append('action',      action)
  form.append('cluster_ids', clusterIds.join(','))
  form.append('reason',      reason || '')
  form.append('analyst_id',  analystId || 'anonymous')
  const { data } = await api.post(`/campaign/${campaignId}/adjust`, form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

/**
 * api.js — Centralized API client for MailForenSIX
 * All backend calls go through this module.
 * Base URL is read from Vite env (proxied to localhost:8000 in dev).
 */

import axios from 'axios'

const BASE = import.meta.env.VITE_API_BASE ?? '/api/v1'

export const api = axios.create({
  baseURL: BASE,
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
  const { data } = await api.get('/health', { baseURL: '' })
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

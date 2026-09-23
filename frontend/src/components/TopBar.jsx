/**
 * TopBar — Phase 3 update + Theme toggle (Phase 5)
 * - Taller header (h-16)
 * - Bigger logo & nav links
 * - Light/dark mode toggle (persisted to localStorage)
 * - Live backend health poll
 */

import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { BACKEND_ROOT } from '../lib/api'
import { checkHealth } from '../lib/api'

export default function TopBar({ airGapped, onToggleAirGap }) {
  const [health, setHealth] = useState(null)
  // Poll health every 30s
  useEffect(() => {
    let cancelled = false
    const fetchHealth = async () => {
      try {
        const h = await checkHealth()
        if (!cancelled) setHealth(h)
      } catch {
        if (!cancelled) setHealth(null)
      }
    }
    fetchHealth()
    const id = setInterval(fetchHealth, 30_000)
    return () => { cancelled = true; clearInterval(id) }
  }, [])

  const backendOk = health?.status === 'ok'
  const mlLoaded  = health?.ml_model_loaded === true

  return (
    <header className="sticky top-0 z-50 backdrop-blur-xl border-b border-white/[0.08] bg-mfx-bg/80">
      <div className="w-full px-8 h-16 flex items-center justify-between">

        {/* ── Logo ──────────────────────────────────────────────────────── */}
        <div className="flex items-center gap-4">
          <Link to="/" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
            <div className="w-10 h-10 rounded-badge bg-mfx-accent flex items-center justify-center text-2xl shadow-glow">
              📧
            </div>
            <div>
              <span className="font-bold text-2xl tracking-tight" style={{ color: 'var(--mfx-text)' }}>
                MailForen
              </span>
              <span className="font-bold text-2xl text-mfx-accent">SIX</span>
            </div>
          </Link>
          <span className="hidden lg:inline text-sm px-3 py-1 rounded-full border"
            style={{ color: 'var(--mfx-muted)', borderColor: 'var(--mfx-border)' }}>
            AI Email Forensics · SIH 2026
          </span>
        </div>

        {/* ── Controls ──────────────────────────────────────────────────── */}
        <div className="flex items-center gap-5">

          {/* Backend + ML health */}
          <div className="hidden md:flex items-center gap-4 text-sm"
            style={{ color: 'var(--mfx-muted)' }}
            title={health
              ? `Backend: ${health.status} | ML: ${health.ml_model_loaded ? 'loaded' : 'heuristic'} | v${health.version}`
              : 'Backend status unknown'}>
            <div className="flex items-center gap-1.5">
              <span className={`w-2.5 h-2.5 rounded-full animate-pulse-dot
                ${backendOk ? 'bg-mfx-safe' : 'bg-mfx-critical'}`} />
              <span>{backendOk ? 'API' : 'Offline'}</span>
            </div>
            {backendOk && (
              <div className="flex items-center gap-1.5">
                <span className={`w-2.5 h-2.5 rounded-full
                  ${mlLoaded ? 'bg-mfx-accent' : 'bg-mfx-suspicious'}`} />
                <span className="hidden lg:inline">{mlLoaded ? 'XGBoost' : 'Heuristic'}</span>
              </div>
            )}
          </div>

          {/* Air-gap mode dot */}
          <div className="hidden sm:flex items-center gap-1.5 text-sm"
            style={{ color: 'var(--mfx-muted)' }}>
            <span className={`w-2.5 h-2.5 rounded-full animate-pulse-dot
              ${airGapped ? 'bg-mfx-suspicious' : 'bg-mfx-safe'}`} />
            <span>{airGapped ? 'Air-gapped' : 'Live APIs'}</span>
          </div>

          {/* Air-gap toggle */}
          <button
            id="air-gap-toggle"
            onClick={onToggleAirGap}
            title="Toggle air-gapped mode (Space)"
            aria-pressed={airGapped}
            className={`relative inline-flex h-7 w-12 items-center rounded-full
              transition-colors duration-200 cursor-pointer border
              ${airGapped
                ? 'border-mfx-suspicious/50 bg-mfx-suspicious/30'
                : 'bg-mfx-surface border-mfx-border'}`}
          >
            <span className={`inline-block h-5 w-5 rounded-full transition-transform duration-200 shadow
              ${airGapped ? 'translate-x-6 bg-mfx-suspicious' : 'translate-x-1 bg-mfx-muted'}`} />
          </button>

          {/* ── Nav links ─────────────────────────────────────────────── */}
          <nav className="hidden md:flex items-center gap-5 text-sm font-medium"
            style={{ color: 'var(--mfx-muted)' }}>
            <Link to="/about"
              className="hover:text-mfx-accent transition-colors">
              About
            </Link>
            <a href={`${BACKEND_ROOT || 'http://localhost:8000'}/docs`} target="_blank" rel="noopener noreferrer"
              className="hover:text-mfx-accent transition-colors">
              API Docs ↗
            </a>
          </nav>

        </div>
      </div>
    </header>
  )
}

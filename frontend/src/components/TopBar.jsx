/**
 * TopBar — Phase 3 update
 * New: live backend health poll (shows ml_model_loaded status), version badge
 */

import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { checkHealth } from '../lib/api'

export default function TopBar({ airGapped, onToggleAirGap }) {
  const [health, setHealth] = useState(null)   // null=unknown, object=fetched

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
    <header className="sticky top-0 z-50 bg-mfx-bg/80 backdrop-blur-md border-b border-mfx-border">
      <div className="w-full px-6 h-14 flex items-center justify-between">

        {/* Logo */}
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-badge bg-mfx-accent flex items-center justify-center text-xl shadow-glow">
            📧
          </div>
          <div>
            <span className="font-bold text-xl text-mfx-text tracking-tight">MailForen</span>
            <span className="font-bold text-xl text-mfx-accent">SIX</span>
          </div>
          <span className="hidden sm:inline text-xs text-mfx-muted border border-mfx-border px-2 py-0.5 rounded-badge ml-2">
            AI Email Forensics · SIH 2026
          </span>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-3">

          {/* Backend + ML health */}
          <div
            className="hidden md:flex items-center gap-3 text-xs text-mfx-muted"
            title={health
              ? `Backend: ${health.status} | ML: ${health.ml_model_loaded ? 'loaded' : 'heuristic'} | v${health.version}`
              : 'Backend status unknown'}
          >
            <div className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full animate-pulse-dot ${backendOk ? 'bg-mfx-safe' : 'bg-mfx-critical'}`} />
              <span>{backendOk ? 'API' : 'Offline'}</span>
            </div>
            {backendOk && (
              <div className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${mlLoaded ? 'bg-mfx-accent' : 'bg-mfx-suspicious'}`} />
                <span className="hidden lg:inline">{mlLoaded ? 'XGBoost' : 'Heuristic'}</span>
              </div>
            )}
          </div>

          {/* Air-gap mode dot */}
          <div className="flex items-center gap-1.5 text-xs text-mfx-muted">
            <span className={`w-2 h-2 rounded-full animate-pulse-dot ${airGapped ? 'bg-mfx-suspicious' : 'bg-mfx-safe'}`} />
            <span className="hidden sm:inline">{airGapped ? 'Air-gapped' : 'Live APIs'}</span>
          </div>

          {/* Air-gap toggle */}
          <button
            id="air-gap-toggle"
            onClick={onToggleAirGap}
            title="Toggle air-gapped mode (Space)"
            aria-pressed={airGapped}
            className={`relative inline-flex h-6 w-11 items-center rounded-full
              transition-colors duration-200 cursor-pointer border border-mfx-border
              ${airGapped ? 'bg-mfx-suspicious/30 border-mfx-suspicious/50' : 'bg-mfx-surface'}`}
          >
            <span
              className={`inline-block h-4 w-4 rounded-full transition-transform duration-200 shadow
                ${airGapped ? 'translate-x-6 bg-mfx-suspicious' : 'translate-x-1 bg-mfx-muted'}`}
            />
          </button>

          {/* About link */}
          <Link
            to="/about"
            className="text-xs text-mfx-muted hover:text-mfx-accent transition-colors hidden md:inline"
          >
            About
          </Link>

          {/* API Docs link */}
          <a
            href="http://localhost:8000/docs"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-mfx-muted hover:text-mfx-accent transition-colors hidden md:inline"
          >
            API Docs ↗
          </a>
        </div>
      </div>
    </header>
  )
}

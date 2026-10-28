/**
 * PanelRiskGauge — Panel 1 (Phase 3: real data + enhanced UX)
 * Real: risk_score, risk_tier, threat_label, confidence from API
 * New: animated score counter, sender/subject summary, warning count badge
 */

import { useEffect, useRef } from 'react'

const TIER_STYLES = {
  critical:   { color: 'text-mfx-critical',   bg: 'bg-mfx-critical',   badge: 'badge-critical',   label: '🔴 CRITICAL',   ring: 'ring-mfx-critical/40' },
  high:       { color: 'text-mfx-high',        bg: 'bg-mfx-high',       badge: 'badge-high',       label: '🟠 HIGH RISK',  ring: 'ring-mfx-high/40' },
  suspicious: { color: 'text-mfx-suspicious',  bg: 'bg-mfx-suspicious', badge: 'badge-suspicious', label: '🟡 SUSPICIOUS', ring: 'ring-mfx-suspicious/40' },
  safe:       { color: 'text-mfx-safe',        bg: 'bg-mfx-safe',       badge: 'badge-safe',       label: '🟢 SAFE',       ring: 'ring-mfx-safe/40' },
}

function AnimatedScore({ target }) {
  const elRef  = useRef(null)
  const rafRef = useRef(null)

  useEffect(() => {
    let current = 0
    const step  = Math.ceil(target / 30)
    const tick  = () => {
      current = Math.min(current + step, target)
      if (elRef.current) elRef.current.textContent = current
      if (current < target) rafRef.current = requestAnimationFrame(tick)
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafRef.current)
  }, [target])

  return <span ref={elRef}>0</span>
}

export default function PanelRiskGauge({ data, loading }) {
  if (loading) return <SkeletonGauge />

  const tier   = data?.risk_tier   ?? 'safe'
  const score  = data?.risk_score  ?? 0
  const label  = data?.threat_label?.toUpperCase() ?? '—'
  const conf   = data ? `${(data.confidence * 100).toFixed(0)}%` : '—'
  const style  = TIER_STYLES[tier] ?? TIER_STYLES.safe
  const warnCount = data?.warnings?.length ?? 0

  return (
    <div className={`panel animate-slide-up ring-1 ${style.ring}`} id="panel-risk-gauge">
      <div className="flex items-start justify-between mb-1">
        <p className="panel-label">Risk Assessment</p>
        {warnCount > 0 && (
          <span className="text-sm px-1.5 py-0.5 rounded-full bg-mfx-suspicious/20 text-mfx-suspicious font-semibold">
            {warnCount} warning{warnCount > 1 ? 's' : ''}
          </span>
        )}
      </div>

      {/* Animated score */}
      <div className={`text-5xl font-bold tabular-nums ${style.color} mb-1`}>
        <AnimatedScore target={score} />
        <span className="text-xl text-mfx-muted font-normal">/100</span>
      </div>

      {/* Gauge bar */}
      <div className="relative h-2.5 bg-mfx-border rounded-full overflow-hidden mb-3">
        <div
          className="absolute inset-y-0 left-0 rounded-full transition-all duration-700 ease-out
            bg-gradient-to-r from-mfx-safe via-mfx-suspicious via-mfx-high to-mfx-critical"
          style={{ width: `${score}%` }}
        />
      </div>

      {/* Verdict badge + Model Name */}
      <div className="flex items-center justify-between gap-2 mb-3 flex-wrap">
        <span className={`badge ${style.badge}`}>{style.label}</span>
        {data?.model_inference?.model_name && (
          <span className="text-[11px] font-mono font-medium px-2 py-0.5 rounded bg-indigo-500/10 border border-indigo-500/25 text-indigo-300">
            🤖 {data.model_inference.model_name}
          </span>
        )}
      </div>

      {/* Threat details */}
      <div className="divider" />
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div>
          <p className="text-mfx-muted mb-0.5">Threat Classification</p>
          <p className="font-semibold text-mfx-text">{label}</p>
        </div>
        <div>
          <p className="text-mfx-muted mb-0.5">Confidence Score</p>
          <p className={`font-semibold ${style.color}`}>{conf}</p>
        </div>
      </div>

      {/* AICS 3-Class Probability Distribution Bar */}
      {data?.model_inference?.class_probabilities && (
        <div className="mt-2.5 pt-2 border-t border-mfx-border/50 space-y-1">
          <div className="flex items-center justify-between text-[11px] text-mfx-muted">
            <span className="font-semibold text-[10px] uppercase tracking-wider">3-Class Posterior Probabilities</span>
            <span className="font-mono text-[10px]">AICS Module 2</span>
          </div>

          <div className="h-2 w-full rounded-full bg-slate-900 flex overflow-hidden border border-white/10">
            <div
              style={{ width: `${(data.model_inference.class_probabilities.legitimate || 0) * 100}%` }}
              className="bg-emerald-500 transition-all duration-500"
              title={`Legitimate: ${((data.model_inference.class_probabilities.legitimate || 0) * 100).toFixed(1)}%`}
            />
            <div
              style={{ width: `${(data.model_inference.class_probabilities.spam || 0) * 100}%` }}
              className="bg-amber-500 transition-all duration-500"
              title={`Spam: ${((data.model_inference.class_probabilities.spam || 0) * 100).toFixed(1)}%`}
            />
            <div
              style={{ width: `${(data.model_inference.class_probabilities.phishing || 0) * 100}%` }}
              className="bg-rose-500 transition-all duration-500"
              title={`Phishing: ${((data.model_inference.class_probabilities.phishing || 0) * 100).toFixed(1)}%`}
            />
          </div>

          <div className="flex justify-between items-center text-[10px] font-mono pt-0.5">
            <span className="text-emerald-400">Legit: {((data.model_inference.class_probabilities.legitimate || 0) * 100).toFixed(1)}%</span>
            <span className="text-amber-400">Spam: {((data.model_inference.class_probabilities.spam || 0) * 100).toFixed(1)}%</span>
            <span className="text-rose-400">Phish: {((data.model_inference.class_probabilities.phishing || 0) * 100).toFixed(1)}%</span>
          </div>
        </div>
      )}

      {/* 4-Pillar Risk Vector Breakdown Chart */}
      {data?.risk_breakdown && (
        <>
          <div className="divider" />
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold uppercase tracking-wider text-mfx-muted text-[11px]">
                Risk Vector Contribution
              </span>
              <span className="text-[10px] text-mfx-muted font-mono">{score}/100 pts</span>
            </div>

            {/* Stacked multi-vector bar */}
            <div className="h-2 w-full rounded-full bg-mfx-surface flex overflow-hidden border border-mfx-border/60">
              <div
                style={{ width: `${(data.risk_breakdown.auth_weighted / 100) * 100}%` }}
                className="bg-purple-500 transition-all duration-500"
                title={`Auth Risk: ${data.risk_breakdown.auth_weighted} pts (max 30)`}
              />
              <div
                style={{ width: `${(data.risk_breakdown.intent_weighted / 100) * 100}%` }}
                className="bg-blue-500 transition-all duration-500"
                title={`ML Intent Risk: ${data.risk_breakdown.intent_weighted} pts (max 30)`}
              />
              <div
                style={{ width: `${(data.risk_breakdown.geo_weighted / 100) * 100}%` }}
                className="bg-sky-500 transition-all duration-500"
                title={`Relay Geo Risk: ${data.risk_breakdown.geo_weighted} pts (max 20)`}
              />
              <div
                style={{ width: `${(data.risk_breakdown.domain_weighted / 100) * 100}%` }}
                className="bg-rose-500 transition-all duration-500"
                title={`Domain Risk: ${data.risk_breakdown.domain_weighted} pts (max 20)`}
              />
            </div>

            {/* Pillar badges with points */}
            <div className="grid grid-cols-2 gap-1.5 pt-1 text-[11px]">
              <div className="flex items-center justify-between px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-300">
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-purple-400" /> Auth
                </span>
                <span className="font-mono font-semibold">{data.risk_breakdown.auth_weighted} <span className="opacity-60 text-[9px]">/30</span></span>
              </div>
              <div className="flex items-center justify-between px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-300">
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-400" /> ML Intent
                </span>
                <span className="font-mono font-semibold">{data.risk_breakdown.intent_weighted} <span className="opacity-60 text-[9px]">/30</span></span>
              </div>
              <div className="flex items-center justify-between px-1.5 py-0.5 rounded bg-sky-500/10 border border-sky-500/20 text-sky-300">
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-sky-400" /> Relay/Geo
                </span>
                <span className="font-mono font-semibold">{data.risk_breakdown.geo_weighted} <span className="opacity-60 text-[9px]">/20</span></span>
              </div>
              <div className="flex items-center justify-between px-1.5 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-300">
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-400" /> Domain
                </span>
                <span className="font-mono font-semibold">{data.risk_breakdown.domain_weighted} <span className="opacity-60 text-[9px]">/20</span></span>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Sender summary */}
      {data?.sender && (
        <>
          <div className="divider" />
          <div className="text-sm space-y-1">
            <div className="flex gap-1 items-start">
              <span className="text-mfx-muted shrink-0 w-14">From:</span>
              <span className="font-mono text-mfx-text truncate">{data.sender}</span>
            </div>
            {data.subject && (
              <div className="flex gap-1 items-start">
                <span className="text-mfx-muted shrink-0 w-14">Subject:</span>
                <span className="text-mfx-text truncate">{data.subject}</span>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}

function SkeletonGauge() {
  return (
    <div className="panel" id="panel-risk-gauge-skeleton">
      <p className="panel-label">Risk Assessment</p>
      <div className="skeleton h-10 w-28 mb-2" />
      <div className="skeleton h-2.5 w-full mb-3" />
      <div className="skeleton h-5 w-24 mb-3" />
      <div className="divider" />
      <div className="grid grid-cols-2 gap-2">
        <div className="skeleton h-8" />
        <div className="skeleton h-8" />
      </div>
    </div>
  )
}

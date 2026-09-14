/**
 * PanelLimeHeatmap — Panel 4 (Phase 3)
 * Real: lime_sentences[{text, score, explanation}] from API
 * New: score-proportional opacity, tooltip on hover, sorted by score desc,
 *      model status badge, score legend with actual values
 */

import { useState } from 'react'

function scoreToStyle(score) {
  if (score >= 0.6) return { bg: 'bg-red-500/30',    text: 'text-red-200',   border: 'border-red-500/40' }
  if (score >= 0.3) return { bg: 'bg-orange-500/20', text: 'text-orange-200', border: 'border-orange-500/30' }
  if (score >= 0.1) return { bg: 'bg-yellow-500/15', text: 'text-yellow-200', border: 'border-yellow-500/20' }
  return               { bg: 'bg-green-500/10',  text: 'text-green-300',  border: 'border-green-500/20' }
}

function LimeToken({ item }) {
  const [showTip, setShowTip] = useState(false)
  const s = scoreToStyle(item.score)
  const opacity = 0.4 + item.score * 0.6  // 0.4 → 1.0 based on score

  return (
    <span className="relative inline-block">
      <span
        className={`inline px-1 py-0.5 rounded-sm cursor-help border ${s.bg} ${s.text} ${s.border} transition-all`}
        style={{ opacity }}
        onMouseEnter={() => setShowTip(true)}
        onMouseLeave={() => setShowTip(false)}
      >
        {item.text}
      </span>
      {showTip && (
        <span className="absolute bottom-full left-0 z-50 mb-1 w-56 p-2 bg-mfx-surface border border-mfx-border rounded-md shadow-xl text-xs text-mfx-text pointer-events-none">
          <span className="font-semibold text-mfx-accent block mb-0.5">Score: {(item.score * 100).toFixed(0)}%</span>
          {item.explanation}
        </span>
      )}
      {' '}
    </span>
  )
}

export default function PanelLimeHeatmap({ data, loading }) {
  if (loading) return <SkeletonLime />

  const raw       = data?.lime_sentences ?? []
  const isMLModel = !data?.warnings?.some(w => w.includes('XGBoost model not loaded'))
  // Sort by score descending for display
  const sentences = [...raw].sort((a, b) => b.score - a.score)

  return (
    <div className="panel animate-slide-up" id="panel-lime-heatmap">
      <div className="flex items-center justify-between mb-3">
        <p className="panel-label mb-0">AI Explanation — LIME</p>
        <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-semibold ${
          isMLModel ? 'bg-mfx-safe/20 text-mfx-safe' : 'bg-mfx-suspicious/20 text-mfx-suspicious'
        }`}>
          {isMLModel ? '🤖 XGBoost+LIME' : '📐 Heuristic'}
        </span>
      </div>

      {sentences.length === 0 ? (
        <p className="text-xs text-mfx-muted">No explanation available for this email.</p>
      ) : (
        <div className="space-y-1 text-sm leading-relaxed">
          {sentences.map((s, i) => (
            <LimeToken key={i} item={s} />
          ))}
        </div>
      )}

      <div className="divider" />
      <div className="flex flex-wrap gap-3 text-xs text-mfx-muted items-center">
        <div className="flex items-center gap-1">
          <span className="w-3 h-3 rounded-sm bg-red-500/30 border border-red-500/40 inline-block" />
          <span>High threat</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-3 h-3 rounded-sm bg-orange-500/20 border border-orange-500/30 inline-block" />
          <span>Moderate</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-3 h-3 rounded-sm bg-green-500/10 border border-green-500/20 inline-block" />
          <span>Benign</span>
        </div>
        <span className="ml-auto text-mfx-muted/60">Hover tokens for details</span>
      </div>
    </div>
  )
}

function SkeletonLime() {
  return (
    <div className="panel" id="panel-lime-heatmap-skeleton">
      <p className="panel-label">AI Explanation — LIME</p>
      <div className="space-y-2">
        <div className="skeleton h-4 w-full" />
        <div className="skeleton h-4 w-4/5" />
        <div className="skeleton h-4 w-3/5" />
      </div>
    </div>
  )
}

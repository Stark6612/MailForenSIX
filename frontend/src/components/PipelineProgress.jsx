/**
 * PipelineProgress — animated stage labels shown during loading
 * Mirrors the UX_Dev.md spec: "Parsing → Auth → NLP → Geo → Report"
 */

const STAGES = ['Parsing', 'Auth Validation', 'NLP Classification', 'Geo Tracing', 'Domain Intel', 'Risk Engine']

export default function PipelineProgress({ stage }) {
  return (
    <div className="mt-4 panel animate-fade-in">
      <p className="panel-label">Analysis Pipeline</p>
      <div className="flex items-center gap-2 flex-wrap">
        {STAGES.map((s, i) => (
          <div key={s} className="flex items-center gap-1.5">
            <span
              className={`text-sm px-2 py-0.5 rounded-badge border transition-all duration-300
                ${stage === s
                  ? 'bg-mfx-accent/20 border-mfx-accent text-mfx-accent font-semibold shadow-glow animate-pulse'
                  : STAGES.indexOf(stage) > i
                    ? 'bg-mfx-safe/10 border-mfx-safe/30 text-mfx-safe'
                    : 'border-mfx-border text-mfx-muted'
                }`}
            >
              {stage === s && <span className="mr-1">⟳</span>}
              {STAGES.indexOf(stage) > i && <span className="mr-1">✓</span>}
              {s}
            </span>
            {i < STAGES.length - 1 && <span className="text-mfx-border">›</span>}
          </div>
        ))}
      </div>
      <div className="mt-3 h-1 bg-mfx-border rounded-full overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-mfx-accent to-mfx-safe transition-all duration-700 ease-out rounded-full"
          style={{ width: `${Math.max(5, (STAGES.indexOf(stage) + 1) / STAGES.length * 100)}%` }}
        />
      </div>
    </div>
  )
}

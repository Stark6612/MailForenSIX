import { useState, useEffect, useRef, useCallback } from 'react'
import { Toaster, toast } from 'react-hot-toast'
import { useAnalysis, STATUS } from './hooks/useAnalysis'
import { exportPDF } from './lib/api'
import TopBar from './components/TopBar'
import UploadZone from './components/UploadZone'
import ErrorBoundary from './components/ErrorBoundary'
import PanelRiskGauge from './components/panels/PanelRiskGauge'
import PanelAuthMatrix from './components/panels/PanelAuthMatrix'
import PanelLimeHeatmap from './components/panels/PanelLimeHeatmap'
import PanelLeafletMap from './components/panels/PanelLeafletMap'
import PanelRelayTable from './components/panels/PanelRelayTable'
import PanelDomainIntel from './components/panels/PanelDomainIntel'
import PanelDossier from './components/panels/PanelDossier'
import PipelineProgress from './components/PipelineProgress'
import ErrorBanner from './components/ErrorBanner'
import ScrollReveal from './components/animations/ScrollReveal'
import Campaign from './pages/Campaign'
import ModelComparison from './pages/ModelComparison'

export default function App() {
  const [airGapped,      setAirGapped]      = useState(false)
  const [emlFile,        setEmlFile]        = useState(null)
  const [rawText,        setRawText]        = useState('')
  const [page,           setPage]           = useState('triage')  // 'triage' | 'campaign' | 'models'
  const [selectedModel,  setSelectedModel]  = useState('lr')      // 'lr' | 'svm' | 'nb' | 'dt' | 'xgb'
  const analyzeRef   = useRef(null)
  const timeoutRef   = useRef(null)    // Phase 4 — 60s timeout guard
  const exportingRef = useRef(false)   // prevent double-trigger

  const { status, result, error, stage, run, reset } = useAnalysis()

  const handleAnalyze = useCallback(async () => {
    if (!emlFile && !rawText.trim()) {
      toast.error('Drop an .eml file or paste raw headers first.')
      return
    }
    // 60-second timeout guard (Phase 4)
    if (timeoutRef.current) clearTimeout(timeoutRef.current)
    timeoutRef.current = setTimeout(() => {
      if (status === STATUS.LOADING) {
        reset()
        toast.error('Analysis timed out after 60 seconds. The backend may be overloaded.', { duration: 6000 })
      }
    }, 60_000)
    await run(emlFile, rawText || null, selectedModel)
    if (timeoutRef.current) clearTimeout(timeoutRef.current)
  }, [emlFile, rawText, selectedModel, run, reset, status])

  /* ── Keyboard shortcuts ─────────────────────────────────────────────────── */
  useEffect(() => {
    const handler = (e) => {
      if (e.ctrlKey && e.key === 'Enter') {
        e.preventDefault()
        handleAnalyze()
      }
      if (e.ctrlKey && e.key === 'e') {
        e.preventDefault()
        if (!result) {
          toast('No analysis to export yet — analyze an email first.', { icon: '📄' })
          return
        }
        if (exportingRef.current) return
        exportingRef.current = true
        const tid = toast.loading('Generating PDF dossier…')
        exportPDF(result)
          .then(blob => {
            const slug = result?.forensic?.email_sha256?.slice(0, 12) ?? 'report'
            const url  = URL.createObjectURL(blob)
            const a    = document.createElement('a')
            a.href = url; a.download = `mailforensix_${slug}.pdf`; a.click()
            URL.revokeObjectURL(url)
            toast.success(`PDF exported — mailforensix_${slug}.pdf`, { id: tid })
          })
          .catch(err => toast.error(`PDF failed: ${err?.response?.data?.detail ?? err.message}`, { id: tid }))
          .finally(() => { exportingRef.current = false })
      }
      if (e.key === 'Escape') {
        // Close any open modals — panels handle this internally
      }
      if (e.key === ' ' && e.target === document.body) {
        e.preventDefault()
        setAirGapped(prev => {
          const next = !prev
          toast(next ? '🔌 Air-gapped mode ON — live APIs disabled.' : '🌐 Air-gapped mode OFF — live APIs enabled.')
          return next
        })
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [handleAnalyze])

  const isLoading = status === STATUS.LOADING
  const isSuccess = status === STATUS.SUCCESS
  const isError   = status === STATUS.ERROR

  return (
    <div className="min-h-dvh flex flex-col bg-mfx-bg text-mfx-text">
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#1E293B',
            color: '#F8FAFC',
            border: '1px solid #334155',
            fontFamily: 'Inter, sans-serif',
            fontSize: '13px',
          },
        }}
      />

      {/* ── Top navigation bar ─────────────────────────────────────────── */}
      <TopBar airGapped={airGapped} currentAnalysis={result} onToggleAirGap={() => {
        setAirGapped(p => {
          const next = !p
          toast(next ? '🔌 Air-gapped ON' : '🌐 Air-gapped OFF')
          return next
        })
      }} />

      {/* Mode tabs */}
      <div style={{ display: "flex", gap: 0, borderBottom: "1px solid rgba(255,255,255,0.06)", background: "#0f0f1a" }}>
        {[
          { key: "triage",   label: "Mode 1 — Email Triage & Threat Analysis" },
          { key: "campaign", label: "Mode 2 — Campaign Intelligence (UMAP/HDBSCAN)" },
          { key: "models",   label: "Mode 3 — AICS Model Benchmark & Comparison" }
        ].map(tab => (
          <button key={tab.key} onClick={() => setPage(tab.key)} style={{
            padding: "0.6rem 1.4rem", fontSize: "0.82rem", fontWeight: 600,
            background: "transparent", border: "none", cursor: "pointer",
            color: page === tab.key ? "#818cf8" : "#94a3b8",
            borderBottom: page === tab.key ? "2px solid #818cf8" : "2px solid transparent",
            transition: "all 0.15s",
          }}>{tab.label}</button>
        ))}
      </div>

      {page === "campaign" && <Campaign />}
      {page === "models" && <ModelComparison />}

      {page === "triage" && <main className="flex-1 px-6 py-4 w-full">

        {/* ── Upload zone + analyze trigger ──────────────────────────── */}
        <UploadZone
          emlFile={emlFile}
          rawText={rawText}
          onFileChange={setEmlFile}
          onTextChange={setRawText}
          onAnalyze={handleAnalyze}
          isLoading={isLoading}
          onReset={reset}
          selectedModel={selectedModel}
          onModelChange={setSelectedModel}
        />

        {/* ── Pipeline progress ───────────────────────────────────────── */}
        {isLoading && <PipelineProgress stage={stage} />}

        {/* ── Error banner ────────────────────────────────────────────── */}
        {isError && <ErrorBanner message={error} onDismiss={reset} />}

        {/* ── 7-Panel dashboard grid with ScrollReveal ──────────────────── */}
        {(isSuccess || isLoading) && (
          <ErrorBoundary onReset={reset}>
            <div className="mt-6 space-y-4">
              {/* Section Header */}
              <div className="flex items-center justify-between px-1">
                <h2 className="text-xl font-bold tracking-tight text-mfx-text flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-mfx-accent animate-pulse" />
                  Forensic Intelligence Dossier
                </h2>
                <span className="text-xs text-mfx-muted font-mono uppercase tracking-wider">
                  7 Analysis Engines Active
                </span>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* Row 1 */}
                <ScrollReveal baseRotation={0.4} baseOpacity={0.3} blurStrength={0} containerClassName="h-full">
                  <PanelRiskGauge data={result} loading={isLoading} />
                </ScrollReveal>

                <ScrollReveal baseRotation={0.4} baseOpacity={0.3} blurStrength={0} containerClassName="h-full">
                  <PanelAuthMatrix data={result} loading={isLoading} />
                </ScrollReveal>

                <ScrollReveal baseRotation={0.4} baseOpacity={0.3} blurStrength={0} containerClassName="h-full">
                  <PanelLeafletMap data={result} loading={isLoading} airGapped={airGapped} />
                </ScrollReveal>

                {/* Row 2 */}
                <ScrollReveal baseRotation={0.4} baseOpacity={0.3} blurStrength={0} containerClassName="h-full">
                  <PanelLimeHeatmap data={result} loading={isLoading} />
                </ScrollReveal>

                <ScrollReveal baseRotation={0.4} baseOpacity={0.3} blurStrength={0} containerClassName="h-full">
                  <PanelRelayTable data={result} loading={isLoading} />
                </ScrollReveal>

                <ScrollReveal baseRotation={0.4} baseOpacity={0.3} blurStrength={0} containerClassName="h-full">
                  <PanelDomainIntel data={result} loading={isLoading} />
                </ScrollReveal>

                {/* Row 3 — full-width dossier strip */}
                <div className="lg:col-span-3">
                  <ScrollReveal baseRotation={0.3} baseOpacity={0.3} blurStrength={0} containerClassName="w-full">
                    <PanelDossier data={result} loading={isLoading} airGapped={airGapped} />
                  </ScrollReveal>
                </div>
              </div>
            </div>
          </ErrorBoundary>
        )}

        {/* ── Idle state hint ─────────────────────────────────────────── */}
        {status === STATUS.IDLE && (
          <ScrollReveal baseRotation={0} baseOpacity={0.4} blurStrength={0} containerClassName="mt-16 w-full">
            <div className="flex flex-col items-center gap-4 text-mfx-muted">
              <div className="w-16 h-16 rounded-2xl bg-mfx-accent/10 border border-mfx-accent/20 flex items-center justify-center text-3xl shadow-glow">
                🔍
              </div>
              <p className="text-2xl font-bold tracking-tight text-mfx-text">Upload a suspicious email to begin analysis</p>
              <p className="text-base text-mfx-muted">Supports <code className="text-mfx-accent font-semibold">.eml</code> files or raw header pastes</p>
              <div className="flex gap-4 mt-2 text-sm text-mfx-muted flex-wrap justify-center">
                <div className="flex items-center gap-2 bg-mfx-surface/80 border border-white/[0.08] px-3.5 py-1.5 rounded-lg">
                  <kbd className="px-2 py-0.5 bg-mfx-bg border border-mfx-border rounded text-xs font-mono text-mfx-accent">Ctrl+Enter</kbd>
                  <span>to analyze</span>
                </div>
                <div className="flex items-center gap-2 bg-mfx-surface/80 border border-white/[0.08] px-3.5 py-1.5 rounded-lg">
                  <kbd className="px-2 py-0.5 bg-mfx-bg border border-mfx-border rounded text-xs font-mono text-mfx-accent">Ctrl+E</kbd>
                  <span>to export</span>
                </div>
                <div className="flex items-center gap-2 bg-mfx-surface/80 border border-white/[0.08] px-3.5 py-1.5 rounded-lg">
                  <kbd className="px-2 py-0.5 bg-mfx-bg border border-mfx-border rounded text-xs font-mono text-mfx-accent">Space</kbd>
                  <span>air-gap toggle</span>
                </div>
              </div>
            </div>
          </ScrollReveal>
        )}
      </main>}
    </div>
  )
}

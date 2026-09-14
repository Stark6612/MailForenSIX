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

export default function App() {
  const [airGapped, setAirGapped] = useState(false)
  const [emlFile,   setEmlFile]   = useState(null)
  const [rawText,   setRawText]   = useState('')
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
    await run(emlFile, rawText || null)
    if (timeoutRef.current) clearTimeout(timeoutRef.current)
  }, [emlFile, rawText, run, reset, status])

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
      <TopBar airGapped={airGapped} onToggleAirGap={() => {
        setAirGapped(p => {
          const next = !p
          toast(next ? '🔌 Air-gapped ON' : '🌐 Air-gapped OFF')
          return next
        })
      }} />

      <main className="flex-1 px-6 py-4 w-full">

        {/* ── Upload zone + analyze trigger ──────────────────────────── */}
        <UploadZone
          emlFile={emlFile}
          rawText={rawText}
          onFileChange={setEmlFile}
          onTextChange={setRawText}
          onAnalyze={handleAnalyze}
          isLoading={isLoading}
          onReset={reset}
        />

        {/* ── Pipeline progress ───────────────────────────────────────── */}
        {isLoading && <PipelineProgress stage={stage} />}

        {/* ── Error banner ────────────────────────────────────────────── */}
        {isError && <ErrorBanner message={error} onDismiss={reset} />}

        {/* ── 7-Panel dashboard grid ────────────────────────────────────── */}
        {(isSuccess || isLoading) && (
          <ErrorBoundary onReset={reset}>
            <div className="mt-4 grid grid-cols-1 lg:grid-cols-3 gap-4">

              {/* Row 1 */}
              <PanelRiskGauge   data={result} loading={isLoading} />
              <PanelAuthMatrix  data={result} loading={isLoading} />
              <PanelLeafletMap  data={result} loading={isLoading} airGapped={airGapped} />

              {/* Row 2 */}
              <PanelLimeHeatmap  data={result} loading={isLoading} />
              <PanelRelayTable   data={result} loading={isLoading} />
              <PanelDomainIntel  data={result} loading={isLoading} />

              {/* Row 3 — full-width dossier strip */}
              <div className="lg:col-span-3">
                <PanelDossier data={result} loading={isLoading} airGapped={airGapped} />
              </div>
            </div>
          </ErrorBoundary>
        )}

        {/* ── Idle state hint ─────────────────────────────────────────── */}
        {status === STATUS.IDLE && (
          <div className="mt-16 flex flex-col items-center gap-4 text-mfx-muted animate-fade-in">
            <div className="text-6xl">🔍</div>
            <p className="text-xl font-semibold text-mfx-text">Upload a suspicious email to begin analysis</p>
            <p className="text-base">Supports <code className="text-mfx-accent">.eml</code> files or raw header paste</p>
            <div className="flex gap-5 mt-3 text-sm text-mfx-muted flex-wrap justify-center">
              <kbd className="px-3 py-1.5 bg-mfx-surface border border-mfx-border rounded-badge font-mono">Ctrl+Enter</kbd>
              <span className="self-center">to analyze</span>
              <kbd className="px-3 py-1.5 bg-mfx-surface border border-mfx-border rounded-badge font-mono">Ctrl+E</kbd>
              <span className="self-center">to export</span>
              <kbd className="px-3 py-1.5 bg-mfx-surface border border-mfx-border rounded-badge font-mono">Space</kbd>
              <span className="self-center">air-gap toggle</span>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

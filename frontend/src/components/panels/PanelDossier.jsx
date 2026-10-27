/**
 * PanelDossier — Panel 7 (Phase 4 — full-width bottom strip)
 * FIX: All hooks moved before any conditional return (Rules of Hooks).
 */

import { useEffect, useState } from 'react'
import { toast } from 'react-hot-toast'
import { exportPDF, anchorHash } from '../../lib/api'


// ── IT Act 2000 — contextual section selector ─────────────────────────────────
// Instead of always showing all 4 sections, we pick which ones apply
// based on the actual signals detected in the analysis.
const ALL_IT_ACT = {
  '§43':  'Penalty and compensation for damage to computer, computer system, etc.',
  '§66':  'Computer related offences — hacking, impersonation, fraud via computer resource',
  '§66C': 'Punishment for identity theft using digital means',
  '§66D': 'Cheating by personation using computer resource',
}

function getApplicableSections(data) {
  if (!data) return [{ section: '§43', desc: ALL_IT_ACT['§43'], reason: 'Baseline — any unauthorized computer interaction' }]

  const sections = []
  const tier     = data.risk_tier ?? 'safe'
  const label    = data.threat_label ?? 'safe'
  const spf      = data.auth?.spf   ?? 'none'
  const dkim     = data.auth?.dkim  ?? 'none'
  const dmarc    = data.auth?.dmarc ?? 'none'
  const privProxy= data.domain_intel?.privacy_proxy ?? false
  const newDomain= (data.domain_intel?.age_days ?? 999) < 60
  const warnings = data.warnings ?? []
  const hasSpoofWarn = warnings.some(w => w.toLowerCase().includes('spoof') || w.toLowerCase().includes('align'))

  // §43 — always applicable when an email causes or attempts unauthorised interaction
  sections.push({ section: '§43', desc: ALL_IT_ACT['§43'], reason: 'Applicable to any fraudulent email interaction with computer systems' })

  // §66 — computer-related offence; applies when risk is suspicious or higher
  if (['suspicious', 'high', 'critical'].includes(tier)) {
    sections.push({ section: '§66', desc: ALL_IT_ACT['§66'], reason: `Risk tier: ${tier.toUpperCase()} — indicates deliberate fraudulent computer use` })
  }

  // §66C — identity theft; applies when auth fails (spoofed sender) or impersonation label
  if (dkim === 'fail' || dmarc === 'fail' || label === 'impersonation' || hasSpoofWarn) {
    const why = dkim === 'fail' ? 'DKIM FAIL (sender identity cannot be verified)'
              : dmarc === 'fail' ? 'DMARC FAIL (domain policy violated — likely spoofed)'
              : 'Display-name or sender domain spoofing detected'
    sections.push({ section: '§66C', desc: ALL_IT_ACT['§66C'], reason: why })
  }

  // §66D — cheating by personation; applies for BEC, impersonation, or privacy-proxy + phishing
  if (label === 'bec' || label === 'impersonation' || label === 'phishing') {
    const why = label === 'bec' ? 'Business Email Compromise pattern detected'
              : label === 'impersonation' ? 'Email impersonates a trusted entity'
              : privProxy ? 'Phishing via privacy-proxy-registered domain'
              : 'Phishing email — personation via deceptive communication'
    sections.push({ section: '§66D', desc: ALL_IT_ACT['§66D'], reason: why })
  }

  return sections
}


export default function PanelDossier({ data, loading, airGapped }) {
  // ── ALL hooks MUST be before any conditional return ──────────────────────────
  const [exporting,  setExporting]  = useState(false)
  const [anchoring,  setAnchoring]  = useState(false)
  const [anchorInfo, setAnchorInfo] = useState(null)

  const forensic   = data?.forensic
  const hash       = forensic?.email_sha256 ?? '—'
  const analysisId = data?.analysis_id

  // Load anchor info from API response or localStorage
  useEffect(() => {
    if (forensic?.anchor_tx_id) {
      setAnchorInfo({
        tx_id:   forensic.anchor_tx_id,
        status:  forensic.anchor_status,
        backend: forensic.anchor_backend,
      })
    } else if (hash !== '—') {
      const stored = localStorage.getItem(`mfx_anchor_${hash.slice(0, 16)}`)
      if (stored) {
        try { setAnchorInfo(JSON.parse(stored)) } catch { /* ignore */ }
      }
    }
  }, [forensic, hash])

  // Persist last-analysis info to localStorage
  useEffect(() => {
    if (data && hash !== '—') {
      localStorage.setItem('mfx_last_analysis', JSON.stringify({
        hash,
        timestamp: forensic?.analysis_timestamp,
        risk_tier: data.risk_tier,
        subject:   data.subject ?? '(no subject)',
      }))
    }
  }, [data, hash, forensic])

  // ── Now safe to do conditional skeleton return ────────────────────────────────
  if (loading) return <SkeletonDossier />

  const ts = forensic?.analysis_timestamp
    ? new Date(forensic.analysis_timestamp).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })
    : '—'

  const handleCopyHash = async () => {
    try {
      await navigator.clipboard.writeText(hash)
      toast.success(`SHA-256 copied: ${hash.slice(0, 8)}…`)
    } catch {
      toast.error('Clipboard access denied')
    }
  }

  const handleCopyTxId = async () => {
    if (!anchorInfo?.tx_id) return
    try {
      await navigator.clipboard.writeText(anchorInfo.tx_id)
      toast.success('TX ID copied!')
    } catch {
      toast.error('Clipboard access denied')
    }
  }

  // ── Real PDF export ──────────────────────────────────────────────────────────
  const handleExportPDF = async () => {
    if (!data) return toast.error('No analysis data to export.')
    setExporting(true)
    const toastId = toast.loading('Generating PDF dossier…')
    try {
      const blob     = await exportPDF(data)
      const slug     = hash !== '—' ? hash.slice(0, 12) : 'report'
      const filename = `mailforensix_${slug}.pdf`
      const url = URL.createObjectURL(blob)
      const a   = document.createElement('a')
      a.href = url; a.download = filename; a.click()
      URL.revokeObjectURL(url)
      toast.success(`PDF exported — ${filename}`, { id: toastId })
    } catch (err) {
      toast.error(`PDF export failed: ${err?.response?.data?.detail ?? err.message}`, { id: toastId })
    } finally {
      setExporting(false)
    }
  }

  // ── Blockchain anchor ────────────────────────────────────────────────────────
  const handleAnchor = async () => {
    if (hash === '—') return
    setAnchoring(true)
    const toastId = toast.loading('Anchoring hash to OpenTimestamps…')
    try {
      const result = await anchorHash(hash)
      setAnchorInfo(result)
      localStorage.setItem(`mfx_anchor_${hash.slice(0, 16)}`, JSON.stringify(result))
      const label = result.backend === 'opentimestamps'
        ? `OTS pending — TX: ${result.tx_id}`
        : `Local anchor saved — ${result.tx_id}`
      toast.success(label, { id: toastId, duration: 5000 })
    } catch (err) {
      toast.error(`Anchor failed: ${err?.response?.data?.detail ?? err.message}`, { id: toastId })
    } finally {
      setAnchoring(false)
    }
  }

  // ── Anchor badge ─────────────────────────────────────────────────────────────
  const AnchorBadge = () => {
    if (!anchorInfo) return null
    const isOts   = anchorInfo.backend === 'opentimestamps'
    const colorCls = isOts
      ? 'text-mfx-safe border-mfx-safe/40 bg-mfx-safe/10'
      : 'text-mfx-suspicious border-mfx-suspicious/40 bg-mfx-suspicious/10'
    const icon  = isOts ? '🔒' : '📁'
    const label = isOts ? 'OTS Pending' : 'Local Anchor'
    return (
      <div className={`flex items-center gap-1.5 px-2 py-1 rounded border text-[11px] font-semibold ${colorCls} mt-1`}>
        <span>{icon}</span>
        <span>{label}</span>
        <span className="opacity-60">·</span>
        <code
          className="font-mono text-xs opacity-80 cursor-pointer hover:opacity-100"
          title={anchorInfo.tx_id}
          onClick={handleCopyTxId}
        >
          {anchorInfo.tx_id.slice(0, 20)}…
        </code>
        <button onClick={handleCopyTxId} className="text-[9px] px-1 py-0.5 rounded bg-white/10 hover:bg-white/20 transition-colors">
          copy
        </button>
      </div>
    )
  }

  return (
    <div className="panel animate-slide-up border-mfx-accent/20" id="panel-dossier">
      <div className="flex flex-col lg:flex-row lg:items-start gap-4">

        {/* Left — forensic metadata */}
        <div className="flex-1 space-y-3 min-w-0">
          <p className="panel-label mb-0">Forensic Dossier</p>

          {/* SHA-256 */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm text-mfx-muted shrink-0">SHA-256:</span>
            <code
              onClick={handleCopyHash}
              className="text-sm font-mono text-mfx-accent cursor-pointer hover:underline hover:text-mfx-accent/80 truncate max-w-[320px] sm:max-w-[480px] transition-colors"
              title="Click to copy full hash"
              id="sha256-hash-display"
            >
              {hash}
            </code>
            <button
              onClick={handleCopyHash}
              className="text-sm px-1.5 py-0.5 rounded bg-mfx-accent/10 text-mfx-accent hover:bg-mfx-accent/20 transition-colors font-semibold"
              id="copy-hash-inline-btn"
            >
              copy
            </button>
          </div>

          <AnchorBadge />

          {/* Meta row */}
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-mfx-muted">
            <div className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full animate-pulse-dot ${airGapped ? 'bg-mfx-suspicious' : 'bg-mfx-safe'}`} />
              <span>Ledger: {airGapped ? 'Local hash (air-gapped)' : anchorInfo ? 'Hash anchored' : 'Pending anchor'}</span>
            </div>
            <span>·</span>
            <span>Analyzed: {ts}</span>
            {analysisId && <><span>·</span><span className="font-mono text-xs">ID: {analysisId.slice(0, 8)}…</span></>}
            {forensic?.air_gapped && <><span>·</span><span className="text-mfx-suspicious">Air-gapped mode</span></>}
          </div>

          {/* IT Act references — contextual, data-driven */}
          <div className="space-y-1.5">
            <p className="text-sm text-mfx-muted uppercase tracking-wide font-semibold">Applicable Legal Sections</p>
            <div className="flex flex-wrap gap-2">
              {getApplicableSections(data).map(ref => (
                <div
                  key={ref.section}
                  title={ref.reason}
                  className="group flex flex-col px-2 py-1 rounded bg-mfx-surface border border-mfx-border hover:border-mfx-accent/50 transition-colors cursor-help"
                >
                  <span className="text-[11px] font-semibold text-mfx-text">IT Act 2000 {ref.section}</span>
                  <span className="text-[9px] text-mfx-muted max-w-[160px] leading-tight">{ref.desc}</span>
                  <span className="text-[9px] text-mfx-accent/70 max-w-[160px] leading-tight mt-0.5 hidden group-hover:block">{ref.reason}</span>
                </div>
              ))}
            </div>
          </div>

        </div>

        {/* Right — risk weights legend + actions */}
        <div className="flex flex-col gap-3 shrink-0">
          {/* Engine weight legend */}
          <div className="text-sm text-mfx-muted space-y-0.5 bg-mfx-bg/60 rounded-md p-2 border border-mfx-border min-w-[140px]">
            <p className="font-semibold text-mfx-muted/80 uppercase tracking-wide mb-1">Risk Weights</p>
            {[['Auth', '30%'], ['ML Intent', '30%'], ['Geo', '20%'], ['Domain', '20%']].map(([k, v]) => (
              <div key={k} className="flex justify-between gap-3">
                <span>{k}</span><span className="font-semibold text-mfx-text">{v}</span>
              </div>
            ))}
          </div>

          {/* Action buttons */}
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <button id="copy-hash-btn" onClick={handleCopyHash} className="btn-ghost text-xs">
                📋 Copy Hash
              </button>
              <button
                id="export-pdf-btn"
                onClick={handleExportPDF}
                disabled={exporting || !data}
                className="btn-primary text-xs disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
                title="Export PDF dossier (Ctrl+E)"
              >
                {exporting
                  ? <><span className="animate-spin inline-block">⏳</span> Generating…</>
                  : <>📄 Export <span className="opacity-50 text-xs ml-1">Ctrl+E</span></>
                }
              </button>
            </div>

            {hash !== '—' && (
              <button
                id="anchor-hash-btn"
                onClick={handleAnchor}
                disabled={anchoring || !!anchorInfo}
                className="btn-ghost text-xs disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1.5 w-full justify-center"
                title="Anchor SHA-256 to Bitcoin testnet via OpenTimestamps"
              >
                {anchoring
                  ? <><span className="animate-spin inline-block">⏳</span> Anchoring…</>
                  : anchorInfo
                    ? `✅ ${anchorInfo.backend === 'opentimestamps' ? 'OTS Anchored' : 'Locally Saved'}`
                    : '⛓ Anchor Hash'
                }
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Warnings */}
      {data?.warnings?.length > 0 && (
        <div className="mt-3 pt-3 border-t border-mfx-border space-y-1">
          {data.warnings.map((w, i) => (
            <p key={i} className="text-sm text-mfx-suspicious flex items-start gap-1.5">
              <span>&#9888;</span> {w}
            </p>
          ))}
        </div>
      )}

      {/* Attachment Forensics & Static Malware Triage */}
      {data?.attachments?.length > 0 && (
        <div className="mt-3 pt-3 border-t border-mfx-border space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-sm text-mfx-muted uppercase tracking-wide font-semibold">
              Attachment Forensic Triage & Malware Analysis ({data.attachments.length})
            </p>
            <span className="text-xs text-mfx-muted">Static Heuristics & Cryptographic Hashes</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {data.attachments.map((att, idx) => (
              <div
                key={idx}
                className="bg-mfx-bg/70 rounded-md p-3 border border-mfx-border space-y-2 relative"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <span className="text-lg">📎</span>
                    <span className="font-semibold text-sm text-mfx-text truncate" title={att.filename}>
                      {att.filename}
                    </span>
                    <span className="text-xs text-mfx-muted shrink-0">({att.size_formatted})</span>
                  </div>
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wider shrink-0 ${
                      att.risk_level === 'MALICIOUS'
                        ? 'bg-red-500/20 text-red-400 border-red-500/40 animate-pulse'
                        : att.risk_level === 'SUSPICIOUS'
                        ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                        : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                    }`}
                  >
                    {att.risk_level}
                  </span>
                </div>

                {/* Hashes & Entropy */}
                <div className="grid grid-cols-1 gap-1 text-xs">
                  <div className="flex items-center justify-between gap-2 bg-mfx-surface/80 p-1.5 rounded border border-mfx-border/60">
                    <span className="text-mfx-muted font-mono text-[11px] shrink-0">SHA-256:</span>
                    <code className="text-mfx-accent text-[11px] font-mono truncate" title={att.sha256}>
                      {att.sha256}
                    </code>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(att.sha256)
                        toast.success('Attachment SHA-256 copied!')
                      }}
                      className="text-[10px] px-1.5 py-0.5 rounded bg-mfx-accent/10 text-mfx-accent hover:bg-mfx-accent/20 transition-colors shrink-0 font-semibold"
                    >
                      copy
                    </button>
                  </div>
                  <div className="flex items-center justify-between text-[11px] px-1 text-mfx-muted">
                    <span>
                      Shannon Entropy: <strong className={att.entropy > 7.0 ? 'text-amber-400' : 'text-mfx-text'}>{att.entropy} / 8.0</strong>
                    </span>
                    <span>Format: <strong className="text-mfx-text font-mono">{att.extension || 'none'}</strong></span>
                  </div>
                </div>

                {/* Risk reasons */}
                {att.risk_reasons?.length > 0 && (
                  <div className="space-y-1 pt-1 border-t border-mfx-border/40">
                    {att.risk_reasons.map((r, rIdx) => (
                      <p key={rIdx} className="text-[11px] text-amber-300/90 flex items-start gap-1 leading-tight">
                        <span className="text-amber-400">&#9888;</span> {r}
                      </p>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* CERT-In Incident Classification */}
      {data?.cert_in && (
        <div className="mt-3 pt-3 border-t border-mfx-border">
          <p className="text-sm text-mfx-muted uppercase tracking-wide font-semibold mb-2">
            CERT-In Incident Classification
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {/* Category + severity */}
            <div className="bg-mfx-bg/60 rounded-md p-2.5 border border-mfx-border space-y-1">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs text-mfx-muted font-semibold uppercase tracking-wide">Category</span>
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                  data.cert_in.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                  data.cert_in.severity === 'HIGH'     ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                  data.cert_in.severity === 'MEDIUM'   ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                                                         'bg-slate-500/20 text-slate-400 border border-slate-500/30'
                }`}>
                  {data.cert_in.severity}
                </span>
              </div>
              <p className="text-sm font-semibold text-mfx-text leading-tight">{data.cert_in.category}</p>
              <p className="text-xs text-mfx-muted leading-tight">{data.cert_in.subcategory}</p>
            </div>

            {/* Statutory references */}
            <div className="bg-mfx-bg/60 rounded-md p-2.5 border border-mfx-border space-y-1">
              <span className="text-xs text-mfx-muted font-semibold uppercase tracking-wide">Statutory Refs</span>
              <p className="text-xs text-mfx-text leading-snug">{data.cert_in.statutory_refs}</p>
            </div>

            {/* IOC summary */}
            {data.cert_in.ioc_summary && (
              <div className="sm:col-span-2 bg-mfx-bg/60 rounded-md p-2.5 border border-mfx-border">
                <span className="text-xs text-mfx-muted font-semibold uppercase tracking-wide block mb-1">IOC Summary</span>
                <p className="text-xs text-mfx-text leading-snug font-mono">{data.cert_in.ioc_summary}</p>
              </div>
            )}

            {/* Report ready flag */}
            {data.cert_in.cert_in_report_ready && (
              <div className="sm:col-span-2">
                <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-green-400 bg-green-500/10 border border-green-500/20 px-2 py-1 rounded">
                  &#10003; CERT-In mandatory report data available
                </span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function SkeletonDossier() {
  return (
    <div className="panel" id="panel-dossier-skeleton">
      <div className="flex items-center justify-between gap-4">
        <div className="flex-1 space-y-2">
          <div className="skeleton h-3 w-24 mb-2" />
          <div className="skeleton h-4 w-80" />
          <div className="skeleton h-3 w-60" />
        </div>
        <div className="flex gap-3">
          <div className="skeleton h-8 w-24" />
          <div className="skeleton h-8 w-28" />
        </div>
      </div>
    </div>
  )
}

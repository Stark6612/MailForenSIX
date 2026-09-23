import React, { useState, useCallback, useRef, useEffect } from 'react'
import { submitCampaign, pollCampaignResults, exportCampaign, adjustCampaignCluster } from '../lib/api'

/* ── Constants ── */
const MITRE_COLORS = {
  'Initial Access':       '#ef4444',
  'Resource Development': '#f97316',
  'Defense Evasion':      '#a855f7',
  'Execution':            '#3b82f6',
}

const TLP_COLORS = {
  white:  '#e5e7eb',
  green:  '#22c55e',
  amber:  '#f59e0b',
  red:    '#ef4444',
}

const EXPORT_FORMATS = [
  { key: 'stix',     label: 'STIX 2.1',            tlpRelevant: true,  desc: 'Bundle for MISP/TIP (TLP:AMBER default)' },
  { key: 'sigma',    label: 'Sigma Rule',           tlpRelevant: false, desc: 'SIEM YAML — Splunk/Elastic/Sentinel' },
  { key: 'suricata', label: 'Suricata Rule',        tlpRelevant: false, desc: 'Network IDS rule for relay IPs' },
  { key: 'postfix',  label: 'Postfix header_checks',tlpRelevant: false, desc: 'Mail server block rules' },
  { key: 'exchange', label: 'Exchange Transport',   tlpRelevant: false, desc: 'PowerShell New-TransportRule' },
  { key: 'dnsbl',    label: 'DNSBL List',           tlpRelevant: false, desc: 'Pi-hole / pfSense IP block list' },
]

/* ── Download helper ── */
function downloadText(content, filename) {
  const blob = new Blob([content], { type: 'text/plain' })
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href     = url; a.download = filename; a.click()
  URL.revokeObjectURL(url)
}

/* ── MITRE ATT&CK Heatmap ── */
function MitreHeatmap({ techniques }) {
  if (!techniques || techniques.length === 0) return null
  const unique = [...new Map(techniques.map(t => [t.id, t])).values()]
  return (
    <div style={{ marginTop: '1rem' }}>
      <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>
        MITRE ATT&CK Sub-Techniques
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
        {unique.map(tech => (
          <div key={tech.id} style={{
            background: MITRE_COLORS[tech.tactic] || '#6366f1',
            color: '#fff', borderRadius: '0.375rem',
            padding: '0.25rem 0.625rem', fontSize: '0.7rem', fontWeight: 600,
            boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
          }}>
            {tech.id} · {tech.name}
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── Cluster Card ── */
function ClusterCard({ cluster, campaignId, tlp, onExport, onAdjust, isNoise }) {
  const [expanded, setExpanded] = useState(false)
  const profile = cluster.actor_profile || {}
  const techniques = profile.mitre_techniques || []
  const relayIps = Object.keys(profile.relay_ips || {}).slice(0, 5)
  const domains  = Object.keys(profile.sender_domains || {}).slice(0, 5)
  const country  = Object.keys(profile.top_countries || {})[0] || 'Unknown'

  return (
    <div style={{
      background: isNoise ? 'rgba(107,114,128,0.08)' : 'rgba(99,102,241,0.07)',
      border: `1px solid ${isNoise ? 'rgba(107,114,128,0.2)' : 'rgba(99,102,241,0.25)'}`,
      borderRadius: '0.75rem', padding: '1.25rem', marginBottom: '1rem',
    }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div>
          <span style={{
            background: isNoise ? '#6b7280' : '#6366f1',
            color: '#fff', borderRadius: '0.375rem',
            padding: '0.2rem 0.6rem', fontSize: '0.7rem', fontWeight: 700, marginRight: '0.5rem',
          }}>
            {isNoise ? 'UNCLUSTERED' : `CAMPAIGN ${cluster.cluster_id + 1}`}
          </span>
          <span style={{ fontWeight: 600, color: '#e5e7eb', fontSize: '0.9rem' }}>
            {cluster.name || `Campaign ${cluster.cluster_id + 1}`}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.75rem', color: '#9ca3af' }}>
            {cluster.email_count} email{cluster.email_count !== 1 ? 's' : ''} · Origin: {country}
          </span>
          <button onClick={() => setExpanded(v => !v)} style={{
            background: 'rgba(99,102,241,0.12)', border: '1px solid rgba(99,102,241,0.3)',
            color: '#a5b4fc', borderRadius: '0.375rem', padding: '0.2rem 0.5rem',
            cursor: 'pointer', fontSize: '0.75rem',
          }}>
            {expanded ? 'Collapse' : 'Expand'}
          </button>
        </div>
      </div>

      {/* Quick stats */}
      <div style={{ display: 'flex', gap: '1.5rem', marginTop: '0.75rem', flexWrap: 'wrap' }}>
        {[
          { label: 'Relay IPs',     value: Object.keys(profile.relay_ips || {}).length },
          { label: 'Domains',       value: Object.keys(profile.sender_domains || {}).length },
          { label: 'ATT&CK TTPs',   value: techniques.length },
          { label: 'Auth Pass %',   value: `${Math.round((profile.auth_pass_ratio || 0) * 100)}%` },
          { label: 'Avg Domain Age',value: profile.avg_domain_age_days != null ? `${profile.avg_domain_age_days}d` : 'N/A' },
        ].map(stat => (
          <div key={stat.label}>
            <div style={{ fontSize: '0.65rem', color: '#6b7280', textTransform: 'uppercase' }}>{stat.label}</div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: '#e5e7eb' }}>{stat.value}</div>
          </div>
        ))}
      </div>

      {/* MITRE Heatmap always visible */}
      <MitreHeatmap techniques={techniques} />

      {/* Expanded detail */}
      {expanded && (
        <div style={{ marginTop: '1rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div>
            <div style={{ fontSize: '0.72rem', color: '#9ca3af', fontWeight: 600, marginBottom: '0.3rem' }}>TOP RELAY IPs</div>
            {relayIps.length ? relayIps.map(ip => (
              <div key={ip} style={{ fontSize: '0.8rem', color: '#d1d5db', fontFamily: 'monospace', marginBottom: '0.15rem' }}>{ip}</div>
            )) : <div style={{ color: '#6b7280', fontSize: '0.8rem' }}>None extracted</div>}
          </div>
          <div>
            <div style={{ fontSize: '0.72rem', color: '#9ca3af', fontWeight: 600, marginBottom: '0.3rem' }}>SENDER DOMAINS</div>
            {domains.length ? domains.map(d => (
              <div key={d} style={{ fontSize: '0.8rem', color: '#fca5a5', fontFamily: 'monospace', marginBottom: '0.15rem' }}>{d}</div>
            )) : <div style={{ color: '#6b7280', fontSize: '0.8rem' }}>None extracted</div>}
          </div>
          {(profile.subject_samples || []).length > 0 && (
            <div style={{ gridColumn: '1 / -1' }}>
              <div style={{ fontSize: '0.72rem', color: '#9ca3af', fontWeight: 600, marginBottom: '0.3rem' }}>SUBJECT SAMPLES</div>
              {(profile.subject_samples || []).slice(0, 3).map((s, i) => (
                <div key={i} style={{ fontSize: '0.78rem', color: '#d1d5db', marginBottom: '0.15rem', padding: '0.2rem 0.4rem', background: 'rgba(0,0,0,0.15)', borderRadius: '0.25rem' }}>"{s}"</div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Export buttons */}
      {!isNoise && (
        <div style={{ marginTop: '1rem', display: 'flex', flexWrap: 'wrap', gap: '0.5rem', borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '0.75rem' }}>
          {EXPORT_FORMATS.map(fmt => (
            <button key={fmt.key} onClick={() => onExport(cluster.cluster_id, fmt.key, tlp)} style={{
              background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.25)',
              color: '#6ee7b7', borderRadius: '0.375rem', padding: '0.25rem 0.625rem',
              cursor: 'pointer', fontSize: '0.7rem', fontWeight: 600,
              transition: 'all 0.15s',
            }}
            onMouseOver={e => e.currentTarget.style.background = 'rgba(16,185,129,0.22)'}
            onMouseOut={e  => e.currentTarget.style.background = 'rgba(16,185,129,0.1)'}
            title={fmt.desc}
            >
              ↓ {fmt.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

/* ── Main Campaign Page ── */
export default function Campaign() {
  const [files,        setFiles]       = useState([])
  const [zipFile,      setZipFile]     = useState(null)
  const [campaignId,   setCampaignId]  = useState(null)
  const [results,      setResults]     = useState(null)
  const [status,       setStatus]      = useState('idle')   // idle|queued|processing|complete|error
  const [error,        setError]       = useState(null)
  const [tlp,          setTlp]         = useState('amber')
  const [dragOver,     setDragOver]    = useState(false)
  const pollRef    = useRef(null)
  const pollStart  = useRef(null)
  const fileInputRef = useRef(null)
  const POLL_TIMEOUT_MS = 5 * 60 * 1000  // 5 minutes

  /* Polling — stops after 5 minutes with a clear error */
  useEffect(() => {
    if (!campaignId || status === 'complete' || status === 'error') return
    pollStart.current = Date.now()
    pollRef.current = setInterval(async () => {
      // Timeout guard
      if (Date.now() - pollStart.current > POLL_TIMEOUT_MS) {
        clearInterval(pollRef.current)
        setStatus('error')
        setError('Analysis timed out after 5 minutes. The embedding model may still be loading on the server — please try again in a minute.')
        return
      }
      try {
        const r = await pollCampaignResults(campaignId)
        setResults(r)
        setStatus(r.status)
        if (r.status === 'complete' || r.status === 'error') {
          clearInterval(pollRef.current)
        }
      } catch {}
    }, 3000)
    return () => clearInterval(pollRef.current)
  }, [campaignId, status])

  /* Submit */
  const handleSubmit = useCallback(async () => {
    if (!files.length && !zipFile) return
    setStatus('queued'); setError(null); setResults(null); setCampaignId(null)
    try {
      const r = await submitCampaign(zipFile, files.length ? files : null)
      setCampaignId(r.campaign_id)
      setStatus(r.status)
    } catch (e) {
      setStatus('error'); setError(e.response?.data?.detail || e.message)
    }
  }, [files, zipFile])

  /* Export */
  const handleExport = useCallback(async (clusterId, format, exportTlp) => {
    if (!campaignId) return
    try {
      const content = await exportCampaign(campaignId, format, exportTlp)
      const ext = { stix: 'json', sigma: 'yml', suricata: 'rules', postfix: 'txt', exchange: 'ps1', dnsbl: 'txt' }[format] || 'txt'
      downloadText(content, `campaign_${campaignId.slice(0,8)}_cluster${clusterId}_${format}.${ext}`)
    } catch (e) {
      alert(`Export failed: ${e.message}`)
    }
  }, [campaignId])

  /* Drag & Drop */
  const onDrop = useCallback(e => {
    e.preventDefault(); setDragOver(false)
    const items = Array.from(e.dataTransfer.files)
    const emls = items.filter(f => f.name.endsWith('.eml'))
    const zips = items.filter(f => f.name.endsWith('.zip'))
    if (zips.length)  setZipFile(zips[0])
    if (emls.length)  setFiles(prev => [...prev, ...emls])
  }, [])

  const clusters  = results?.clusters  || []
  const noiseCount = results?.n_noise  || 0

  return (
    <div style={{ minHeight: '100vh', background: '#0f0f1a', color: '#e5e7eb', padding: '2rem', fontFamily: "'Inter', system-ui, sans-serif" }}>
      {/* Header */}
      <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem', marginBottom: '2rem' }}>
          <div>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 800, background: 'linear-gradient(135deg,#6366f1,#a855f7)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', margin: 0 }}>
              Campaign Intelligence
            </h1>
            <p style={{ color: '#9ca3af', margin: '0.3rem 0 0', fontSize: '0.875rem' }}>
              Mode 2 · UMAP + HDBSCAN · 0.4 cosine + 0.6 Jaccard · MITRE ATT&CK mapping
            </p>
          </div>
          {/* TLP Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', color: '#9ca3af', fontWeight: 600 }}>TLP:</span>
            {['white','green','amber','red'].map(t => (
              <button key={t} onClick={() => setTlp(t)} style={{
                background: tlp === t ? TLP_COLORS[t] : 'transparent',
                border: `2px solid ${TLP_COLORS[t]}`,
                color: tlp === t ? '#000' : TLP_COLORS[t],
                borderRadius: '0.375rem', padding: '0.2rem 0.5rem',
                cursor: 'pointer', fontSize: '0.7rem', fontWeight: 700,
                transition: 'all 0.15s',
              }}>
                {t.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {/* Upload Zone */}
        {status === 'idle' && (
          <div
            onDragOver={e => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={onDrop}
            onClick={() => fileInputRef.current?.click()}
            style={{
              border: `2px dashed ${dragOver ? '#6366f1' : 'rgba(99,102,241,0.3)'}`,
              borderRadius: '1rem', padding: '3rem', textAlign: 'center',
              background: dragOver ? 'rgba(99,102,241,0.07)' : 'rgba(255,255,255,0.02)',
              cursor: 'pointer', transition: 'all 0.2s', marginBottom: '1.5rem',
            }}
          >
            <div style={{ fontSize: '2.5rem', marginBottom: '0.75rem' }}>📧</div>
            <div style={{ fontWeight: 700, fontSize: '1.1rem', marginBottom: '0.3rem' }}>
              Drop .eml files or a .zip archive
            </div>
            <div style={{ color: '#9ca3af', fontSize: '0.85rem' }}>
              Supports: individual .eml files or a .zip containing .eml files (max 200 emails)
            </div>
            <input ref={fileInputRef} type="file" multiple accept=".eml,.zip" style={{ display: 'none' }}
              onChange={e => {
                const items = Array.from(e.target.files)
                setFiles(items.filter(f => f.name.endsWith('.eml')))
                setZipFile(items.find(f => f.name.endsWith('.zip')) || null)
              }} />
          </div>
        )}

        {/* File count + submit */}
        {(files.length > 0 || zipFile) && status === 'idle' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
            <span style={{ color: '#9ca3af', fontSize: '0.85rem' }}>
              {zipFile ? `ZIP: ${zipFile.name}` : `${files.length} .eml files selected`}
            </span>
            <button onClick={handleSubmit} style={{
              background: 'linear-gradient(135deg,#6366f1,#a855f7)',
              color: '#fff', border: 'none', borderRadius: '0.5rem',
              padding: '0.6rem 1.5rem', fontWeight: 700, cursor: 'pointer',
              fontSize: '0.9rem', boxShadow: '0 4px 15px rgba(99,102,241,0.4)',
            }}>
              Analyze Campaign →
            </button>
            <button onClick={() => { setFiles([]); setZipFile(null) }} style={{
              background: 'transparent', color: '#6b7280', border: '1px solid rgba(107,114,128,0.3)',
              borderRadius: '0.5rem', padding: '0.6rem 1rem', cursor: 'pointer', fontSize: '0.85rem',
            }}>Clear</button>
          </div>
        )}

        {/* Status bar */}
        {(status === 'queued' || status === 'processing') && (
          <div style={{ background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: '0.75rem', padding: '1.25rem', marginBottom: '1.5rem', textAlign: 'center' }}>
            <div style={{ width: '2rem', height: '2rem', border: '3px solid rgba(99,102,241,0.3)', borderTop: '3px solid #6366f1', borderRadius: '50%', margin: '0 auto 0.75rem', animation: 'spin 1s linear infinite' }} />
            <div style={{ fontWeight: 600 }}>{status === 'queued' ? 'Queued for processing…' : 'Analyzing campaign…'}</div>
            <div style={{ color: '#9ca3af', fontSize: '0.8rem', marginTop: '0.25rem' }}>Embedding {results?.n_files || '?'} emails · Computing distance matrix · HDBSCAN clustering</div>
            <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
          </div>
        )}

        {/* Error */}
        {status === 'error' && (
          <div style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: '0.75rem', padding: '1rem', marginBottom: '1.5rem', color: '#fca5a5' }}>
            <strong>Error:</strong> {error || results?.error || 'Unknown error'}
            <button onClick={() => { setStatus('idle'); setFiles([]); setZipFile(null) }}
              style={{ marginLeft: '1rem', background: 'transparent', border: '1px solid rgba(239,68,68,0.4)', color: '#fca5a5', borderRadius: '0.375rem', padding: '0.2rem 0.5rem', cursor: 'pointer', fontSize: '0.8rem' }}>
              Reset
            </button>
          </div>
        )}

        {/* Results */}
        {status === 'complete' && results && (
          <div>
            {/* Summary banner */}
            <div style={{ background: 'rgba(16,185,129,0.07)', border: '1px solid rgba(16,185,129,0.2)', borderRadius: '0.75rem', padding: '1.25rem', marginBottom: '1.5rem', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
              <div>
                <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#6ee7b7' }}>
                  {results.n_clusters} Campaign{results.n_clusters !== 1 ? 's' : ''} Detected
                </div>
                <div style={{ color: '#9ca3af', fontSize: '0.85rem', marginTop: '0.2rem' }}>
                  {results.n_emails} emails · {noiseCount} unclustered · Algorithm: {results.algorithm}
                </div>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                {EXPORT_FORMATS.map(fmt => (
                  <button key={fmt.key} onClick={() => handleExport(0, fmt.key, tlp)} style={{
                    background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.25)',
                    color: '#6ee7b7', borderRadius: '0.375rem', padding: '0.3rem 0.7rem',
                    cursor: 'pointer', fontSize: '0.7rem', fontWeight: 600,
                  }} title={`Export all as ${fmt.label} (TLP:${tlp.toUpperCase()})`}>
                    ↓ {fmt.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Cluster cards */}
            {clusters.map(cluster => (
              <ClusterCard key={cluster.cluster_id} cluster={cluster} campaignId={campaignId} tlp={tlp} onExport={handleExport} onAdjust={() => {}} isNoise={false} />
            ))}

            {noiseCount > 0 && (
              <ClusterCard cluster={{ cluster_id: -1, name: 'Unclustered Emails', email_count: noiseCount, actor_profile: {} }} campaignId={campaignId} tlp={tlp} onExport={() => {}} onAdjust={() => {}} isNoise={true} />
            )}
          </div>
        )}
      </div>
    </div>
  )
}

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

/* ── UMAP 2D Campaign Scatter Plot ── */
const CLUSTER_PALETTE = ['#6366f1', '#10b981', '#f59e0b', '#ec4899', '#3b82f6', '#8b5cf6', '#14b8a6']

function UmapScatterPlot({ embedding, labels, emailSummaries, clusters }) {
  const [hoveredPoint, setHoveredPoint] = useState(null)
  const [selectedCluster, setSelectedCluster] = useState(null)

  if (!embedding || embedding.length === 0) return null

  const xs = embedding.map(p => p[0])
  const ys = embedding.map(p => p[1])
  const minX = Math.min(...xs), maxX = Math.max(...xs)
  const minY = Math.min(...ys), maxY = Math.max(...ys)
  const spanX = maxX - minX || 1
  const spanY = maxY - minY || 1

  const scaleX = x => 40 + ((x - minX) / spanX) * 440
  const scaleY = y => 30 + ((y - minY) / spanY) * 230

  return (
    <div style={{
      background: 'rgba(15, 23, 42, 0.65)',
      border: '1px solid rgba(99, 102, 241, 0.25)',
      borderRadius: '0.75rem',
      padding: '1.25rem',
      marginBottom: '1.5rem',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div>
          <div style={{ fontSize: '0.9rem', fontWeight: 700, color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>📈</span> 2D Campaign UMAP Manifold Projection
          </div>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
            Multi-Modal Vector Space (40% Semantic Intent + 60% Infrastructure ASNs)
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
          <button
            onClick={() => setSelectedCluster(null)}
            style={{
              fontSize: '0.7rem', padding: '0.2rem 0.5rem', borderRadius: '0.25rem',
              background: selectedCluster === null ? '#4f46e5' : 'rgba(255,255,255,0.05)',
              color: '#fff', border: '1px solid rgba(255,255,255,0.1)', cursor: 'pointer'
            }}
          >
            All Clusters
          </button>
          {clusters.map((c, i) => (
            <button
              key={c.cluster_id}
              onClick={() => setSelectedCluster(selectedCluster === c.cluster_id ? null : c.cluster_id)}
              style={{
                fontSize: '0.7rem', padding: '0.2rem 0.5rem', borderRadius: '0.25rem',
                background: selectedCluster === c.cluster_id ? CLUSTER_PALETTE[i % CLUSTER_PALETTE.length] : 'rgba(255,255,255,0.05)',
                color: '#fff', border: '1px solid rgba(255,255,255,0.1)', cursor: 'pointer'
              }}
            >
              Campaign {c.cluster_id + 1}
            </button>
          ))}
          <button
            onClick={() => setSelectedCluster(selectedCluster === -1 ? null : -1)}
            style={{
              fontSize: '0.7rem', padding: '0.2rem 0.5rem', borderRadius: '0.25rem',
              background: selectedCluster === -1 ? '#64748b' : 'rgba(255,255,255,0.05)',
              color: '#94a3b8', border: '1px solid rgba(255,255,255,0.1)', cursor: 'pointer'
            }}
          >
            Noise (-1)
          </button>
        </div>
      </div>

      <div style={{ position: 'relative', width: '100%', height: '290px', background: 'radial-gradient(ellipse at center, rgba(30,41,59,0.5) 0%, rgba(15,23,42,0.85) 100%)', borderRadius: '0.5rem', border: '1px solid rgba(51,65,85,0.5)', overflow: 'hidden' }}>
        <svg viewBox="0 0 520 290" style={{ width: '100%', height: '100%' }}>
          <line x1="30" y1="145" x2="490" y2="145" stroke="rgba(255,255,255,0.07)" strokeDasharray="3 3" />
          <line x1="260" y1="20" x2="260" y2="270" stroke="rgba(255,255,255,0.07)" strokeDasharray="3 3" />

          {embedding.map((pt, i) => {
            const cid = labels[i]
            const isDimmed = selectedCluster !== null && selectedCluster !== cid
            const isNoise = cid === -1
            const color = isNoise ? '#64748b' : CLUSTER_PALETTE[cid % CLUSTER_PALETTE.length]
            const cx = scaleX(pt[0])
            const cy = scaleY(pt[1])
            const info = emailSummaries?.[i] || {}

            return (
              <circle
                key={i}
                cx={cx}
                cy={cy}
                r={hoveredPoint?.index === i ? 7 : isNoise ? 3.5 : 5}
                fill={color}
                opacity={isDimmed ? 0.15 : hoveredPoint?.index === i ? 1 : 0.85}
                stroke={hoveredPoint?.index === i ? '#ffffff' : color}
                strokeWidth={hoveredPoint?.index === i ? 2 : 1}
                style={{ cursor: 'pointer', transition: 'all 0.15s ease' }}
                onMouseEnter={() => setHoveredPoint({ index: i, cx, cy, info, cid, color })}
                onMouseLeave={() => setHoveredPoint(null)}
              />
            )
          })}
        </svg>

        {hoveredPoint && (
          <div style={{
            position: 'absolute',
            bottom: '10px',
            right: '10px',
            background: 'rgba(15, 23, 42, 0.95)',
            border: `1px solid ${hoveredPoint.color}`,
            borderRadius: '0.5rem',
            padding: '0.6rem 0.85rem',
            maxWidth: '320px',
            fontSize: '0.75rem',
            boxShadow: '0 4px 20px rgba(0,0,0,0.6)',
            pointerEvents: 'none',
            zIndex: 10,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
              <span style={{ fontWeight: 700, color: hoveredPoint.color }}>
                {hoveredPoint.cid === -1 ? 'Unclustered (Noise)' : `Campaign ${hoveredPoint.cid + 1}`}
              </span>
              <span style={{ color: '#94a3b8', fontSize: '0.7rem' }}>Email #{hoveredPoint.index + 1}</span>
            </div>
            <div style={{ color: '#f8fafc', fontWeight: 600, marginBottom: '0.2rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {hoveredPoint.info.subject || '(No Subject)'}
            </div>
            <div style={{ color: '#94a3b8', display: 'flex', gap: '0.5rem', fontSize: '0.7rem' }}>
              <span>Domain: <strong style={{ color: '#cbd5e1' }}>{hoveredPoint.info.domain}</strong></span>
              <span>Origin: <strong style={{ color: '#cbd5e1' }}>{hoveredPoint.info.country}</strong></span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

/* ── Diamond Model & MITRE Tactic Distribution ── */
function AnalyticsDashboard({ clusters }) {
  if (!clusters || clusters.length === 0) return null

  // Compute tactic distribution
  const tacticCounts = {}
  let totalTechs = 0
  clusters.forEach(c => {
    (c.actor_profile?.mitre_techniques || []).forEach(t => {
      const tac = t.tactic || 'Other'
      tacticCounts[tac] = (tacticCounts[tac] || 0) + 1
      totalTechs++
    })
  })

  const topCluster = clusters[0]
  const profile = topCluster.actor_profile || {}
  const topIps = Object.keys(profile.relay_ips || {}).slice(0, 3)
  const topDomains = Object.keys(profile.sender_domains || {}).slice(0, 3)
  const topTTPs = (profile.mitre_techniques || []).slice(0, 3)

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
      gap: '1.25rem',
      marginBottom: '1.5rem',
    }}>
      {/* MITRE Tactic Distribution Bar Chart */}
      <div style={{
        background: 'rgba(15, 23, 42, 0.65)',
        border: '1px solid rgba(99, 102, 241, 0.25)',
        borderRadius: '0.75rem',
        padding: '1.25rem',
      }}>
        <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#e2e8f0', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span>📊</span> MITRE ATT&CK Tactic Distribution
        </div>
        <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '1rem' }}>
          Observed Adversary Progression across {totalTechs} Sub-Technique hits
        </div>

        {/* Stacked bar */}
        <div style={{ height: '14px', borderRadius: '7px', display: 'flex', overflow: 'hidden', background: 'rgba(255,255,255,0.05)', marginBottom: '1rem' }}>
          {Object.entries(tacticCounts).map(([tactic, count]) => (
            <div
              key={tactic}
              style={{
                width: `${(count / (totalTechs || 1)) * 100}%`,
                background: MITRE_COLORS[tactic] || '#6366f1',
                transition: 'width 0.4s ease',
              }}
              title={`${tactic}: ${count} (${Math.round((count / (totalTechs || 1)) * 100)}%)`}
            />
          ))}
        </div>

        {/* Legend */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.75rem' }}>
          {Object.entries(tacticCounts).map(([tactic, count]) => (
            <div key={tactic} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.35rem 0.5rem', background: 'rgba(255,255,255,0.03)', borderRadius: '0.375rem', border: '1px solid rgba(255,255,255,0.06)' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: MITRE_COLORS[tactic] || '#6366f1' }} />
                <span style={{ color: '#cbd5e1' }}>{tactic}</span>
              </span>
              <span style={{ fontWeight: 700, color: '#93c5fd' }}>{count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Diamond Model Intrusion Analysis Graph */}
      <div style={{
        background: 'rgba(15, 23, 42, 0.65)',
        border: '1px solid rgba(99, 102, 241, 0.25)',
        borderRadius: '0.75rem',
        padding: '1.25rem',
        position: 'relative',
      }}>
        <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#e2e8f0', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span>💎</span> Diamond Model Intrusion Correlation
        </div>
        <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.75rem' }}>
          Primary Threat Cluster: {topCluster.name}
        </div>

        {/* Diamond Model Node-Link Layout */}
        <div style={{ position: 'relative', height: '200px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          {/* Top: Adversary */}
          <div style={{ position: 'absolute', top: '0', textAlign: 'center', padding: '0.3rem 0.6rem', borderRadius: '0.375rem', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.4)', fontSize: '0.7rem' }}>
            <span style={{ color: '#f87171', fontWeight: 700 }}>ADVERSARY</span>
            <div style={{ color: '#fca5a5', fontSize: '0.65rem' }}>{topCluster.name.slice(0, 18)}</div>
          </div>

          {/* Left: Capability */}
          <div style={{ position: 'absolute', left: '0', textAlign: 'center', padding: '0.3rem 0.6rem', borderRadius: '0.375rem', background: 'rgba(59, 130, 246, 0.15)', border: '1px solid rgba(59, 130, 246, 0.4)', fontSize: '0.7rem', maxWidth: '120px' }}>
            <span style={{ color: '#60a5fa', fontWeight: 700 }}>CAPABILITY</span>
            <div style={{ color: '#93c5fd', fontSize: '0.65rem', truncate: 'true' }}>
              {topTTPs.map(t => t.id).join(', ') || 'Spearphishing'}
            </div>
          </div>

          {/* Center SVG connector lines */}
          <svg viewBox="0 0 200 200" style={{ width: '100%', height: '100%', position: 'absolute', inset: 0, pointerEvents: 'none' }}>
            <polygon points="100,28 175,100 100,172 25,100" fill="none" stroke="rgba(99,102,241,0.3)" strokeWidth="1.5" strokeDasharray="3 3" />
            <circle cx="100" cy="100" r="4" fill="#a5b4fc" />
          </svg>

          {/* Right: Infrastructure */}
          <div style={{ position: 'absolute', right: '0', textAlign: 'center', padding: '0.3rem 0.6rem', borderRadius: '0.375rem', background: 'rgba(168, 85, 247, 0.15)', border: '1px solid rgba(168, 85, 247, 0.4)', fontSize: '0.7rem', maxWidth: '120px' }}>
            <span style={{ color: '#c084fc', fontWeight: 700 }}>INFRASTRUCTURE</span>
            <div style={{ color: '#d8b4fe', fontSize: '0.65rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {topDomains[0] || topIps[0] || 'Transit ASN'}
            </div>
          </div>

          {/* Bottom: Victim */}
          <div style={{ position: 'absolute', bottom: '0', textAlign: 'center', padding: '0.3rem 0.6rem', borderRadius: '0.375rem', background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.4)', fontSize: '0.7rem' }}>
            <span style={{ color: '#34d399', fontWeight: 700 }}>VICTIM / ASSET</span>
            <div style={{ color: '#6ee7b7', fontSize: '0.65rem' }}>Enterprise Mailbox ({topCluster.email_count} targets)</div>
          </div>
        </div>
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
            <div style={{ color: '#9ca3af', fontSize: '0.85rem', marginBottom: '1rem' }}>
              Supports: individual .eml files or a .zip containing .eml files (max 200 emails)
            </div>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={async (e) => {
                  e.stopPropagation()
                  try {
                    const res = await fetch('/demo_campaign.zip')
                    if (!res.ok) throw new Error('Demo file not found')
                    const blob = await res.blob()
                    const file = new File([blob], 'mode2_demo.zip', { type: 'application/zip' })
                    setZipFile(file)
                    setFiles([])
                  } catch (err) {
                    alert('Could not load demo zip: ' + err.message)
                  }
                }}
                style={{
                  background: 'rgba(99,102,241,0.18)',
                  border: '1px solid rgba(99,102,241,0.4)',
                  color: '#c7d2fe',
                  borderRadius: '0.375rem',
                  padding: '0.4rem 0.9rem',
                  cursor: 'pointer',
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  transition: 'all 0.15s',
                }}
                onMouseOver={e => e.currentTarget.style.background = 'rgba(99,102,241,0.3)'}
                onMouseOut={e => e.currentTarget.style.background = 'rgba(99,102,241,0.18)'}
              >
                ⚡ Load Demo Sample (50 Emails · 3 Campaigns + Noise)
              </button>
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

            {/* Visual Analytics: 2D UMAP Scatter Plot */}
            {results.umap_embedding && (
              <UmapScatterPlot
                embedding={results.umap_embedding}
                labels={results.labels || []}
                emailSummaries={results.email_summaries || []}
                clusters={clusters}
              />
            )}

            {/* Visual Analytics: Diamond Model & ATT&CK Tactic Distribution */}
            <AnalyticsDashboard clusters={clusters} />

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

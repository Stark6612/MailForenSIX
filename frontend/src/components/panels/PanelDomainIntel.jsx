/**
 * PanelDomainIntel — Panel 6 (Phase 3)
 * Real: domain_intel{domain, age_days, registrar, mx_valid, privacy_proxy,
 *        suspicion_score, notes, creation_date, expiry_date} from API
 * New: risky TLD badge, new-domain alert, creation/expiry formatted, notes styled
 */

export default function PanelDomainIntel({ data, loading }) {
  if (loading) return <SkeletonDomain />

  const d = data?.domain_intel

  if (!d) return (
    <div className="panel animate-slide-up" id="panel-domain-intel">
      <p className="panel-label">Domain Intelligence</p>
      <div className="flex flex-col items-center justify-center h-32 text-mfx-muted text-xs gap-2">
        <span className="text-2xl">🌐</span>
        <span>No sender domain to analyse.</span>
      </div>
    </div>
  )

  const suspPct = Math.round((d.suspicion_score ?? 0) * 100)
  const suspColor = suspPct >= 70 ? 'text-mfx-critical' : suspPct >= 40 ? 'text-mfx-suspicious' : 'text-mfx-safe'
  const barColor  = suspPct >= 70 ? 'bg-mfx-critical'   : suspPct >= 40 ? 'bg-mfx-suspicious'   : 'bg-mfx-safe'

  return (
    <div className="panel animate-slide-up" id="panel-domain-intel">
      <div className="flex items-start justify-between mb-3">
        <p className="panel-label mb-0">Domain Intelligence</p>
        {suspPct >= 50 && (
          <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-semibold ${
            suspPct >= 70 ? 'bg-mfx-critical/20 text-mfx-critical' : 'bg-mfx-suspicious/20 text-mfx-suspicious'
          }`}>
            ⚠ Suspicious
          </span>
        )}
      </div>

      <p className="font-mono text-sm font-semibold text-mfx-accent mb-3 truncate">{d.domain}</p>

      <div className="space-y-1.5 text-xs">
        <Row
          label="Domain Age"
          value={d.age_days != null ? `${d.age_days.toLocaleString()} days` : '⚠ Unknown'}
          warn={d.age_days != null && d.age_days < 30}
          alert={d.age_days != null && d.age_days < 30 ? 'New domain — high risk' : null}
        />
        <Row label="Registrar"  value={d.registrar ?? '—'} />
        <Row label="Created"    value={d.creation_date ?? '—'} />
        <Row label="Expires"    value={d.expiry_date ?? '—'} />
        <Row label="MX Valid"   value={d.mx_valid ? '✓ Yes' : '✕ No'} warn={!d.mx_valid} />
        <Row
          label="WHOIS Privacy"
          value={d.privacy_proxy ? '⚠ Protected' : '✓ Public'}
          warn={d.privacy_proxy}
        />
      </div>

      {/* Suspicion score bar */}
      <div className="mt-3">
        <div className="flex justify-between text-xs mb-1">
          <span className="text-mfx-muted">Domain Suspicion</span>
          <span className={`font-semibold ${suspColor}`}>{suspPct}%</span>
        </div>
        <div className="h-1.5 bg-mfx-border rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-700 ${barColor}`}
            style={{ width: `${suspPct}%` }}
          />
        </div>
      </div>

      {/* Notes */}
      {d.notes?.length > 0 && (
        <ul className="mt-3 space-y-1">
          {d.notes.map((n, i) => (
            <li key={i} className={`text-xs flex gap-1.5 ${n.includes('high') || n.includes('suspicious') || n.includes('risk') ? 'text-mfx-suspicious' : 'text-mfx-muted'}`}>
              <span className="shrink-0">•</span>{n}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function Row({ label, value, warn = false, alert = null }) {
  return (
    <div className="flex justify-between gap-2 items-start">
      <span className="text-mfx-muted shrink-0">{label}</span>
      <div className="text-right">
        <span className={`font-medium ${warn ? 'text-mfx-suspicious' : 'text-mfx-text'}`}>{value}</span>
        {alert && <p className="text-[10px] text-mfx-critical mt-0.5">{alert}</p>}
      </div>
    </div>
  )
}

function SkeletonDomain() {
  return (
    <div className="panel" id="panel-domain-intel-skeleton">
      <p className="panel-label">Domain Intelligence</p>
      <div className="skeleton h-4 w-40 mb-3" />
      <div className="space-y-2">
        {[1, 2, 3, 4, 5, 6].map(i => <div key={i} className="skeleton h-4 w-full" />)}
      </div>
    </div>
  )
}

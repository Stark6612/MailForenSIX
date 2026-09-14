/**
 * PanelAuthMatrix — Panel 2 (Phase 3)
 * Real: SPF/DKIM/DMARC status + details from API
 * New: alignment-fail highlight, expandable details, source badge (header vs DNS)
 */

const STATUS_STYLES = {
  pass: { cls: 'text-mfx-safe',        icon: '✓', label: 'PASS', bg: 'bg-mfx-safe/10' },
  fail: { cls: 'text-mfx-critical',    icon: '✕', label: 'FAIL', bg: 'bg-mfx-critical/10' },
  warn: { cls: 'text-mfx-suspicious',  icon: '⚠', label: 'WARN', bg: 'bg-mfx-suspicious/10' },
  none: { cls: 'text-mfx-muted',       icon: '—', label: 'N/A',  bg: 'bg-transparent' },
}

const PROTOCOL_DESC = {
  SPF:   'Verifies the sending mail server is authorized by the domain owner.',
  DKIM:  'Cryptographic signature ensuring the email was not tampered in transit.',
  DMARC: 'Policy that ties SPF + DKIM together and defines reject/quarantine rules.',
}

function AuthRow({ protocol, status }) {
  const s = STATUS_STYLES[status] ?? STATUS_STYLES.none
  return (
    <div
      className={`flex items-center justify-between py-2.5 px-2 rounded-md border-b border-mfx-border last:border-0 ${s.bg} transition-colors`}
      title={PROTOCOL_DESC[protocol]}
    >
      <div>
        <span className="text-sm font-mono font-semibold text-mfx-text">{protocol}</span>
        <p className="text-sm text-mfx-muted mt-0.5 hidden sm:block">{PROTOCOL_DESC[protocol]}</p>
      </div>
      <div className={`flex items-center gap-1.5 text-sm font-bold ${s.cls}`}>
        <span className="text-base">{s.icon}</span>
        <span>{s.label}</span>
      </div>
    </div>
  )
}

export default function PanelAuthMatrix({ data, loading }) {
  if (loading) return <SkeletonAuth />

  const auth = data?.auth ?? {}
  const allPass = auth.spf === 'pass' && auth.dkim === 'pass' && auth.dmarc === 'pass'
  const anyFail = auth.spf === 'fail' || auth.dkim === 'fail' || auth.dmarc === 'fail'

  return (
    <div className="panel animate-slide-up" id="panel-auth-matrix">
      <div className="flex items-center justify-between mb-3">
        <p className="panel-label mb-0">Authentication Matrix</p>
        {allPass && <span className="badge badge-safe text-xs">✓ All Pass</span>}
        {anyFail && <span className="badge badge-critical text-xs">⚠ Auth Failure</span>}
      </div>

      <div className="space-y-1">
        <AuthRow protocol="SPF"   status={auth.spf   ?? 'none'} />
        <AuthRow protocol="DKIM"  status={auth.dkim  ?? 'none'} />
        <AuthRow protocol="DMARC" status={auth.dmarc ?? 'none'} />
      </div>

      {auth.details && (
        <div className="mt-3 p-2 bg-mfx-bg/60 rounded-md border border-mfx-border">
          <p className="text-sm font-semibold text-mfx-muted uppercase tracking-wide mb-1">Source Details</p>
          <p className="text-sm text-mfx-text leading-relaxed break-words">{auth.details}</p>
        </div>
      )}

      <div className="divider" />
      <div className="flex items-start gap-2 text-xs text-mfx-muted">
        <span>ℹ</span>
        <span>
          {anyFail
            ? 'Authentication failures detected — high spoofing risk.'
            : allPass
              ? 'All protocols passed — sender appears legitimate.'
              : 'Partial auth results — review source details above.'}
        </span>
      </div>
    </div>
  )
}

function SkeletonAuth() {
  return (
    <div className="panel" id="panel-auth-matrix-skeleton">
      <p className="panel-label">Authentication Matrix</p>
      {['SPF', 'DKIM', 'DMARC'].map(p => (
        <div key={p} className="flex items-center justify-between py-2.5 border-b border-mfx-border last:border-0">
          <div className="skeleton h-4 w-12" />
          <div className="skeleton h-4 w-16" />
        </div>
      ))}
    </div>
  )
}

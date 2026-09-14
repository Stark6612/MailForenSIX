import { Link } from 'react-router-dom'

// ── Reusable card shell ────────────────────────────────────────────────────────
function Card({ children, className = '' }) {
  return (
    <div className={`bg-mfx-surface border border-mfx-border rounded-panel p-6 ${className}`}>
      {children}
    </div>
  )
}

function SectionTitle({ icon, children }) {
  return (
    <h2 className="flex items-center gap-2 text-lg font-bold text-mfx-text mb-4">
      <span className="text-mfx-accent">{icon}</span>
      {children}
    </h2>
  )
}

function MetricRow({ label, value, sub, pass }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-mfx-border last:border-0">
      <div>
        <span className="text-sm text-mfx-text font-medium">{label}</span>
        {sub && <span className="ml-2 text-xs text-mfx-muted">{sub}</span>}
      </div>
      <div className="flex items-center gap-2">
        <span className="text-sm font-bold text-mfx-accent font-mono">{value}</span>
        {pass !== undefined && (
          <span className={`text-xs px-1.5 py-0.5 rounded-badge font-semibold
            ${pass ? 'bg-mfx-safe/20 text-mfx-safe' : 'bg-mfx-critical/20 text-mfx-critical'}`}>
            {pass ? '✓ Pass' : '✗ Fail'}
          </span>
        )}
      </div>
    </div>
  )
}

function Step({ n, title, children }) {
  return (
    <div className="flex gap-4">
      <div className="flex-shrink-0 w-8 h-8 rounded-full bg-mfx-accent/20 border border-mfx-accent/40
                      flex items-center justify-center text-sm font-bold text-mfx-accent">
        {n}
      </div>
      <div className="pb-5 border-b border-mfx-border last:border-0 flex-1">
        <p className="text-sm font-semibold text-mfx-text mb-1">{title}</p>
        <p className="text-xs text-mfx-muted leading-relaxed">{children}</p>
      </div>
    </div>
  )
}

function NoveltyCard({ icon, title, children }) {
  return (
    <div className="p-4 rounded-lg bg-mfx-bg border border-mfx-border hover:border-mfx-accent/40
                    transition-colors group">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-xl">{icon}</span>
        <span className="text-sm font-bold text-mfx-text group-hover:text-mfx-accent transition-colors">
          {title}
        </span>
      </div>
      <p className="text-xs text-mfx-muted leading-relaxed">{children}</p>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────
export default function About() {
  return (
    <div className="min-h-dvh bg-mfx-bg text-mfx-text">

      {/* ── Mini top bar ──────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-50 bg-mfx-bg/80 backdrop-blur-md border-b border-mfx-border">
        <div className="max-w-[1100px] mx-auto px-6 h-14 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
            <div className="w-8 h-8 rounded-badge bg-mfx-accent flex items-center justify-center text-lg shadow-glow">
              📧
            </div>
            <div>
              <span className="font-bold text-lg text-mfx-text tracking-tight">MailForen</span>
              <span className="font-bold text-lg text-mfx-accent">SIX</span>
            </div>
          </Link>
          <Link
            to="/"
            className="text-sm text-mfx-muted hover:text-mfx-accent transition-colors flex items-center gap-1"
          >
            ← Back to Analyzer
          </Link>
        </div>
      </header>

      <main className="max-w-[1100px] mx-auto px-6 py-10 space-y-8">

        {/* ── Hero ──────────────────────────────────────────────────────── */}
        <div className="text-center space-y-3 pb-4">
          <div className="inline-flex items-center gap-2 text-xs text-mfx-muted border border-mfx-border
                          px-3 py-1 rounded-full mb-2">
            <span className="w-1.5 h-1.5 rounded-full bg-mfx-accent animate-pulse" />
            SIH 2026 · Problem #26106 · Team CyberNexus
          </div>
          <h1 className="text-4xl font-extrabold tracking-tight">
            MailForen<span className="text-mfx-accent">SIX</span>
          </h1>
          <p className="text-mfx-muted text-base max-w-xl mx-auto">
            An AI-powered email threat detection, geolocation, and forensic intelligence platform
            — built for cybersecurity analysts, forensic investigators, and law enforcement.
          </p>
        </div>

        {/* ── MVP Disclaimer banner ──────────────────────────────────────── */}
        <div className="rounded-panel border border-mfx-suspicious/40 bg-mfx-suspicious/10 p-4
                        flex gap-3 items-start">
          <span className="text-xl flex-shrink-0">⚠️</span>
          <div className="space-y-1">
            <p className="text-sm font-semibold text-mfx-suspicious">
              Demo Build — Not for Production Investigative Use
            </p>
            <p className="text-xs text-mfx-muted leading-relaxed">
              This is an MVP built for the Smart India Hackathon 2026 (48-hour sprint).
              This live deployment is shared for demonstration and evaluation purposes only.
              When you submit an email here, its content is processed by our server.
              For actual forensic investigations involving sensitive or confidential emails,
              <strong className="text-mfx-text"> run MailForenSIX locally</strong> using Docker —
              your data never leaves your machine.
              See the <a href="https://github.com/Stark6612/SIH_2026" target="_blank"
              rel="noopener noreferrer" className="text-mfx-accent hover:underline">GitHub repo</a> for
              local setup instructions.
            </p>
          </div>
        </div>

        {/* ── Main grid ──────────────────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* ML Metrics */}
          <Card>
            <SectionTitle icon="📊">Model Performance</SectionTitle>
            <p className="text-xs text-mfx-muted mb-4">
              Trained on <strong className="text-mfx-text">83,497 emails</strong> (43,040 phishing · 40,457 ham).
              Evaluated on a <strong className="text-mfx-text">16,700-email stratified hold-out set</strong> (20%, random_state=42).
            </p>
            <MetricRow label="Accuracy"  value="97.23%" sub="target ≥ 95%" pass={true} />
            <MetricRow label="Precision" value="96.16%" sub="target ≥ 92%" pass={true} />
            <MetricRow label="Recall"    value="98.56%" sub="target ≥ 90%" pass={true} />
            <MetricRow label="F1 Score"  value="97.34%" sub="target ≥ 91%" pass={true} />
            <MetricRow label="Classify latency" value="0.005 ms" sub="per email, CPU" pass={true} />
            <MetricRow label="Pipeline latency" value="< 15s" sub="typical, online mode" pass={true} />
            <div className="mt-4 text-xs text-mfx-muted bg-mfx-bg rounded p-3 border border-mfx-border">
              <strong className="text-mfx-text">Stack:</strong> XGBoost (200 trees, depth 6) ·
              TF-IDF (ngram 1–3, 50k features) · LIME sentence-level explanations ·
              Synthetic URLTOKEN + URGENCYTOKEN features
            </div>
          </Card>

          {/* How to Use */}
          <Card>
            <SectionTitle icon="🚀">How to Use</SectionTitle>
            <div className="space-y-0">
              <Step n="1" title="Get your email's raw source">
                In Gmail: open email → ⋮ menu → "Show original" → "Copy to clipboard".
                In Outlook: File → Properties → copy the Internet Headers box.
                Or just download the .eml file directly.
              </Step>
              <Step n="2" title="Paste or drag-and-drop">
                Paste the raw text into the input area, or drag your .eml file onto the upload zone.
                The tool accepts both full raw emails (with body) and header-only pastes.
              </Step>
              <Step n="3" title="Click Analyze (or Ctrl+Enter)">
                The 4-engine pipeline runs in parallel: Auth validation → ML classification →
                IP geolocation → Domain intelligence. Takes 5–30 seconds.
              </Step>
              <Step n="4" title="Review the 7-panel dashboard">
                Risk gauge, SPF/DKIM/DMARC matrix, LIME sentence highlights,
                Leaflet geo-map with relay hops, domain intel, and the full forensic dossier.
              </Step>
              <Step n="5" title="Export forensic report (Ctrl+E)">
                Download a PDF dossier with chain-of-custody, IT Act 2000 legal mapping,
                LIME explanations, and a Bitcoin-anchored SHA-256 evidence hash.
              </Step>
            </div>
          </Card>

        </div>

        {/* ── Novelties grid ──────────────────────────────────────────────── */}
        <Card>
          <SectionTitle icon="✨">What Makes This Novel</SectionTitle>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            <NoveltyCard icon="⚖️" title="Contextual IT Act 2000 Mapping">
              The only tool that automatically maps detected email signals to specific Indian legal
              provisions (§43 / §66 / §66C / §66D) with a stated reason — bridging technical
              detection and law enforcement workflow.
            </NoveltyCard>
            <NoveltyCard icon="⛓️" title="Blockchain Evidence Anchoring">
              Email SHA-256 is committed to Bitcoin's blockchain via OpenTimestamps — free,
              permissionless, and permanently verifiable. No central authority. Court-grade
              tamper-evident proof without any fees.
            </NoveltyCard>
            <NoveltyCard icon="🔬" title="LIME Sentence Explainability">
              Not just a verdict — the model highlights which specific sentences triggered the
              phishing classification. An analyst can cite exact evidence, not just a score.
            </NoveltyCard>
            <NoveltyCard icon="🗺️" title="Provider Masking Detection">
              Explicitly flags when Gmail, Outlook, or SendGrid strip the originating IP —
              surfacing this as an investigative signal rather than silently losing the trail.
            </NoveltyCard>
            <NoveltyCard icon="🔌" title="True Air-Gap Mode">
              Runs fully offline — MaxMind GeoLite2 (local 62 MB DB) + SQLite cache.
              Designed for classified environments where email evidence cannot leave the machine.
            </NoveltyCard>
            <NoveltyCard icon="🧩" title="Unified Forensic Pipeline">
              No single existing tool combines ML intent classification + auth validation +
              multi-hop geo + domain WHOIS + blockchain anchoring + legal mapping in one
              drag-and-drop workflow under 60 seconds.
            </NoveltyCard>
          </div>
        </Card>

        {/* ── Local deployment ────────────────────────────────────────────── */}
        <Card>
          <SectionTitle icon="🐳">For Real Investigations — Run Locally</SectionTitle>
          <p className="text-xs text-mfx-muted mb-4">
            MailForenSIX is intentionally designed to be self-hosted. The air-gap mode,
            local MaxMind DB, and SQLite cache exist precisely so sensitive email evidence
            never needs to leave the investigator's machine.
          </p>
          <div className="bg-mfx-bg rounded border border-mfx-border p-4 font-mono text-xs text-mfx-accent space-y-1">
            <p className="text-mfx-muted"># One-command local setup</p>
            <p>git clone https://github.com/Stark6612/SIH_2026.git</p>
            <p>cd SIH_2026/MailForenSIX/mail-foren-six</p>
            <p>docker compose up --build</p>
            <p className="text-mfx-muted mt-2"># Then open http://localhost:5173</p>
          </div>
          <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div className="flex items-start gap-2 p-3 bg-mfx-bg rounded border border-mfx-border">
              <span className="text-mfx-safe text-base">✓</span>
              <span className="text-mfx-muted">All models included in repo — no extra downloads</span>
            </div>
            <div className="flex items-start gap-2 p-3 bg-mfx-bg rounded border border-mfx-border">
              <span className="text-mfx-safe text-base">✓</span>
              <span className="text-mfx-muted">MaxMind GeoLite2-City.mmdb (62 MB) bundled</span>
            </div>
            <div className="flex items-start gap-2 p-3 bg-mfx-bg rounded border border-mfx-border">
              <span className="text-mfx-safe text-base">✓</span>
              <span className="text-mfx-muted">Air-gap mode: zero external API calls</span>
            </div>
          </div>
        </Card>

        {/* ── Pipeline overview ───────────────────────────────────────────── */}
        <Card>
          <SectionTitle icon="⚙️">How the Pipeline Works</SectionTitle>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center text-xs">
            {[
              { icon: '📨', label: 'Parse', sub: 'RFC 5322 headers, body, relay hops' },
              { icon: '🔐', label: 'Auth', sub: 'SPF · DKIM · DMARC · From alignment' },
              { icon: '🤖', label: 'Classify', sub: 'XGBoost + TF-IDF + LIME' },
              { icon: '🌍', label: 'Geo', sub: 'ip-api.com → MaxMind fallback' },
              { icon: '🔎', label: 'Domain', sub: 'WHOIS · MX · TLD · Privacy proxy' },
              { icon: '⚖️', label: 'Risk Score', sub: 'Auth 30% + ML 30% + Geo 20% + Domain 20%' },
              { icon: '📄', label: 'PDF Report', sub: 'ReportLab · CoC · IT Act · SHA-256' },
              { icon: '⛓️', label: 'Anchor', sub: 'OTS → Bitcoin blockchain' },
            ].map(item => (
              <div key={item.label}
                className="p-3 rounded-lg bg-mfx-bg border border-mfx-border hover:border-mfx-accent/40 transition-colors">
                <div className="text-2xl mb-1">{item.icon}</div>
                <div className="font-bold text-mfx-text mb-0.5">{item.label}</div>
                <div className="text-mfx-muted leading-tight">{item.sub}</div>
              </div>
            ))}
          </div>
        </Card>

        {/* ── Footer ──────────────────────────────────────────────────────── */}
        <div className="text-center text-xs text-mfx-muted py-6 border-t border-mfx-border space-y-1">
          <p>MailForenSIX v0.3.0 · Smart India Hackathon 2026 · Problem #26106</p>
          <p>Team CyberNexus ·{' '}
            <a href="https://github.com/Stark6612/SIH_2026" target="_blank"
              rel="noopener noreferrer" className="text-mfx-accent hover:underline">
              github.com/Stark6612/SIH_2026
            </a>
          </p>
          <p className="text-mfx-border">
            Trained on 83,497 emails · XGBoost 97.23% accuracy · Forensic + Legal + Blockchain
          </p>
        </div>

      </main>
    </div>
  )
}

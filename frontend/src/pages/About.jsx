import { Link } from 'react-router-dom'
import StrokeText from '../components/animations/StrokeText'
import SpotlightCard from '../components/animations/SpotlightCard'
import CountUp from '../components/animations/CountUp'
import ScrollReveal from '../components/animations/ScrollReveal'

// ── Reusable card shell ────────────────────────────────────────────────────────
function Card({ children, className = '', scrollReveal = true }) {
  const inner = (
    <div className={`bg-mfx-surface border border-mfx-border rounded-panel p-6 ${className}`}>
      {children}
    </div>
  )
  if (!scrollReveal) return inner
  return (
    <ScrollReveal baseRotation={0.5} baseOpacity={0.3} blurStrength={0} containerClassName="w-full">
      {inner}
    </ScrollReveal>
  )
}

function SectionTitle({ icon, children }) {
  return (
    <h2 className="flex items-center gap-2 text-xl font-bold text-mfx-text mb-5">
      <span className="text-mfx-accent">{icon}</span>
      {children}
    </h2>
  )
}

function MetricRow({ label, value, sub, pass }) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-mfx-border last:border-0">
      <div>
        <span className="text-base text-mfx-text font-medium">{label}</span>
        {sub && <span className="ml-2 text-sm text-mfx-muted">{sub}</span>}
      </div>
      <div className="flex items-center gap-2">
        <span className="text-base font-bold text-mfx-accent font-mono">{value}</span>
        {pass !== undefined && (
          <span className={`text-sm px-2 py-0.5 rounded-badge font-semibold
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
      <div className="flex-shrink-0 w-9 h-9 rounded-full bg-mfx-accent/20 border border-mfx-accent/40
                      flex items-center justify-center text-base font-bold text-mfx-accent">
        {n}
      </div>
      <div className="pb-6 border-b border-mfx-border last:border-0 flex-1">
        <p className="text-base font-semibold text-mfx-text mb-1">{title}</p>
        <p className="text-sm text-mfx-muted leading-relaxed">{children}</p>
      </div>
    </div>
  )
}

function NoveltyCard({ icon, title, children }) {
  return (
    <SpotlightCard
      className="bg-mfx-bg border border-mfx-border hover:border-mfx-accent/40 transition-colors group"
      spotlightColor="rgba(59,130,246,0.12)"
    >
      <div className="p-5">
        <div className="flex items-center gap-2 mb-2.5">
          <span className="text-2xl">{icon}</span>
          <span className="text-base font-bold text-mfx-text group-hover:text-mfx-accent transition-colors">
            {title}
          </span>
        </div>
        <p className="text-sm text-mfx-muted leading-relaxed">{children}</p>
      </div>
    </SpotlightCard>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────
export default function About() {
  return (
    <div className="min-h-dvh bg-mfx-bg text-mfx-text">

      {/* ── Mini top bar ──────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-50 bg-mfx-bg/80 backdrop-blur-md border-b border-mfx-border">
        <div className="w-full px-8 h-14 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
            <div className="w-9 h-9 rounded-badge bg-mfx-accent flex items-center justify-center text-xl shadow-glow">
              📧
            </div>
            <div>
              <span className="font-bold text-xl text-mfx-text tracking-tight">MailForen</span>
              <span className="font-bold text-xl text-mfx-accent">SIX</span>
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

      <main className="w-full px-8 py-10 space-y-8">

        {/* ── Hero ──────────────────────────────────────────────────────── */}
        <div className="text-center space-y-3 pb-4">
          <div className="inline-flex items-center gap-2 text-sm text-mfx-muted border border-mfx-border
                          px-4 py-1.5 rounded-full mb-3">
            <span className="w-2 h-2 rounded-full bg-mfx-accent animate-pulse" />
            Academic Project · AI & Cyber Threat Intelligence
          </div>
          <div className="max-w-xl mx-auto py-1">
            <StrokeText
              text="MailForenSIX"
              strokeColor="#3B82F6"
              fillColor="#F8FAFC"
              strokeWidth={1.4}
              drawDuration={1.6}
              fillDelay={0.2}
              stagger={0.05}
              ease="power2.out"
              trigger="mount"
              fillMode="wipe"
              fontSize={80}
              fontWeight={800}
              letterSpacing={-2}
            />
          </div>
          <ScrollReveal
            enableBlur={true}
            baseOpacity={0.2}
            blurStrength={3}
            baseRotation={0}
            containerClassName="max-w-2xl mx-auto"
            textClassName="text-mfx-muted text-lg text-center leading-relaxed"
          >
            An AI-powered email threat detection, geolocation, and forensic intelligence platform — built for cybersecurity analysts, forensic investigators, and law enforcement.
          </ScrollReveal>
        </div>

        {/* ── MVP Disclaimer banner ──────────────────────────────────────── */}
        <ScrollReveal baseRotation={0.5} baseOpacity={0.4} blurStrength={0} containerClassName="w-full">
          <div className="rounded-panel border border-mfx-suspicious/40 bg-mfx-suspicious/10 p-5
                          flex gap-4 items-start">
            <span className="text-2xl flex-shrink-0">⚠️</span>
            <div className="space-y-1.5">
              <p className="text-base font-semibold text-mfx-suspicious">
                Demo Build — Not for Production Investigative Use
              </p>
              <p className="text-sm text-mfx-muted leading-relaxed">
                This is an academic research prototype built for threat intelligence and forensic analysis evaluation.
                This live deployment is shared for demonstration and evaluation purposes only.
                When you submit an email here, its content is processed by our server.
                For actual forensic investigations involving sensitive or confidential emails,
                <strong className="text-mfx-text"> run MailForenSIX locally</strong> using Docker —
                your data never leaves your machine.
                See the <a href="https://github.com/Stark6612/MailForenSIX" target="_blank"
                rel="noopener noreferrer" className="text-mfx-accent hover:underline">GitHub repo</a> for
                local setup instructions.
              </p>
            </div>
          </div>
        </ScrollReveal>

        {/* ── Main grid — 3 cols ──────────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* ML Metrics */}
          <Card>
            <SectionTitle icon="📊">Model Performance</SectionTitle>
            <p className="text-sm text-mfx-muted mb-5">
              Trained on <strong className="text-mfx-text">103,360 emails</strong> (53,785 phishing · 49,575 ham).
              Evaluated on a <strong className="text-mfx-text">20,672-email stratified hold-out set</strong> (20%, random_state=42).
            </p>
            <MetricRow label="Accuracy"  value="96.16%" sub="target ≥ 95%" pass={true} />
            <MetricRow label="Precision" value="96.16%" sub="target ≥ 92%" pass={true} />
            <MetricRow label="Recall"    value="96.20%" sub="target ≥ 90%" pass={true} />
            <MetricRow label="F1 Score"  value="96.31%" sub="target ≥ 91%" pass={true} />
            <MetricRow label="Classify latency" value="0.005 ms" sub="per email, CPU" pass={true} />
            <MetricRow label="Pipeline latency (air-gapped)" value="~10 ms" sub="local, no DNS/geo calls" pass={true} />
            <MetricRow label="Pipeline latency (live DNS)" value="4 – 9s" sub="local server, real DNS + ip-api.com" pass={true} />
            <MetricRow label="Pipeline latency (deployed)" value="8 – 20s" sub="cloud VPS, live DNS + geo, network RTT" pass={true} />
            <div className="mt-5 text-sm text-mfx-muted bg-mfx-bg rounded p-4 border border-mfx-border">
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
                The 7-engine pipeline runs in parallel: Auth validation → ML classification → IP geolocation → Domain intelligence. Air-gapped: ~10 ms. Live DNS (local): 4–9s. Deployed (cloud): 8–20s.
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

          {/* Quick Stats — 3rd column */}
          <Card>
            <SectionTitle icon="🏆">Quick Stats</SectionTitle>
            <div className="space-y-3">
              {[
                { label: 'Training Emails', value: '83,497', icon: '📧',
                  animated: <CountUp from={0} to={103360} separator="," duration={1.8} /> },
                { label: 'Test Accuracy', value: '97.23%', icon: '🎯',
                  animated: <><CountUp from={0} to={96.16} decimals={2} duration={1.5} />%</> },
                { label: 'F1 Score', value: '97.34%', icon: '📐',
                  animated: <><CountUp from={0} to={96.31} decimals={2} duration={1.5} />%</> },
                { label: 'Classify Speed', value: '0.005 ms', icon: '⚡' },
                { label: 'Pipeline (air-gap)', value: '~10 ms', icon: '⚡' },
                { label: 'Pipeline (live DNS)', value: '4 – 9s', icon: '🚀' },
                { label: 'Pipeline (deployed)', value: '8 – 20s', icon: '☁️' },
                { label: 'Geo DB Size', value: '62 MB offline', icon: '🗺️' },
                { label: 'Risk Signals', value: '7 engines', icon: '🔬',
                  animated: <><CountUp from={0} to={7} duration={1} /> engines</> },
                { label: 'IT Act Sections', value: '§43 · §66 · §66C · §66D', icon: '⚖️' },
                { label: 'Evidence Anchor', value: 'Bitcoin blockchain', icon: '⛓️' },
                { label: 'Campaign ARI', value: '0.8806', icon: '🧩' },
                { label: 'Docker Deploy', value: '1 command', icon: '🐳' },
              ].map(s => (
                <div key={s.label}
                  className="flex items-center justify-between py-2 border-b border-mfx-border last:border-0">
                  <span className="flex items-center gap-2 text-sm text-mfx-muted">
                    <span>{s.icon}</span>{s.label}
                  </span>
                  <span className="text-sm font-bold text-mfx-accent font-mono">{s.animated ?? s.value}</span>
                </div>
              ))}
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
            <NoveltyCard icon="🗺️" title="CERT-In Incident Classification">
              Every analysis is automatically classified into CERT-In 2022 incident categories (Phishing, BEC, Malware, Spam) with severity rating and statutory reference — mandatory for Indian institutional reporting.
            </NoveltyCard>
            <NoveltyCard icon="🔌" title="True Air-Gap Mode">
              Runs fully offline — MaxMind GeoLite2 (62 MB DB) + SQLite SPF/DMARC cache (52 Indian institutional domains pre-loaded) + URLhaus 5,728 malicious domain blacklist.
              Designed for classified environments where email evidence cannot leave the machine.
            </NoveltyCard>
            <NoveltyCard icon="🧩" title="Mode 2: Campaign Clustering">
              Batch-analyze up to 200 emails at once. UMAP + HDBSCAN clustering groups them by campaign — ARI 0.88 on synthetic corpus. Exports STIX 2.1, Sigma, Suricata, Postfix, Exchange rules, and DNSBL blocklists.
            </NoveltyCard>
          </div>
        </Card>

        {/* ── Local deployment ────────────────────────────────────────────── */}
        <Card>
          <SectionTitle icon="🐳">For Real Investigations — Run Locally</SectionTitle>
          <p className="text-sm text-mfx-muted mb-5">
            MailForenSIX is intentionally designed to be self-hosted. The air-gap mode,
            local MaxMind DB, and SQLite cache exist precisely so sensitive email evidence
            never needs to leave the investigator's machine.
          </p>
          <div className="bg-mfx-bg rounded border border-mfx-border p-5 font-mono text-sm text-mfx-accent space-y-1.5">
            <p className="text-mfx-muted"># One-command local setup</p>
            <p>git clone https://github.com/Stark6612/MailForenSIX.git</p>
            <p>cd MailForenSIX</p>
            <p>docker compose up --build</p>
            <p className="text-mfx-muted mt-2"># Then open http://localhost:5173</p>
          </div>
          <div className="mt-5 grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
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
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-center text-sm">
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
                <div className="text-3xl mb-1.5">{item.icon}</div>
                <div className="font-bold text-mfx-text mb-1">{item.label}</div>
                <div className="text-mfx-muted leading-tight text-xs">{item.sub}</div>
              </div>
            ))}
          </div>
        </Card>

        {/* ── Footer ──────────────────────────────────────────────────────── */}
        <div className="text-center text-sm text-mfx-muted py-8 border-t border-mfx-border space-y-1.5">
          <p>MailForenSIX v0.4.0 · Academic Threat Intelligence & Forensics Platform</p>
          <p>Cyber Threat Intelligence & Forensics Lab ·{' '}
            <a href="https://github.com/Stark6612/MailForenSIX" target="_blank"
              rel="noopener noreferrer" className="text-mfx-accent hover:underline">
              github.com/Stark6612/MailForenSIX
            </a>
          </p>
          <p className="text-mfx-border">
            Trained on 103,360 emails · XGBoost 96.16% accuracy · Forensic + Legal + Blockchain
          </p>
        </div>

      </main>
    </div>
  )
}

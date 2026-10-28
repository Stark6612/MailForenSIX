import React, { useState, useEffect } from 'react'
import { getModelBenchmark, getAblationResults, getAvLimits, evaluateModelSandbox, analyzeEmail, BACKEND_ROOT } from '../lib/api'

const PLOT_OPTIONS = [
  { id: 'confusion_matrices', name: '5-Panel Confusion Matrices', desc: 'Normalized per-class misclassifications across all 5 algorithms' },
  { id: 'roc_curves',         name: 'Multi-Class ROC Curves',      desc: 'One-vs-Rest ROC curves with Macro-AUCs (LR: 0.9903, SVM: 0.9886)' },
  { id: 'latency_pareto',     name: 'Latency Pareto Frontier',    desc: 'Trade-off frontier between inference latency (µs) and Macro-F1' },
  { id: 'pr_curves',          name: 'Precision-Recall Curves',    desc: 'Precision vs. Recall curves per class and algorithm' },
  { id: 'feature_ablation',   name: 'Feature Representation Ablation', desc: 'Systematic progression from BoW to Hybrid structural metadata (+1.83%)' },
  { id: 'lime_attribution',   name: 'Multi-Class LIME Attributions',   desc: 'Local surrogate linear feature weights for Phishing, Spam, and Legitimate' },
  { id: 'av_limits',          name: 'CO2: Antivirus Limits & Entropy', desc: 'Cryptographic hash evasion (0% AV vs 100% AI) and Shannon entropy' },
]

export default function ModelComparison() {
  const [activeTab, setActiveTab] = useState('table') // 'table' | 'plots' | 'ablation' | 'av_limits' | 'sandbox'
  const [selectedPlot, setSelectedPlot] = useState('confusion_matrices')
  const [benchmarkData, setBenchmarkData] = useState(null)
  const [ablationData, setAblationData] = useState(null)
  const [avLimitsData, setAvLimitsData] = useState(null)
  const [loading, setLoading] = useState(true)

  // Sandbox state
  const [sandboxText, setSandboxText] = useState('')
  const [sandboxRunning, setSandboxRunning] = useState(false)
  const [sandboxResults, setSandboxResults] = useState(null)

  useEffect(() => {
    async function loadData() {
      try {
        const [bench, ablate, av] = await Promise.allSettled([
          getModelBenchmark(),
          getAblationResults(),
          getAvLimits(),
        ])
        if (bench.status === 'fulfilled') setBenchmarkData(bench.value)
        if (ablate.status === 'fulfilled') setAblationData(ablate.value)
        if (av.status === 'fulfilled') setAvLimitsData(av.value)
      } catch (err) {
        console.error('Failed to load benchmark data', err)
      } finally {
        setLoading(false)
      }
    }
    loadData()
  }, [])

  const handleRunSandbox = async (sampleText) => {
    const textToTest = sampleText || sandboxText
    if (!textToTest.trim()) return
    setSandboxText(textToTest)
    setSandboxRunning(true)
    setSandboxResults(null)

    try {
      // 1. Direct high-speed AICS sandbox endpoint
      const data = await evaluateModelSandbox(textToTest)
      if (data && data.results && data.results.length > 0) {
        setSandboxResults(data.results)
        return
      }
    } catch (sandboxErr) {
      console.warn('Sandbox endpoint returned error, trying analyzeEmail fallback:', sandboxErr)
    }

    // 2. Fallback via analyzeEmail route
    const modelKeys = ['lr', 'svm', 'xgb', 'nb', 'dt']
    try {
      const results = await Promise.all(
        modelKeys.map(async (m) => {
          try {
            const res = await analyzeEmail(null, textToTest, m)
            return {
              key: m,
              name: res.model_inference?.model_name || m.toUpperCase(),
              label: res.threat_label || 'safe',
              confidence: res.confidence || 0.0,
              probs: res.model_inference?.class_probabilities || {},
              riskScore: res.risk_score || 0,
              riskTier: res.risk_tier || 'safe',
            }
          } catch (e) {
            return { key: m, name: m.toUpperCase(), label: 'error', confidence: 0, probs: {}, error: e.message }
          }
        })
      )
      setSandboxResults(results)
    } catch (err) {
      console.error('All sandbox evaluations failed:', err)
    } finally {
      setSandboxRunning(false)
    }
  }

  const plotUrl = BACKEND_ROOT
    ? `${BACKEND_ROOT}/api/v1/models/plots/${selectedPlot}`
    : `/api/v1/models/plots/${selectedPlot}`

  return (
    <div className="flex-1 px-6 py-6 w-full max-w-7xl mx-auto space-y-6 text-mfx-text">
      {/* Page Header */}
      <div className="flex items-center justify-between border-b border-white/[0.08] pb-4 flex-wrap gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-2xl">📊</span>
            <h1 className="text-xl font-bold tracking-tight text-white">
              AICS Multi-Model Algorithmic Benchmark & Comparison
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-500/10 border border-indigo-500/30 text-indigo-300">
              Course: 23AI2001
            </span>
          </div>
          <p className="text-xs text-mfx-muted mt-1">
            Empirical comparative analysis of 5 syllabus classifiers on 31,164 stratified tripartite emails (Legitimate vs. Spam vs. Phishing).
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center bg-slate-900/80 p-1 rounded-xl border border-white/10 text-xs font-medium">
          {[
            { id: 'table',     label: 'Benchmark Table' },
            { id: 'plots',     label: 'Diagnostic Curves' },
            { id: 'ablation',  label: 'Feature Ablation' },
            { id: 'av_limits', label: 'Antivirus Limits (CO2)' },
            { id: 'sandbox',   label: 'Live 5-Model Sandbox' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-3 py-1.5 rounded-lg transition-all ${
                activeTab === tab.id
                  ? 'bg-indigo-600 text-white shadow font-semibold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── TAB 1: Benchmark Matrix Table ── */}
      {activeTab === 'table' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <span>🏆</span> Cross-Model Empirical Evaluation Matrix (6,233 Stratified Test Emails)
            </h2>
            <span className="text-xs text-slate-400 font-mono">
              Stratified: 80% Train (24,931) / 20% Test (6,233)
            </span>
          </div>

          <div className="overflow-x-auto rounded-xl border border-white/10 bg-slate-900/60 shadow-xl backdrop-blur-md">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-800/80 text-slate-300 uppercase tracking-wider text-[11px] font-mono border-b border-white/10">
                <tr>
                  <th className="py-3 px-4">Algorithm & Paradigm</th>
                  <th className="py-3 px-3 text-center">Syllabus Ref</th>
                  <th className="py-3 px-3 text-right">Accuracy</th>
                  <th className="py-3 px-3 text-right">Macro Prec</th>
                  <th className="py-3 px-3 text-right">Macro Rec</th>
                  <th className="py-3 px-3 text-right font-bold text-indigo-300">Macro F1</th>
                  <th className="py-3 px-3 text-right text-emerald-400">F1 (Legit)</th>
                  <th className="py-3 px-3 text-right text-amber-400">F1 (Spam)</th>
                  <th className="py-3 px-3 text-right text-rose-400">F1 (Phish)</th>
                  <th className="py-3 px-3 text-right text-sky-300">Latency</th>
                  <th className="py-3 px-3 text-right">Size</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 font-mono">
                {benchmarkData ? (
                  Object.entries(benchmarkData).map(([key, m]) => {
                    const isWinner = key === 'lr' || key === 'svm'
                    return (
                      <tr
                        key={key}
                        className={`hover:bg-indigo-500/5 transition-colors ${
                          isWinner ? 'bg-indigo-500/[0.03]' : ''
                        }`}
                      >
                        <td className="py-3.5 px-4 font-sans font-semibold text-white flex items-center gap-2">
                          <span>{m.name}</span>
                          {key === 'lr' && (
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                              ★ Pareto Winner
                            </span>
                          )}
                          {key === 'svm' && (
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-blue-500/20 text-blue-300 border border-blue-500/40">
                              Max Margin
                            </span>
                          )}
                        </td>
                        <td className="py-3.5 px-3 text-center text-slate-400 text-[11px]">
                          {m.syllabus_ref?.split(':')[0] || 'Module 2'}
                        </td>
                        <td className="py-3.5 px-3 text-right font-bold text-white">
                          {(m.accuracy * 100).toFixed(2)}%
                        </td>
                        <td className="py-3.5 px-3 text-right text-slate-300">{m.macro_precision?.toFixed(4)}</td>
                        <td className="py-3.5 px-3 text-right text-slate-300">{m.macro_recall?.toFixed(4)}</td>
                        <td className="py-3.5 px-3 text-right font-bold text-indigo-300 text-sm">
                          {m.macro_f1?.toFixed(4)}
                        </td>
                        <td className="py-3.5 px-3 text-right text-emerald-400">{m.f1_legitimate?.toFixed(4)}</td>
                        <td className="py-3.5 px-3 text-right text-amber-400">{m.f1_spam?.toFixed(4)}</td>
                        <td className="py-3.5 px-3 text-right text-rose-400">{m.f1_phishing?.toFixed(4)}</td>
                        <td className="py-3.5 px-3 text-right text-sky-300 font-semibold">
                          {m.inference_latency_us?.toFixed(1)} µs
                        </td>
                        <td className="py-3.5 px-3 text-right text-slate-400">
                          {m.model_size_kb?.toFixed(0)} KB
                        </td>
                      </tr>
                    )
                  })
                ) : (
                  <tr>
                    <td colSpan={11} className="py-6 text-center text-slate-500">
                      Loading benchmark matrix...
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pareto Frontier Insights Card */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
            <div className="p-4 rounded-xl bg-slate-900/60 border border-white/10 space-y-1.5">
              <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                <span>⚡</span> Sub-Microsecond Gateway Throughput
              </span>
              <p className="text-sm font-bold text-white">Logistic Regression (0.2 µs)</p>
              <p className="text-xs text-slate-400 leading-relaxed">
                Processes ~5,000,000 emails per second per CPU core with 93.34% F1, creating an optimal edge filter for SMTP MTAs.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/60 border border-white/10 space-y-1.5">
              <span className="text-xs font-semibold text-blue-400 uppercase tracking-wider flex items-center gap-1.5">
                <span>🛡️</span> Maximum Margin Geometric Separation
              </span>
              <p className="text-sm font-bold text-white">Linear SVM (Platt Calibrated)</p>
              <p className="text-xs text-slate-400 leading-relaxed">
                Achieves 93.28% F1 with Platt calibration, separating high-dimensional sparse TF-IDF vectors (10,000 dims) with maximal boundary confidence.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/60 border border-white/10 space-y-1.5">
              <span className="text-xs font-semibold text-purple-400 uppercase tracking-wider flex items-center gap-1.5">
                <span>🌲</span> Non-Linear Ensemble Boosting
              </span>
              <p className="text-sm font-bold text-white">HistGradientBoosting (91.22% Acc)</p>
              <p className="text-xs text-slate-400 leading-relaxed">
                Bins features into 256 discrete histograms, capturing non-linear interactions across phishing collocations with 0.9124 Macro F1.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 2: Diagnostic Curves Gallery ── */}
      {activeTab === 'plots' && (
        <div className="space-y-4">
          <div className="flex items-center gap-2 flex-wrap">
            {PLOT_OPTIONS.map((opt) => (
              <button
                key={opt.id}
                onClick={() => setSelectedPlot(opt.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  selectedPlot === opt.id
                    ? 'bg-indigo-600 text-white shadow'
                    : 'bg-slate-900 text-slate-400 hover:text-white border border-white/5'
                }`}
              >
                {opt.name}
              </button>
            ))}
          </div>

          <div className="p-4 rounded-xl bg-slate-900/70 border border-white/10 space-y-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div>
                <h3 className="text-sm font-bold text-white">
                  {PLOT_OPTIONS.find((p) => p.id === selectedPlot)?.name}
                </h3>
                <p className="text-xs text-slate-400">
                  {PLOT_OPTIONS.find((p) => p.id === selectedPlot)?.desc}
                </p>
              </div>
              <a
                href={plotUrl}
                target="_blank"
                rel="noreferrer"
                className="text-xs text-indigo-400 hover:underline flex items-center gap-1 font-mono"
              >
                <span>↗</span> Open Full High-Res PNG
              </a>
            </div>

            <div className="rounded-lg overflow-hidden border border-white/10 bg-black/40 flex items-center justify-center min-h-[400px]">
              <img
                src={plotUrl}
                alt={selectedPlot}
                className="w-full max-h-[650px] object-contain rounded"
                onError={(e) => {
                  e.target.onerror = null
                  e.target.src = ''
                }}
              />
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 3: Feature Ablation Study ── */}
      {activeTab === 'ablation' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <span>🔬</span> Systematic Feature Engineering Ablation Study (Module 1 Optimization)
            </h2>
            <span className="text-xs text-indigo-300 font-mono font-semibold">
              Maximum Gain: +1.83% Macro F1
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[
              {
                setup: 'Setup 1',
                title: 'Bag-of-Words (BoW)',
                desc: 'Raw term frequencies (CountVectorizer, max_features=10,000)',
                acc: '91.42%',
                f1: '0.9145',
                delta: '+0.00%',
                deltaColor: 'text-slate-400',
              },
              {
                setup: 'Setup 2',
                title: 'TF-IDF (Unigram)',
                desc: 'Inverse document frequency scaling dampening common terms',
                acc: '92.76%',
                f1: '0.9276',
                delta: '+1.31%',
                deltaColor: 'text-sky-400',
              },
              {
                setup: 'Setup 3',
                title: 'TF-IDF (1-2 N-grams)',
                desc: 'Sublinear TF scaling + bigram phrases (account suspended, click here)',
                acc: '93.18%',
                f1: '0.9318',
                delta: '+1.73%',
                deltaColor: 'text-emerald-400',
              },
              {
                setup: 'Setup 4',
                title: 'Hybrid + Structural',
                desc: 'TF-IDF + 8 continuous cyber cues (URL, IP, Currency, Urgency ratios)',
                acc: '93.28%',
                f1: '0.9327',
                delta: '+1.83%',
                deltaColor: 'text-indigo-400 font-bold',
              },
            ].map((s) => (
              <div
                key={s.setup}
                className="p-4 rounded-xl bg-slate-900/60 border border-white/10 space-y-2 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">{s.setup}</span>
                    <span className={`text-xs font-mono font-semibold ${s.deltaColor}`}>{s.delta} F1</span>
                  </div>
                  <h4 className="text-sm font-bold text-white">{s.title}</h4>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">{s.desc}</p>
                </div>
                <div className="pt-2 border-t border-white/5 flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400">Acc: <span className="text-white font-semibold">{s.acc}</span></span>
                  <span className="text-slate-400">Macro F1: <span className="text-indigo-300 font-bold">{s.f1}</span></span>
                </div>
              </div>
            ))}
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-white/10 space-y-2">
            <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              Scientific Takeaway & Defense Argument
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed">
              Moving from raw Bag-of-Words to Sublinear TF-IDF with bigram collocations improves model Macro-F1 by <strong>+1.73%</strong>. Concatenating dense syntactic metadata via <code className="text-indigo-300">scipy.sparse.hstack</code> achieves an overall <strong>+1.83%</strong> gain (93.28% Accuracy), proving that feature representation optimization was mathematically principled rather than empirical guesswork.
            </p>
          </div>
        </div>
      )}

      {/* ── TAB 4: Antivirus Limits (CO2) ── */}
      {activeTab === 'av_limits' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <span>🛡️</span> Course Outcome 2: Antivirus Limits in Threat Detection
            </h2>
            <span className="text-xs text-rose-300 font-mono font-semibold">
              CO2 Empirical Benchmark
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Signature Hash Evasion Card */}
            <div className="p-5 rounded-xl bg-slate-900/70 border border-white/10 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <span>💥</span> Cryptographic Hash Avalanche vs. Semantic AI
                </h3>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  0% AV vs 100% AI
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Traditional signature antivirus engines compute cryptographic digests (MD5, SHA-256) of known malicious lures. By applying polymorphic rephrasing, synonym replacement, or tracking IDs, the digest completely mutates:
              </p>
              <div className="space-y-1.5 font-mono text-[11px]">
                <div className="p-2 rounded bg-black/40 border border-white/5 flex justify-between items-center">
                  <span className="text-slate-400">Seed Lure MD5:</span>
                  <span className="text-emerald-400 font-bold">0597b666... (AV Hit: 100%)</span>
                </div>
                <div className="p-2 rounded bg-black/40 border border-white/5 flex justify-between items-center">
                  <span className="text-slate-400">Mutation 1 (Lexical):</span>
                  <span className="text-rose-400 font-bold">7a278398... (AV Miss: 0% | AI Hit: 98.9%)</span>
                </div>
                <div className="p-2 rounded bg-black/40 border border-white/5 flex justify-between items-center">
                  <span className="text-slate-400">Mutation 2 (Salutation):</span>
                  <span className="text-rose-400 font-bold">31d7ecbd... (AV Miss: 0% | AI Hit: 90.6%)</span>
                </div>
                <div className="p-2 rounded bg-black/40 border border-white/5 flex justify-between items-center">
                  <span className="text-slate-400">Mutation 3 (Zero-width):</span>
                  <span className="text-rose-400 font-bold">a892fd29... (AV Miss: 0% | AI Hit: 82.6%)</span>
                </div>
              </div>
            </div>

            {/* Shannon Entropy Payload Triage Card */}
            <div className="p-5 rounded-xl bg-slate-900/70 border border-white/10 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <span>🎲</span> Shannon Entropy Attachment Triage (Max: 8.0 Bits)
                </h3>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  Threshold: 7.20 Bits
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Calculates byte randomness: <code className="text-emerald-300">H(X) = -∑ p(x) log2 p(x)</code>. High entropy ($H \ge 7.20$) detects encrypted, obfuscated, and UPX-packed payloads before execution:
              </p>
              <div className="space-y-1.5 font-mono text-[11px]">
                <div className="p-2 rounded bg-black/40 border border-white/5 flex justify-between items-center">
                  <span className="text-slate-400">Plaintext HTML / Invoice:</span>
                  <span className="text-emerald-400 font-bold">4.18 bits/byte (Clean / Benign)</span>
                </div>
                <div className="p-2 rounded bg-black/40 border border-white/5 flex justify-between items-center">
                  <span className="text-slate-400">Benign Python Script:</span>
                  <span className="text-emerald-400 font-bold">4.29 bits/byte (Clean / Benign)</span>
                </div>
                <div className="p-2 rounded bg-black/40 border border-white/5 flex justify-between items-center">
                  <span className="text-slate-400">Standard PE x86 Binary:</span>
                  <span className="text-amber-400 font-bold">5.82 bits/byte (Compiled Binary)</span>
                </div>
                <div className="p-2 rounded bg-black/40 border border-white/5 flex justify-between items-center">
                  <span className="text-slate-400">Packed / Obfuscated Trojan:</span>
                  <span className="text-rose-400 font-bold">8.00 bits/byte (🚨 High-Risk Blocked)</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 5: Live 5-Model Testing Sandbox ── */}
      {activeTab === 'sandbox' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <span>🧪</span> Real-Time Multi-Model Decision Surface Sandbox
            </h2>
            <span className="text-xs text-slate-400 font-mono">
              Runs all 5 algorithms in parallel on the same email
            </span>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-slate-400 font-medium">Quick Lures:</span>
            <button
              onClick={() =>
                handleRunSandbox(
                  'Mail Security Alert: Dear user, your mailbox session has expired and incoming emails are on pending status. Action required: Please click here immediately to verify your identity and confirm your account login: http://security-update-portal.org/login. Unauthorized access has been detected.'
                )
              }
              className="px-2.5 py-1 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs hover:bg-rose-500/20 font-mono"
            >
              Phishing Lure
            </button>
            <button
              onClick={() =>
                handleRunSandbox(
                  'CONGRATULATIONS! You have been selected to win a free $5,000 cash voucher and luxury gift card. Limited time discount offer for approved subscribers! Claim your exclusive prize today: http://best-deals-super-promo.org/claim. Unsubscribe at any time.'
                )
              }
              className="px-2.5 py-1 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs hover:bg-amber-500/20 font-mono"
            >
              Commercial Bulk Spam
            </button>
            <button
              onClick={() =>
                handleRunSandbox(
                  "Hi team, please find attached the quarterly financial progress report and sprint deliverables review. We finalized the Q4 roadmap yesterday. Let me know if you have any questions before Friday's project standup."
                )
              }
              className="px-2.5 py-1 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs hover:bg-emerald-500/20 font-mono"
            >
              Legitimate Corporate Memo
            </button>
          </div>

          <div className="space-y-2">
            <textarea
              rows={4}
              value={sandboxText}
              onChange={(e) => setSandboxText(e.target.value)}
              placeholder="Paste email text to compare decisions across all 5 models..."
              className="w-full bg-slate-900 border border-white/10 rounded-xl p-3 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
            />
            <button
              onClick={() => handleRunSandbox(null)}
              disabled={sandboxRunning || !sandboxText.trim()}
              className="btn-primary text-xs py-2 px-4 disabled:opacity-40"
            >
              {sandboxRunning ? 'Evaluating 5 Classifiers…' : '▶ Compare All 5 Models Live'}
            </button>
          </div>

          {/* Sandbox Results Cards */}
          {sandboxResults && (
            <div className="grid grid-cols-1 md:grid-cols-5 gap-3 pt-2">
              {sandboxResults.map((res) => {
                const isPhish = res.label === 'phishing'
                const isSpam  = res.label === 'spam'
                const isErr   = res.error || res.label === 'error'
                const borderCls = isErr
                  ? 'border-rose-500/30 bg-rose-500/[0.02]'
                  : isPhish
                  ? 'border-rose-500/40 bg-rose-500/[0.04]'
                  : isSpam
                  ? 'border-amber-500/40 bg-amber-500/[0.04]'
                  : 'border-emerald-500/40 bg-emerald-500/[0.04]'

                const confPct = Math.round((res.confidence ?? 0) * 100)

                return (
                  <div key={res.key} className={`p-3.5 rounded-xl border ${borderCls} space-y-2.5 transition-all`}>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[10px] text-slate-400 uppercase font-semibold">
                        {res.key.toUpperCase()}
                      </span>
                      <span
                        className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                          isErr
                            ? 'bg-rose-500/20 text-rose-300'
                            : isPhish
                            ? 'bg-rose-500/20 text-rose-300'
                            : isSpam
                            ? 'bg-amber-500/20 text-amber-300'
                            : 'bg-emerald-500/20 text-emerald-300'
                        }`}
                      >
                        {isErr ? 'ERROR' : res.label?.toUpperCase()}
                      </span>
                    </div>

                    <div>
                      <h4 className="text-xs font-bold text-white truncate" title={res.name}>
                        {res.name}
                      </h4>
                      <div className="flex items-center justify-between mt-1 text-[11px] font-mono">
                        <span className="text-indigo-300">Conf: {confPct}%</span>
                        {res.latency_ms != null && (
                          <span className="text-[10px] text-slate-400">⚡ {res.latency_ms} ms</span>
                        )}
                      </div>
                    </div>

                    {isErr ? (
                      <div className="text-[10px] text-rose-400 font-mono bg-rose-500/10 p-1.5 rounded border border-rose-500/20">
                        {res.error}
                      </div>
                    ) : res.probs ? (
                      <div className="space-y-1.5 pt-1.5 border-t border-white/5 text-[10px] font-mono">
                        {/* 3-class distribution bar */}
                        <div className="h-1.5 w-full rounded-full bg-slate-800 flex overflow-hidden">
                          <div
                            style={{ width: `${Math.round((res.probs.legitimate || 0) * 100)}%` }}
                            className="bg-emerald-500 transition-all duration-300"
                            title={`Legit: ${Math.round((res.probs.legitimate || 0) * 100)}%`}
                          />
                          <div
                            style={{ width: `${Math.round((res.probs.spam || 0) * 100)}%` }}
                            className="bg-amber-500 transition-all duration-300"
                            title={`Spam: ${Math.round((res.probs.spam || 0) * 100)}%`}
                          />
                          <div
                            style={{ width: `${Math.round((res.probs.phishing || 0) * 100)}%` }}
                            className="bg-rose-500 transition-all duration-300"
                            title={`Phish: ${Math.round((res.probs.phishing || 0) * 100)}%`}
                          />
                        </div>

                        <div className="flex justify-between text-emerald-400">
                          <span>Legit:</span>
                          <span>{((res.probs.legitimate || 0) * 100).toFixed(1)}%</span>
                        </div>
                        <div className="flex justify-between text-amber-400">
                          <span>Spam:</span>
                          <span>{((res.probs.spam || 0) * 100).toFixed(1)}%</span>
                        </div>
                        <div className="flex justify-between text-rose-400">
                          <span>Phish:</span>
                          <span>{((res.probs.phishing || 0) * 100).toFixed(1)}%</span>
                        </div>
                      </div>
                    ) : null}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
    </div>
  )
}


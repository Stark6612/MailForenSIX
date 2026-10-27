import React, { useState, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { toast } from 'react-hot-toast'
import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

export default function SecurityToolsModal({ isOpen, onClose, currentAnalysis }) {
  const [activeTab, setActiveTab] = useState('yara')
  const [yaraRules, setYaraRules] = useState([])
  const [loadingRules, setLoadingRules] = useState(false)
  const [scanningYara, setScanningYara] = useState(false)
  const [yaraResults, setYaraResults] = useState(null)
  const [customRule, setCustomRule] = useState('')

  // MISP / OpenCTI State
  const [mispUrl, setMispUrl] = useState('https://misp.cyberdefense.local')
  const [mispKey, setMispKey] = useState('sec_misp_auth_key_academic_demo')
  const [tlp, setTlp] = useState('AMBER')
  const [pushingMisp, setPushingMisp] = useState(false)

  // OSINT State
  const [osintKey, setOsintKey] = useState('')
  const [osintQuery, setOsintQuery] = useState(currentAnalysis?.relay_hops?.[0]?.ip || '185.220.101.45')
  const [osintResult, setOsintResult] = useState(null)
  const [checkingOsint, setCheckingOsint] = useState(false)

  // Fetch YARA rules on open
  useEffect(() => {
    if (isOpen) {
      setLoadingRules(true)
      axios.get(`${API_BASE}/tools/yara/rules`)
        .then(res => setYaraRules(res.data.rules || []))
        .catch(() => setYaraRules([]))
        .finally(() => setLoadingRules(false))
    }
  }, [isOpen])

  if (!isOpen) return null

  const handleYaraScan = async () => {
    setScanningYara(true)
    try {
      const emailText = `${currentAnalysis?.subject || ''} ${currentAnalysis?.lime_sentences?.map(s => s.text).join(' ') || ''}`
      const attNames = (currentAnalysis?.attachments || []).map(a => a.filename)

      const res = await axios.post(`${API_BASE}/tools/yara/scan`, {
        text: emailText || 'urgent verify your account wire transfer',
        attachment_names: attNames.length ? attNames : ['invoice_urgent.pdf.exe'],
        custom_rule: customRule || undefined,
      })
      setYaraResults(res.data)
      toast.success(`YARA Scan Complete: ${res.data.matched_count} rules matched!`)
    } catch (err) {
      toast.error('Failed to run YARA scan')
    } finally {
      setScanningYara(false)
    }
  }

  const handleMispPush = async () => {
    setPushingMisp(true)
    try {
      const res = await axios.post(`${API_BASE}/tools/misp/export`, {
        misp_url: mispUrl,
        api_key: mispKey,
        event_info: `MailForenSIX Forensic Triage: ${currentAnalysis?.subject || 'Campaign Incident'}`,
        tlp: tlp.toLowerCase(),
      })
      toast.success(res.data.message)
    } catch (err) {
      toast.error(err.response?.data?.detail || 'MISP dispatch error')
    } finally {
      setPushingMisp(false)
    }
  }

  const handleOsintCheck = async () => {
    setCheckingOsint(true)
    try {
      const res = await axios.post(`${API_BASE}/tools/osint/check`, {
        query_type: 'ip',
        query_value: osintQuery,
        api_key: osintKey || undefined,
      })
      setOsintResult(res.data)
      toast.success('OSINT Query Complete')
    } catch (err) {
      toast.error('OSINT lookup error')
    } finally {
      setCheckingOsint(false)
    }
  }

  return createPortal(
    <div
      className="fixed inset-0 z-[9999] bg-black/85 backdrop-blur-md overflow-y-auto p-4 sm:p-8 flex justify-center items-start sm:items-center"
      onClick={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="relative bg-[#0f172a] border border-indigo-500/50 rounded-xl w-full max-w-3xl shadow-2xl flex flex-col my-auto max-h-[85vh] overflow-hidden text-slate-200">
        
        {/* Header (Pinned) */}
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between bg-[#1e293b]/90 shrink-0">
          <div className="flex items-center gap-2.5">
            <span className="text-xl">🛠️</span>
            <div>
              <h2 className="text-sm sm:text-base font-bold text-slate-100 flex items-center gap-2">
                Security Tool Proficiency & Integrations Hub
              </h2>
              <p className="text-[11px] text-slate-400">Configure & operationalize industry CTI tools with MailForenSIX</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center text-sm font-bold transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Tab Navigation (Pinned) */}
        <div className="flex border-b border-slate-800 px-5 bg-[#090d16] shrink-0 overflow-x-auto gap-1">
          {[
            { id: 'yara', label: 'YARA Rule Scanner', icon: '🔍' },
            { id: 'misp', label: 'MISP / OpenCTI Sharing', icon: '🌐' },
            { id: 'osint', label: 'AbuseIPDB & OSINT', icon: '🛡️' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-3.5 py-2.5 text-xs font-semibold flex items-center gap-1.5 border-b-2 transition-all shrink-0 ${
                activeTab === tab.id
                  ? 'border-indigo-500 text-indigo-400 bg-indigo-500/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <span>{tab.icon}</span> {tab.label}
            </button>
          ))}
        </div>

        {/* Body Content (Independently Scrollable with min-h-0 flex-1) */}
        <div className="p-5 overflow-y-auto min-h-0 flex-1 space-y-4 text-xs">
          
          {/* TAB 1: YARA ENGINE */}
          {activeTab === 'yara' && (
            <div className="space-y-4">
              <div className="flex justify-between items-center bg-slate-800/40 p-3 rounded-lg border border-slate-700/60">
                <div>
                  <p className="font-semibold text-slate-200">Active YARA Rule Engine</p>
                  <p className="text-[11px] text-slate-400">Pre-compiled signatures scanning email lures and attachments</p>
                </div>
                <button
                  onClick={handleYaraScan}
                  disabled={scanningYara}
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded font-bold text-xs disabled:opacity-50 transition-colors shadow-glow"
                >
                  {scanningYara ? 'Scanning…' : '⚡ Run YARA Scan on Active Email'}
                </button>
              </div>

              {/* Rules List */}
              <div className="space-y-2">
                <p className="font-semibold text-slate-300 uppercase tracking-wider text-[10px]">Loaded Detection Signatures ({yaraRules.length})</p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {yaraRules.map(r => (
                    <div key={r.id} className="p-2.5 rounded bg-slate-950/60 border border-slate-800 space-y-1">
                      <div className="flex justify-between items-center">
                        <span className="font-bold text-indigo-300 font-mono text-[11px]">{r.name}</span>
                        <span className={`text-[9px] px-1.5 py-0.2 rounded font-bold ${
                          r.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        }`}>{r.severity}</span>
                      </div>
                      <p className="text-slate-400 text-[10px]">{r.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Scan Results */}
              {yaraResults && (
                <div className="p-3 bg-slate-950/90 rounded-lg border border-indigo-500/40 space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-slate-200">Inspection Scan Report</span>
                    <span className="text-indigo-400 font-mono font-bold">{yaraResults.matched_count} matches / {yaraResults.total_scanned_rules} rules</span>
                  </div>
                  {yaraResults.matches.length === 0 ? (
                    <p className="text-emerald-400 text-[11px]">✓ No malicious YARA patterns triggered.</p>
                  ) : (
                    yaraResults.matches.map((m, i) => (
                      <div key={i} className="p-2 bg-red-950/20 border border-red-500/30 rounded text-[11px] space-y-1">
                        <div className="flex justify-between">
                          <span className="font-bold text-red-400">{m.rule_name}</span>
                          <span className="text-[10px] text-red-300 uppercase">{m.severity}</span>
                        </div>
                        <p className="text-slate-300">{m.description}</p>
                        <p className="font-mono text-[10px] text-slate-400">Tokens: {m.matched_strings.join(', ')}</p>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          )}

          {/* TAB 2: MISP / OpenCTI */}
          {activeTab === 'misp' && (
            <div className="space-y-4">
              <p className="text-slate-300 leading-relaxed">
                Configure bidirectional synchronization with standard Cyber Threat Intelligence (CTI) platforms.
                Export formatted STIX 2.1 bundles directly to downstream SOC repositories.
              </p>

              <div className="space-y-3 bg-slate-950/60 p-4 rounded-lg border border-slate-800">
                <div>
                  <label className="block text-slate-400 mb-1 font-semibold text-[11px]">MISP / OpenCTI Instance URL</label>
                  <input
                    type="text"
                    value={mispUrl}
                    onChange={e => setMispUrl(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 font-mono text-xs focus:border-indigo-500 outline-none"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 font-semibold text-[11px]">API Authentication Key</label>
                  <input
                    type="password"
                    value={mispKey}
                    onChange={e => setMispKey(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 font-mono text-xs focus:border-indigo-500 outline-none"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 font-semibold text-[11px]">Traffic Light Protocol (TLP) Sharing Tag</label>
                  <select
                    value={tlp}
                    onChange={e => setTlp(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 text-xs focus:border-indigo-500 outline-none"
                  >
                    <option value="WHITE">TLP:WHITE (Unrestricted Public Sharing)</option>
                    <option value="GREEN">TLP:GREEN (Community & Partner Sharing)</option>
                    <option value="AMBER">TLP:AMBER (Restricted Organization Need-to-Know)</option>
                    <option value="RED">TLP:RED (Strictly Confidential / Named Recipients)</option>
                  </select>
                </div>

                <button
                  onClick={handleMispPush}
                  disabled={pushingMisp}
                  className="w-full mt-2 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded font-bold text-xs disabled:opacity-50 transition-colors"
                >
                  {pushingMisp ? 'Staging STIX Event…' : '🚀 Push STIX 2.1 Threat Event to MISP'}
                </button>
              </div>
            </div>
          )}

          {/* TAB 3: OSINT */}
          {activeTab === 'osint' && (
            <div className="space-y-4">
              <p className="text-slate-300 leading-relaxed">
                Connect external OSINT APIs (AbuseIPDB, VirusTotal, AlienVault OTX) for live reputation checks or operate in sovereign air-gapped mode.
              </p>

              <div className="space-y-3 bg-slate-950/60 p-4 rounded-lg border border-slate-800">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-400 mb-1 font-semibold text-[11px]">AbuseIPDB API Key (Optional)</label>
                    <input
                      type="password"
                      placeholder="Enter API key for live IP reputation"
                      value={osintKey}
                      onChange={e => setOsintKey(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 font-mono text-xs focus:border-indigo-500 outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1 font-semibold text-[11px]">Target IP or File Hash</label>
                    <input
                      type="text"
                      value={osintQuery}
                      onChange={e => setOsintQuery(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 font-mono text-xs focus:border-indigo-500 outline-none"
                    />
                  </div>
                </div>

                <button
                  onClick={handleOsintCheck}
                  disabled={checkingOsint}
                  className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded font-bold text-xs disabled:opacity-50 transition-colors"
                >
                  {checkingOsint ? 'Querying Threat Intelligence Feeds…' : '🔍 Execute Live OSINT Threat Check'}
                </button>
              </div>

              {/* OSINT Query Result */}
              {osintResult && (
                <div className="p-3 bg-slate-950/80 rounded border border-indigo-500/30 space-y-1.5">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-slate-200">OSINT Query Result</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                      osintResult.reputation === 'MALICIOUS' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    }`}>
                      {osintResult.reputation} ({osintResult.abuse_confidence})
                    </span>
                  </div>
                  <p className="text-slate-400 font-mono text-[10px]">Source: {osintResult.source}</p>
                  <p className="text-slate-300">Target Value: <span className="font-mono text-indigo-300">{osintResult.query_value}</span></p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/60 flex justify-end">
          <button onClick={onClose} className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded font-semibold text-xs transition-colors">
            Close
          </button>
        </div>
      </div>
    </div>,
    document.body
  )
}

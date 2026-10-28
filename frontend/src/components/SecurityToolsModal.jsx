import React, { useState, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { toast } from 'react-hot-toast'
import { fetchYaraRules, scanYara, pushMisp, checkOsint } from '../lib/api'

// Fallback rules in case API is loading or network is offline
const FALLBACK_RULES = [
  {
    id: "rule_phish_cred_01",
    name: "Email_Phishing_Credential_Harvest",
    severity: "HIGH",
    mitre_ttp: "T1566.002",
    description: "Matches credential harvesting lures, deceptive account verification, and re-authentication directives.",
    strings: ["verify your account", "login immediately", "password reset", "account suspended"],
    condition: "1 of ($strings*)",
  },
  {
    id: "rule_mal_attach_02",
    name: "Malicious_Script_Executable_Attachment",
    severity: "CRITICAL",
    mitre_ttp: "T1204.002",
    description: "Detects executable and script payloads disguised as attachments.",
    strings: [".exe", ".scr", ".vbs", ".hta", ".iso", ".ps1"],
    condition: "1 of ($strings*) in attachment_names",
  },
  {
    id: "rule_bec_wire_03",
    name: "Executive_BEC_Wire_Fraud",
    severity: "CRITICAL",
    mitre_ttp: "T1566.001",
    description: "Flags unauthorized invoice alterations, payment diversion, and urgent wire transfer directives.",
    strings: ["wire transfer", "bank routing", "urgent payment", "invoice attached"],
    condition: "1 of ($strings*)",
  },
  {
    id: "rule_macro_dropper_04",
    name: "Suspicious_Office_Macro_Dropper",
    severity: "HIGH",
    mitre_ttp: "T1566.001",
    description: "Flags macro-enabled Office containers commonly used to deliver secondary trojan payloads.",
    strings: [".docm", ".xlsm", "vbaproject.bin", "autoopen"],
    condition: "1 of ($strings*)",
  },
]

export default function SecurityToolsModal({ isOpen, onClose, currentAnalysis }) {
  const [activeTab, setActiveTab] = useState('yara')
  const [yaraRules, setYaraRules] = useState(FALLBACK_RULES)
  const [loadingRules, setLoadingRules] = useState(false)
  const [scanningYara, setScanningYara] = useState(false)
  const [yaraResults, setYaraResults] = useState(null)
  const [customRule, setCustomRule] = useState('')
  const [customText, setCustomText] = useState('')
  const [customAttachments, setCustomAttachments] = useState('')
  const [useCustomInput, setUseCustomInput] = useState(false)

  // MISP / OpenCTI State
  const [mispUrl, setMispUrl] = useState('https://misp.cyberdefense.local')
  const [mispKey, setMispKey] = useState('sec_misp_auth_key_academic_demo')
  const [tlp, setTlp] = useState('AMBER')
  const [pushingMisp, setPushingMisp] = useState(false)
  const [mispResult, setMispResult] = useState(null)

  // OSINT State
  const [osintKey, setOsintKey] = useState('')
  const [osintQuery, setOsintQuery] = useState('185.220.101.45')
  const [osintResult, setOsintResult] = useState(null)
  const [checkingOsint, setCheckingOsint] = useState(false)

  // Extract analysis attributes
  const analysisIp = currentAnalysis?.relay_hops?.[0]?.ip
  const analysisDomain = currentAnalysis?.domain_intel?.domain
  const analysisHash = currentAnalysis?.forensic?.email_sha256 || currentAnalysis?.attachments?.[0]?.sha256

  // Sync state when modal opens or currentAnalysis changes
  useEffect(() => {
    if (isOpen) {
      if (analysisIp) {
        setOsintQuery(analysisIp)
      } else if (analysisDomain) {
        setOsintQuery(analysisDomain)
      }

      setLoadingRules(true)
      fetchYaraRules()
        .then(res => {
          if (res?.rules?.length) setYaraRules(res.rules)
        })
        .catch(() => {
          setYaraRules(FALLBACK_RULES)
        })
        .finally(() => setLoadingRules(false))
    }
  }, [isOpen, analysisIp, analysisDomain])

  if (!isOpen) return null

  // ── YARA Scan Execution ──────────────────────────────────────────────────
  const handleYaraScan = async () => {
    setScanningYara(true)
    try {
      let emailText = ''
      let attNames = []

      if (useCustomInput) {
        emailText = customText.trim()
        attNames = customAttachments.split(',').map(s => s.trim()).filter(Boolean)
      } else {
        const textParts = [
          currentAnalysis?.subject,
          ...(currentAnalysis?.lime_sentences?.map(s => s.text) || []),
          currentAnalysis?.domain_intel?.domain,
          ...(currentAnalysis?.warnings || [])
        ].filter(Boolean)

        emailText = textParts.join(' ').trim()
        attNames = (currentAnalysis?.attachments || []).map(a => a.filename).filter(Boolean)

        // If no email has been loaded yet, provide a realistic threat sample
        if (!emailText && attNames.length === 0) {
          emailText = "URGENT: Executive wire transfer request. Please verify your banking credentials and authorize payment immediately. Updated vendor invoice attached."
          attNames = ['urgent_invoice_payment.pdf.exe', 'remittance_macro.docm']
          toast('Using sample phishing lure for evaluation demonstration.', { icon: 'ℹ️' })
        }
      }

      const res = await scanYara({
        text: emailText || 'urgent account verification wire transfer invoice attached',
        attachment_names: attNames.length ? attNames : ['invoice_urgent.exe'],
        custom_rule: customRule.trim() || undefined,
      })

      setYaraResults(res)
      if (res.matched_count > 0) {
        toast.success(`YARA Scan Complete: ${res.matched_count} rules triggered!`)
      } else {
        toast('YARA scan complete: No malicious patterns triggered.', { icon: '🛡️' })
      }
    } catch (err) {
      console.error(err)
      toast.error(err?.response?.data?.detail || err.message || 'Failed to run YARA scan')
    } finally {
      setScanningYara(false)
    }
  }

  // ── MISP Dispatch Execution ──────────────────────────────────────────────
  const handleMispPush = async () => {
    setPushingMisp(true)
    try {
      const subject = currentAnalysis?.subject || 'Campaign Incident Triage'
      const res = await pushMisp({
        misp_url: mispUrl.trim(),
        api_key: mispKey.trim(),
        event_info: `MailForenSIX CTI Forensic Triage: ${subject}`,
        tlp: tlp.toLowerCase(),
      })
      setMispResult(res.misp_event)
      toast.success(res.message || 'STIX 2.1 Threat Event successfully staged!')
    } catch (err) {
      console.error(err)
      toast.error(err.response?.data?.detail || err.message || 'MISP dispatch error')
    } finally {
      setPushingMisp(false)
    }
  }

  // ── OSINT Lookup Execution ───────────────────────────────────────────────
  const handleOsintCheck = async (queryVal) => {
    const val = (queryVal || osintQuery).trim()
    if (!val) {
      toast.error('Enter an IP, domain, or hash to query.')
      return
    }
    setCheckingOsint(true)
    try {
      const isIp = /^[0-9.]+$/.test(val)
      const res = await checkOsint({
        query_type: isIp ? 'ip' : (val.length === 64 ? 'hash' : 'domain'),
        query_value: val,
        api_key: osintKey.trim() || undefined,
      })
      setOsintResult(res)
      toast.success(`OSINT Query: ${res.reputation}`)
    } catch (err) {
      console.error(err)
      toast.error(err.response?.data?.detail || err.message || 'OSINT lookup error')
    } finally {
      setCheckingOsint(false)
    }
  }

  // Helper to copy text to clipboard
  const copyToClipboard = (text, label) => {
    navigator.clipboard.writeText(text)
    toast.success(`${label} copied to clipboard!`)
  }

  return createPortal(
    <div
      className="fixed inset-0 z-[9999] bg-black/85 backdrop-blur-md overflow-y-auto p-4 sm:p-6 flex justify-center items-start sm:items-center"
      onClick={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="relative bg-[#0f172a] border border-indigo-500/50 rounded-xl w-full max-w-3xl shadow-2xl flex flex-col my-auto max-h-[90vh] overflow-hidden text-slate-200">
        
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between bg-[#1e293b]/95 shrink-0">
          <div className="flex items-center gap-2.5">
            <span className="text-xl">🛠️</span>
            <div>
              <h2 className="text-sm sm:text-base font-bold text-slate-100 flex items-center gap-2">
                Security Tool Proficiency & Integrations Hub
              </h2>
              <p className="text-[11px] text-slate-400">SOC Operationalization: YARA Signatures, MISP / OpenCTI STIX Sharing & OSINT Lookups</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center text-sm font-bold transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Tab Navigation */}
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

        {/* Body Content */}
        <div className="p-5 overflow-y-auto min-h-0 flex-1 space-y-4 text-xs">
          
          {/* TAB 1: YARA ENGINE */}
          {activeTab === 'yara' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 bg-slate-800/40 p-3.5 rounded-lg border border-slate-700/60">
                <div>
                  <p className="font-semibold text-slate-200">Active YARA Signature Inspection Engine</p>
                  <p className="text-[11px] text-slate-400">
                    {currentAnalysis
                      ? `Analyzing active email (${(currentAnalysis.attachments || []).length} attachments, Subject: "${(currentAnalysis.subject || 'No subject').slice(0, 30)}…")`
                      : 'No email loaded — demo payload with BEC & executable triggers ready'}
                  </p>
                </div>
                <button
                  onClick={handleYaraScan}
                  disabled={scanningYara}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded font-bold text-xs disabled:opacity-50 transition-colors shadow-glow shrink-0 flex items-center gap-1.5"
                >
                  {scanningYara ? 'Scanning…' : '⚡ Execute YARA Scan'}
                </button>
              </div>

              {/* Mode Toggle: Current Email vs Custom Payload */}
              <div className="flex items-center justify-between text-[11px] px-1 text-slate-300">
                <span className="font-semibold text-slate-400 uppercase tracking-wider text-[10px]">Input Source</span>
                <button
                  onClick={() => setUseCustomInput(!useCustomInput)}
                  className="text-indigo-400 hover:text-indigo-300 underline font-medium"
                >
                  {useCustomInput ? 'Switch to Active Email Data' : 'Custom Text / Attachment Editor'}
                </button>
              </div>

              {/* Custom Input Fields (if active) */}
              {useCustomInput && (
                <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800 space-y-2">
                  <div>
                    <label className="block text-slate-400 font-semibold text-[10px] uppercase mb-1">Email Body / Subject to Scan</label>
                    <textarea
                      rows={2}
                      value={customText}
                      onChange={e => setCustomText(e.target.value)}
                      placeholder="Paste suspicious text or phishing email lure here..."
                      className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-slate-200 font-mono text-xs focus:border-indigo-500 outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 font-semibold text-[10px] uppercase mb-1">Attachment Filenames (comma-separated)</label>
                    <input
                      type="text"
                      value={customAttachments}
                      onChange={e => setCustomAttachments(e.target.value)}
                      placeholder="e.g. invoice_march.pdf.exe, macro_payload.docm"
                      className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:border-indigo-500 outline-none"
                    />
                  </div>
                </div>
              )}

              {/* Custom YARA Rule Editor */}
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800 space-y-2">
                <div className="flex justify-between items-center">
                  <label className="text-slate-300 font-semibold text-[11px] flex items-center gap-1.5">
                    <span>✏️</span> Custom Analyst Rule (Optional)
                  </label>
                  <button
                    onClick={() => setCustomRule('rule Executive_Urgency_Check {\n    strings: "confidential request", "urgent payment"\n    condition: any of them\n}')}
                    className="text-[10px] text-indigo-400 hover:text-indigo-300 underline"
                  >
                    Insert Example
                  </button>
                </div>
                <textarea
                  rows={2}
                  value={customRule}
                  onChange={e => setCustomRule(e.target.value)}
                  placeholder='rule Custom_Lure { strings: "wire transfer", "login immediately" condition: any of them }'
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-slate-200 font-mono text-xs focus:border-indigo-500 outline-none"
                />
              </div>

              {/* Scan Results Display */}
              {yaraResults && (
                <div className="p-3.5 bg-slate-950/95 rounded-lg border border-indigo-500/40 space-y-2.5">
                  <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                    <span className="font-bold text-slate-200 text-xs">YARA Inspection Report</span>
                    <span className="text-indigo-400 font-mono font-bold text-xs">
                      {yaraResults.matched_count} matches / {yaraResults.total_scanned_rules} rules
                    </span>
                  </div>
                  {yaraResults.matches.length === 0 ? (
                    <p className="text-emerald-400 text-[11px] py-1">✓ No malicious YARA patterns or payload signatures triggered.</p>
                  ) : (
                    <div className="space-y-2">
                      {yaraResults.matches.map((m, i) => (
                        <div key={i} className="p-2.5 bg-red-950/20 border border-red-500/30 rounded text-[11px] space-y-1">
                          <div className="flex justify-between items-center">
                            <span className="font-bold text-red-400 font-mono">{m.rule_name}</span>
                            <div className="flex items-center gap-1.5">
                              {m.mitre_ttp && (
                                <span className="bg-indigo-950 text-indigo-300 border border-indigo-700/50 px-1.5 py-0.5 rounded text-[9px] font-mono">
                                  {m.mitre_ttp}
                                </span>
                              )}
                              <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${
                                m.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                              }`}>{m.severity}</span>
                            </div>
                          </div>
                          <p className="text-slate-300">{m.description}</p>
                          <p className="font-mono text-[10px] text-slate-400">
                            Matched Tokens: <span className="text-amber-300 font-semibold">{m.matched_strings.join(', ')}</span>
                          </p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Loaded Rules List */}
              <div className="space-y-2 pt-1">
                <p className="font-semibold text-slate-400 uppercase tracking-wider text-[10px]">
                  Loaded Platform Signatures ({yaraRules.length})
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {yaraRules.map(r => (
                    <div key={r.id} className="p-2.5 rounded bg-slate-950/60 border border-slate-800 space-y-1">
                      <div className="flex justify-between items-center">
                        <span className="font-bold text-indigo-300 font-mono text-[11px] truncate max-w-[200px]" title={r.name}>{r.name}</span>
                        <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${
                          r.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        }`}>{r.severity}</span>
                      </div>
                      <p className="text-slate-400 text-[10px] leading-tight">{r.description}</p>
                    </div>
                  ))}
                </div>
              </div>
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
                  className="w-full mt-2 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded font-bold text-xs disabled:opacity-50 transition-colors flex items-center justify-center gap-2"
                >
                  {pushingMisp ? 'Staging STIX 2.1 Event…' : '🚀 Push STIX 2.1 Threat Event to MISP'}
                </button>
              </div>

              {/* Staged MISP Event Result */}
              {mispResult && (
                <div className="p-4 bg-slate-950/90 rounded-lg border border-emerald-500/40 space-y-3">
                  <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                    <span className="font-bold text-emerald-400 flex items-center gap-1.5">
                      <span>✓</span> Incident Staged for MISP Sync
                    </span>
                    <span className={`text-[9px] px-2 py-0.5 rounded font-bold uppercase ${
                      mispResult.tlp === 'RED' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                      mispResult.tlp === 'AMBER' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' :
                      'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                    }`}>
                      TLP:{mispResult.tlp}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div>
                      <span className="text-slate-400 block">Event UUID:</span>
                      <code className="text-slate-200 font-mono text-[10px]">{mispResult.uuid}</code>
                    </div>
                    <div>
                      <span className="text-slate-400 block">Threat Level:</span>
                      <span className="text-red-400 font-semibold">{mispResult.threat_level}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block">Sharing Group:</span>
                      <span className="text-slate-200">{mispResult.sharing_group}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block">IOC Attributes Staged:</span>
                      <span className="text-indigo-300 font-bold">{mispResult.attribute_count}</span>
                    </div>
                  </div>

                  {mispResult.stix_bundle && (
                    <div className="pt-2 border-t border-slate-800 flex gap-2">
                      <button
                        onClick={() => copyToClipboard(JSON.stringify(mispResult.stix_bundle, null, 2), 'STIX 2.1 JSON')}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px] font-semibold transition-colors"
                      >
                        📋 Copy STIX JSON
                      </button>
                      <button
                        onClick={() => {
                          const blob = new Blob([JSON.stringify(mispResult.stix_bundle, null, 2)], { type: 'application/json' })
                          const url = URL.createObjectURL(blob)
                          const a = document.createElement('a')
                          a.href = url
                          a.download = `stix_bundle_${mispResult.uuid.slice(0, 8)}.json`
                          a.click()
                          URL.revokeObjectURL(url)
                          toast.success('STIX 2.1 bundle downloaded!')
                        }}
                        className="px-2.5 py-1 bg-emerald-700 hover:bg-emerald-600 text-white rounded text-[11px] font-semibold transition-colors"
                      >
                        💾 Download STIX Bundle
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* TAB 3: OSINT */}
          {activeTab === 'osint' && (
            <div className="space-y-4">
              <p className="text-slate-300 leading-relaxed">
                Cross-reference suspicious indicators (Relay IPs, domains, attachment hashes) against AbuseIPDB, VirusTotal, and URLhaus threat repositories.
              </p>

              {/* Quick-fill pills from active email */}
              <div className="space-y-1.5">
                <span className="text-slate-400 font-semibold text-[10px] uppercase">Quick-Query Indicators:</span>
                <div className="flex flex-wrap gap-1.5">
                  {analysisIp && (
                    <button
                      onClick={() => { setOsintQuery(analysisIp); handleOsintCheck(analysisIp) }}
                      className="px-2 py-0.5 rounded bg-indigo-950/80 border border-indigo-600/40 text-indigo-300 hover:bg-indigo-900 text-[10px] font-mono"
                    >
                      IP: {analysisIp}
                    </button>
                  )}
                  {analysisDomain && (
                    <button
                      onClick={() => { setOsintQuery(analysisDomain); handleOsintCheck(analysisDomain) }}
                      className="px-2 py-0.5 rounded bg-indigo-950/80 border border-indigo-600/40 text-indigo-300 hover:bg-indigo-900 text-[10px] font-mono"
                    >
                      Domain: {analysisDomain}
                    </button>
                  )}
                  {analysisHash && (
                    <button
                      onClick={() => { setOsintQuery(analysisHash); handleOsintCheck(analysisHash) }}
                      className="px-2 py-0.5 rounded bg-indigo-950/80 border border-indigo-600/40 text-indigo-300 hover:bg-indigo-900 text-[10px] font-mono"
                    >
                      Hash: {analysisHash.slice(0, 10)}…
                    </button>
                  )}
                  <button
                    onClick={() => { setOsintQuery('185.220.101.45'); handleOsintCheck('185.220.101.45') }}
                    className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 text-[10px] font-mono"
                  >
                    Sample TOR IP (185.220.101.45)
                  </button>
                  <button
                    onClick={() => { setOsintQuery('02teste.cc'); handleOsintCheck('02teste.cc') }}
                    className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 text-[10px] font-mono"
                  >
                    Sample URLhaus C2 (02teste.cc)
                  </button>
                </div>
              </div>

              <div className="space-y-3 bg-slate-950/60 p-4 rounded-lg border border-slate-800">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-400 mb-1 font-semibold text-[11px]">AbuseIPDB / VT API Key (Optional)</label>
                    <input
                      type="password"
                      placeholder="Enter API key for live external query"
                      value={osintKey}
                      onChange={e => setOsintKey(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 font-mono text-xs focus:border-indigo-500 outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1 font-semibold text-[11px]">Target IP, Domain or Hash</label>
                    <input
                      type="text"
                      value={osintQuery}
                      onChange={e => setOsintQuery(e.target.value)}
                      placeholder="e.g. 185.220.101.45 or malicious-domain.com"
                      className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 font-mono text-xs focus:border-indigo-500 outline-none"
                    />
                  </div>
                </div>

                <button
                  onClick={() => handleOsintCheck(osintQuery)}
                  disabled={checkingOsint}
                  className="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded font-bold text-xs disabled:opacity-50 transition-colors flex items-center justify-center gap-2"
                >
                  {checkingOsint ? 'Querying Threat Intelligence Feeds…' : '🔍 Execute Threat Intelligence Lookup'}
                </button>
              </div>

              {/* OSINT Query Result */}
              {osintResult && (
                <div className="p-4 bg-slate-950/90 rounded-lg border border-indigo-500/30 space-y-3">
                  <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                    <div>
                      <span className="font-bold text-slate-200">OSINT Reputation Report</span>
                      <span className="text-slate-400 font-mono text-[11px] block mt-0.5">{osintResult.query_value}</span>
                    </div>
                    <span className={`text-[10px] px-2.5 py-0.5 rounded font-bold border uppercase tracking-wider ${
                      osintResult.reputation === 'MALICIOUS'
                        ? 'bg-red-500/20 text-red-400 border-red-500/40 animate-pulse'
                        : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                    }`}>
                      {osintResult.reputation}
                    </span>
                  </div>

                  {/* Threat Score Bar */}
                  <div className="space-y-1">
                    <div className="flex justify-between text-[11px]">
                      <span className="text-slate-400 font-semibold">Abuse / Threat Score</span>
                      <span className={`font-bold ${osintResult.threat_score >= 70 ? 'text-red-400' : 'text-emerald-400'}`}>
                        {osintResult.threat_score} / 100 ({osintResult.abuse_confidence})
                      </span>
                    </div>
                    <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          osintResult.threat_score >= 70 ? 'bg-red-500' : (osintResult.threat_score >= 40 ? 'bg-amber-500' : 'bg-emerald-500')
                        }`}
                        style={{ width: `${osintResult.threat_score}%` }}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
                    <div>
                      <span className="text-slate-400 block">Intelligence Source:</span>
                      <span className="text-slate-200 font-medium">{osintResult.source}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block">Last Reported Incident:</span>
                      <span className="text-slate-200">{osintResult.last_reported}</span>
                    </div>
                  </div>

                  {osintResult.tags && osintResult.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 pt-1 border-t border-slate-800">
                      {osintResult.tags.map((t, i) => (
                        <span key={i} className="text-[10px] px-2 py-0.5 bg-indigo-950/70 border border-indigo-700/40 text-indigo-300 rounded font-medium">
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-[#090d16] flex justify-end">
          <button onClick={onClose} className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded font-semibold text-xs transition-colors">
            Close
          </button>
        </div>
      </div>
    </div>,
    document.body
  )
}

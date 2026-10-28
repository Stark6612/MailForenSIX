/**
 * UploadZone — drag-and-drop .eml upload + raw header paste + Analyze button
 * Matches UX_Dev.md: "top bar always visible, upload, toggle, analyze"
 */

import { useRef, useState, useCallback } from 'react'

const SAMPLE_PHISHING = `Received: from mail-transit.gateway-relay.net (mail-transit.gateway-relay.net [203.0.113.5])
    by mx.enterprise-target.com with ESMTPS id 4V8xY29L
    for <victim@enterprise.com>; Wed, 28 Oct 2026 10:00:00 +0000
Received: from mail.secure-corp-verify.com (mail.secure-corp-verify.com [185.234.218.22])
    by mail-transit.gateway-relay.net with ESMTP id 9B12cA99
    for <victim@enterprise.com>; Wed, 28 Oct 2026 09:58:30 +0000
Authentication-Results: mx.enterprise-target.com;
    spf=fail (sender IP 185.234.218.22 not authorized);
    dkim=fail header.i=@secure-corp-verify.com;
    dmarc=fail (p=reject sp=reject) header.from=secure-corp-verify.com
From: Mail Security Team <alerts@secure-corp-verify.com>
To: victim@enterprise.com
Subject: URGENT: Mailbox Session Expired
Date: Wed, 28 Oct 2026 10:00:00 +0000
Message-ID: <threat-test-82934@secure-corp-verify.com>
X-Campaign-ASN: AS197695
X-Campaign-ISP: Reg.ru LLC

Dear user, your enterprise mailbox session has expired and incoming emails are on pending status.
Action required: Please click here immediately to verify your identity and confirm your account login:
http://mail-security-verification.org/login.
Failure to confirm within 24 hours will lead to permanent mailbox deactivation.`

const SAMPLE_BENIGN = `Received: from mail-sor-f68.google.com (mail-sor-f68.google.com [209.85.218.68])
    by mx.enterprise-target.com with ESMTPS id 8K21aZ10
    for <engineer@internal-corp.com>; Wed, 28 Oct 2026 10:02:00 +0000
Received: from outbound.internal-corp.com (outbound.internal-corp.com [203.122.2.197])
    by mail-sor-f68.google.com with ESMTP id 5X99vA12
    for <engineer@internal-corp.com>; Wed, 28 Oct 2026 10:01:15 +0000
Authentication-Results: mx.enterprise-target.com;
    spf=pass smtp.mailfrom=internal-corp.com;
    dkim=pass header.d=internal-corp.com;
    dmarc=pass header.from=internal-corp.com
From: Project Lead <lead@internal-corp.com>
To: engineer@internal-corp.com
Subject: Sprint Deliverables & Review Meeting
Date: Wed, 28 Oct 2026 10:00:00 +0000
Message-ID: <legit-test-10293@internal-corp.com>

Hi team, please find attached the quarterly project alignment summary and sprint deliverables review.
Let me know if you have any questions before Friday's standup meeting.`

export default function UploadZone({
  emlFile, rawText,
  onFileChange, onTextChange,
  onAnalyze, isLoading, onReset,
  selectedModel = 'lr',
  onModelChange = () => {},
}) {
  const inputRef = useRef(null)
  const [dragging, setDragging] = useState(false)
  const [showPaste, setShowPaste] = useState(false)

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files?.[0]
    if (file) {
      onFileChange(file)
      onTextChange('')
    }
  }, [onFileChange, onTextChange])

  const handleFile = (e) => {
    const file = e.target.files?.[0]
    if (file) {
      onFileChange(file)
      onTextChange('')
    }
  }

  const handlePaste = (e) => {
    onTextChange(e.target.value)
    onFileChange(null)
  }

  const handleClear = () => {
    onFileChange(null)
    onTextChange('')
    onReset()
    if (inputRef.current) inputRef.current.value = ''
  }

  const hasInput = !!emlFile || !!rawText.trim()

  return (
    <div className="mt-4 space-y-3">

      {/* Drop zone */}
      <div
        id="upload-drop-zone"
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => !emlFile && inputRef.current?.click()}
        className={`relative flex flex-col items-center justify-center gap-2
          border-2 border-dashed rounded-panel p-6 cursor-pointer
          transition-all duration-200 select-none backdrop-blur-md
          ${dragging
            ? 'border-mfx-accent bg-mfx-accent/10 shadow-glow'
            : emlFile
              ? 'border-mfx-safe bg-mfx-safe/5'
              : 'border-white/[0.08] bg-mfx-surface/75 hover:border-mfx-accent/50 hover:bg-mfx-surface/90'
          }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".eml,.msg"
          className="hidden"
          onChange={handleFile}
          id="eml-file-input"
        />

        {emlFile ? (
          <div className="flex items-center gap-3">
            <span className="text-2xl">📎</span>
            <div>
              <p className="font-semibold text-mfx-text text-sm">{emlFile.name}</p>
              <p className="text-sm text-mfx-muted">{(emlFile.size / 1024).toFixed(1)} KB</p>
            </div>
          </div>
        ) : (
          <>
            <span className="text-4xl">{dragging ? '📥' : '📂'}</span>
            <p className="text-base font-semibold text-mfx-text">
              {dragging ? 'Release to upload' : 'Drop your .eml file here'}
            </p>
            <p className="text-sm text-mfx-muted">or click to browse · max 10 MB</p>
          </>
        )}
      </div>

      {/* Raw paste toggle */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => setShowPaste(p => !p)}
          className="text-sm text-mfx-muted hover:text-mfx-accent transition-colors"
          id="toggle-paste-btn"
        >
          {showPaste ? '▾ Hide paste area' : '▸ Or paste raw email source'}
        </button>
        {hasInput && (
          <button
            onClick={handleClear}
            className="text-sm text-mfx-muted hover:text-mfx-critical transition-colors ml-auto"
            id="clear-input-btn"
          >
            ✕ Clear
          </button>
        )}
      </div>

      {showPaste && (
        <textarea
          id="raw-headers-input"
          rows={6}
          value={rawText}
          onChange={handlePaste}
          placeholder="Paste full email source (headers + body)…"
          className="w-full bg-mfx-surface border border-mfx-border rounded-panel
            px-3 py-2 text-sm font-mono text-mfx-text placeholder-mfx-muted
            resize-y focus:outline-none focus:border-mfx-accent transition-colors"
        />
      )}

      {/* Quick sample loading buttons */}
      <div className="flex items-center gap-2 flex-wrap text-xs">
        <span className="text-mfx-muted font-medium">Quick Test:</span>
        <button
          type="button"
          onClick={() => { onFileChange(null); onTextChange(SAMPLE_PHISHING) }}
          className="px-2.5 py-1 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 hover:bg-rose-500/20 transition-all font-mono"
        >
          🚨 Load Phishing Alert Lure
        </button>
        <button
          type="button"
          onClick={() => { onFileChange(null); onTextChange(SAMPLE_BENIGN) }}
          className="px-2.5 py-1 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/20 transition-all font-mono"
        >
          ✅ Load Benign Corporate Memo
        </button>
      </div>

      {/* Analyze button & AI Model Selector */}
      <div className="flex items-center gap-3 flex-wrap pt-1">
        <button
          id="analyze-btn"
          onClick={onAnalyze}
          disabled={isLoading || !hasInput}
          className={`btn-primary disabled:opacity-40 disabled:cursor-not-allowed
            ${isLoading ? 'animate-pulse' : ''}`}
        >
          {isLoading ? (
            <>
              <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Analyzing…
            </>
          ) : (
            <> ▶ Analyze <span className="opacity-50 text-xs ml-1">Ctrl+Enter</span> </>
          )}
        </button>

        {/* Dynamic Model Selector */}
        <div className="flex items-center gap-2 bg-mfx-surface/90 border border-white/[0.08] px-3 py-1.5 rounded-lg text-xs">
          <span className="text-mfx-muted font-semibold flex items-center gap-1">
            <span>🧠</span> Model:
          </span>
          <select
            value={selectedModel}
            onChange={(e) => onModelChange(e.target.value)}
            disabled={isLoading}
            className="bg-transparent text-indigo-400 font-semibold focus:outline-none cursor-pointer"
          >
            <option value="lr" className="bg-slate-900 text-white">Logistic Regression (L2 — 93.3% F1, 0.2µs)</option>
            <option value="svm" className="bg-slate-900 text-white">Linear SVM (Platt Calibrated — 93.3% F1)</option>
            <option value="xgb" className="bg-slate-900 text-white">HistGradientBoosting (Ensemble — 91.2% F1)</option>
            <option value="nb" className="bg-slate-900 text-white">Multinomial Naive Bayes (Laplace — 87.6% F1)</option>
            <option value="dt" className="bg-slate-900 text-white">Decision Tree (CART Gini — 83.6% F1)</option>
          </select>
        </div>

        {hasInput && !isLoading && (
          <span className="text-sm text-mfx-muted">
            {emlFile ? `${emlFile.name}` : `${rawText.trim().split('\n').length} lines ready`}
          </span>
        )}
      </div>
    </div>
  )
}

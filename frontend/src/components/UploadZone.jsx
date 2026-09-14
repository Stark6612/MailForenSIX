/**
 * UploadZone — drag-and-drop .eml upload + raw header paste + Analyze button
 * Matches UX_Dev.md: "top bar always visible, upload, toggle, analyze"
 */

import { useRef, useState, useCallback } from 'react'

export default function UploadZone({
  emlFile, rawText,
  onFileChange, onTextChange,
  onAnalyze, isLoading, onReset,
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
          transition-all duration-200 select-none
          ${dragging
            ? 'border-mfx-accent bg-mfx-accent/10 shadow-glow'
            : emlFile
              ? 'border-mfx-safe bg-mfx-safe/5'
              : 'border-mfx-border bg-mfx-surface hover:border-mfx-accent/60'
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
              <p className="text-xs text-mfx-muted">{(emlFile.size / 1024).toFixed(1)} KB</p>
            </div>
          </div>
        ) : (
          <>
            <span className="text-3xl">{dragging ? '📥' : '📂'}</span>
            <p className="text-sm font-medium text-mfx-text">
              {dragging ? 'Release to upload' : 'Drop your .eml file here'}
            </p>
            <p className="text-xs text-mfx-muted">or click to browse · max 10 MB</p>
          </>
        )}
      </div>

      {/* Raw paste toggle */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => setShowPaste(p => !p)}
          className="text-xs text-mfx-muted hover:text-mfx-accent transition-colors"
          id="toggle-paste-btn"
        >
          {showPaste ? '▾ Hide paste area' : '▸ Or paste raw email source'}
        </button>
        {hasInput && (
          <button
            onClick={handleClear}
            className="text-xs text-mfx-muted hover:text-mfx-critical transition-colors ml-auto"
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

      {/* Analyze button */}
      <div className="flex items-center gap-3">
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

        {hasInput && !isLoading && (
          <span className="text-xs text-mfx-muted">
            {emlFile ? `${emlFile.name}` : `${rawText.trim().split('\n').length} lines pasted`}
          </span>
        )}
      </div>
    </div>
  )
}

/** ErrorBanner — inline error display with RFC-style code and dismiss */

export default function ErrorBanner({ message, onDismiss }) {
  return (
    <div
      role="alert"
      className="mt-4 panel border-mfx-critical/50 bg-mfx-critical/5 animate-slide-up flex items-start gap-3"
    >
      <span className="text-mfx-critical text-xl mt-0.5">✕</span>
      <div className="flex-1">
        <p className="text-sm font-semibold text-mfx-critical">Analysis Failed</p>
        <p className="text-sm text-mfx-muted mt-0.5 font-mono">{message}</p>
      </div>
      <button
        onClick={onDismiss}
        className="text-sm text-mfx-muted hover:text-mfx-critical transition-colors"
        id="error-dismiss-btn"
      >
        Dismiss
      </button>
    </div>
  )
}

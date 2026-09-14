/**
 * ErrorBoundary.jsx — Class-based React error boundary.
 * Wraps the panel grid so a render crash shows a helpful message
 * instead of a blank screen.
 */

import { Component } from 'react'

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, info) {
    console.error('[ErrorBoundary] Panel crash:', error, info.componentStack)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="mt-6 p-6 rounded-xl border border-mfx-critical/40 bg-mfx-critical/5 text-center space-y-3">
          <div className="text-3xl">⚠️</div>
          <p className="text-mfx-critical font-semibold text-sm">
            A panel crashed during rendering
          </p>
          <p className="text-mfx-muted text-xs font-mono break-all px-4">
            {this.state.error?.message ?? 'Unknown render error'}
          </p>
          <button
            onClick={() => {
              this.setState({ hasError: false, error: null })
              this.props.onReset?.()
            }}
            className="btn-ghost text-xs"
          >
            🔄 Reset &amp; Try Again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

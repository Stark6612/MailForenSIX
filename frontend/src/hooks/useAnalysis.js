/**
 * useAnalysis.js — Custom hook for managing email analysis state
 * Phases 1–4 will fill in the real data; Phase 0 just wires the loading states.
 */

import { useState, useCallback } from 'react'
import { analyzeEmail } from '../lib/api'

export const STATUS = {
  IDLE:     'idle',
  LOADING:  'loading',
  SUCCESS:  'success',
  ERROR:    'error',
}

export function useAnalysis() {
  const [status, setStatus]   = useState(STATUS.IDLE)
  const [result, setResult]   = useState(null)
  const [error,  setError]    = useState(null)

  /**
   * Pipeline stage labels — shown in the skeleton loader progress bar.
   * Each engine fires sequentially in the UI even though the backend
   * runs them with asyncio.gather (all ~parallel).
   */
  const [stage, setStage] = useState('')

  const run = useCallback(async (emlFile, rawText, model = 'lr') => {
    setStatus(STATUS.LOADING)
    setResult(null)
    setError(null)

    const stages = ['Parsing', 'Auth Validation', `AI Inference (${model.toUpperCase()})`, 'Geo Tracing', 'Domain Intel', 'Risk Engine']
    let i = 0
    const stageTimer = setInterval(() => {
      setStage(stages[i % stages.length])
      i++
    }, 800)

    try {
      const data = await analyzeEmail(emlFile, rawText, model)
      setResult(data)
      setStatus(STATUS.SUCCESS)
    } catch (err) {
      const msg = err?.response?.data?.detail ?? err.message ?? 'Unknown error'
      setError(msg)
      setStatus(STATUS.ERROR)
    } finally {
      clearInterval(stageTimer)
      setStage('')
    }
  }, [])

  const reset = useCallback(() => {
    setStatus(STATUS.IDLE)
    setResult(null)
    setError(null)
    setStage('')
  }, [])

  return { status, result, error, stage, run, reset }
}

/**
 * DecryptedText — ReactBits-style matrix scramble reveal
 * Triggers on mount (view). Characters randomise then resolve one by one.
 * Zero external deps — pure React.
 */
import { useEffect, useRef, useState } from 'react'

const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&!'

export default function DecryptedText({
  text = '',
  speed = 40,
  maxIterations = 12,
  className = '',
  onComplete,
}) {
  const [displayText, setDisplayText] = useState(text)
  const iterRef = useRef(0)
  const timerRef = useRef(null)
  const resolvedRef = useRef(0)

  useEffect(() => {
    iterRef.current = 0
    resolvedRef.current = 0

    const tick = () => {
      const resolved = resolvedRef.current
      const next = text
        .split('')
        .map((char, i) => {
          if (char === ' ') return ' '
          if (i < resolved) return char
          // Each char gets its own iteration budget
          if (iterRef.current > maxIterations + i * 2) {
            resolvedRef.current = Math.max(resolvedRef.current, i + 1)
            return char
          }
          return CHARS[Math.floor(Math.random() * CHARS.length)]
        })
        .join('')

      setDisplayText(next)
      iterRef.current++

      if (resolvedRef.current < text.length) {
        timerRef.current = setTimeout(tick, speed)
      } else {
        setDisplayText(text)
        onComplete?.()
      }
    }

    timerRef.current = setTimeout(tick, 80) // slight initial delay
    return () => clearTimeout(timerRef.current)
  }, [text, speed, maxIterations, onComplete])

  return (
    <span className={className} aria-label={text}>
      {displayText}
    </span>
  )
}

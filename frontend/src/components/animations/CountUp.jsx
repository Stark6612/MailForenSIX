/**
 * CountUp — ReactBits-style spring count animation using motion
 * Triggers when element scrolls into view.
 */
import { useEffect, useRef, useState } from 'react'
import { useInView, useMotionValue, useSpring } from 'motion/react'

export default function CountUp({
  from = 0,
  to,
  duration = 1.5,
  separator = '',
  decimals = 0,
  suffix = '',
  prefix = '',
  className = '',
}) {
  const ref = useRef(null)
  const motionVal = useMotionValue(from)
  const springVal = useSpring(motionVal, {
    stiffness: 60,
    damping: 20,
    duration,
  })
  const isInView = useInView(ref, { once: true, margin: '0px 0px -40px 0px' })
  const [display, setDisplay] = useState(from)

  useEffect(() => {
    if (isInView) motionVal.set(to)
  }, [isInView, to, motionVal])

  useEffect(() => {
    const unsub = springVal.on('change', (v) => {
      const rounded = parseFloat(v.toFixed(decimals))
      if (separator) {
        setDisplay(rounded.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals }))
      } else {
        setDisplay(decimals > 0 ? rounded.toFixed(decimals) : Math.round(rounded))
      }
    })
    return unsub
  }, [springVal, separator, decimals])

  return (
    <span ref={ref} className={className}>
      {prefix}{display}{suffix}
    </span>
  )
}

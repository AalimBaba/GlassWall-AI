import { useEffect, useState } from 'react'
import type { ThreatState } from '../features/zones/zoneMath'
import { buildWatermarkText, watermarkOpacity } from '../features/watermark/watermark'

export function ForensicWatermark({ state, organizationId, deviceId, sessionId }: { state: ThreatState; organizationId: string; deviceId: string; sessionId: string }) {
  const [timestamp, setTimestamp] = useState(() => new Date())
  const [shift, setShift] = useState(0)
  useEffect(() => {
    const timer = window.setInterval(() => {
      setTimestamp(new Date())
      setShift(value => (value + 17) % 96)
    }, 30_000)
    return () => window.clearInterval(timer)
  }, [])
  const text = buildWatermarkText({ organizationId, deviceId, sessionId, timestamp })
  return <div
    className="forensic-watermark"
    aria-label="Session forensic watermark"
    style={{ opacity: watermarkOpacity(state), backgroundPosition: `${shift}px ${shift / 2}px` }}
  >
    <span>{text}</span>
  </div>
}

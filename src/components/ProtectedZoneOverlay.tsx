import type { ProtectedZone } from '../api/types'
import { zoneProtectionDecision, type ThreatState } from '../features/zones/zoneMath'

export function ProtectedZoneOverlay({ zones, state, editorMode = false, selectedId, onSelect }: { zones: ProtectedZone[]; state: ThreatState; editorMode?: boolean; selectedId?: string | null; onSelect?: (zone: ProtectedZone) => void }) {
  const decisions = zoneProtectionDecision(zones, state)
  return <div className={editorMode ? 'zone-layer editing' : 'zone-layer'} aria-label="Protected zones">
    {decisions.map(({ zone, action, active, reason }) => <button
      type="button"
      key={zone.id}
      className={`zone-box ${active ? action.toLowerCase() : 'inactive'} ${selectedId === zone.id ? 'selected' : ''}`}
      style={{ left: `${zone.relative_x * 100}%`, top: `${zone.relative_y * 100}%`, width: `${zone.relative_width * 100}%`, height: `${zone.relative_height * 100}%` }}
      onClick={() => onSelect?.(zone)}
      title={reason}
    >
      <span>{zone.name}</span><small>{zone.sensitivity} · {zone.enabled ? zone.protection_action : 'DISABLED'}</small>
      {editorMode && <i className="zone-handle"/>}
    </button>)}
  </div>
}

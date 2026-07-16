import { useMemo, useState } from 'react'
import type React from 'react'
import type { ProtectedZone, ProtectedZoneInput, ZoneProtectionAction, ZoneSensitivity } from '../api/types'
import { normalizeRect } from '../features/zones/zoneMath'
import { ProtectedZoneOverlay } from './ProtectedZoneOverlay'

const fallbackDraft: ProtectedZoneInput = {
  name: 'Sensitive zone',
  description: '',
  relative_x: 0.12,
  relative_y: 0.12,
  relative_width: 0.24,
  relative_height: 0.18,
  sensitivity: 'HIGH',
  protection_action: 'BLUR',
  enabled: true,
}

function draftFromZone(zone: ProtectedZone | null): ProtectedZoneInput {
  if (!zone) return fallbackDraft
  const { name, description, relative_x, relative_y, relative_width, relative_height, sensitivity, protection_action, enabled } = zone
  return { name, description, relative_x, relative_y, relative_width, relative_height, sensitivity, protection_action, enabled }
}

export function ProtectedZoneEditor({ zones, selectedZone, onSelect, onCreate, onUpdate, onDelete, onCancel }: { zones: ProtectedZone[]; selectedZone: ProtectedZone | null; onSelect: (zone: ProtectedZone | null) => void; onCreate: (zone: ProtectedZoneInput) => void; onUpdate: (zoneId: string, updates: Partial<ProtectedZoneInput>) => void; onDelete: (zoneId: string) => void; onCancel: () => void }) {
  const [draft, setDraft] = useState<ProtectedZoneInput>(draftFromZone(selectedZone))
  const [drawStart, setDrawStart] = useState<{ x: number; y: number } | null>(null)
  const previewZone = useMemo<ProtectedZone>(() => ({
    id: selectedZone?.id || 'draft-zone',
    organization_id: selectedZone?.organization_id || '',
    workspace_id: selectedZone?.workspace_id || '',
    created_at: selectedZone?.created_at || '',
    updated_at: selectedZone?.updated_at || '',
    ...draft,
  }), [draft, selectedZone])

  const updateDraft = (patch: Partial<ProtectedZoneInput>) => setDraft(current => ({ ...current, ...patch }))
  const pointFromEvent = (event: React.PointerEvent<HTMLDivElement>) => {
    const rect = event.currentTarget.getBoundingClientRect()
    return { x: Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width)), y: Math.max(0, Math.min(1, (event.clientY - rect.top) / rect.height)) }
  }

  return <div className="zone-editor">
    <div className="zone-editor-stage" onPointerDown={event => setDrawStart(pointFromEvent(event))} onPointerUp={event => { if (!drawStart) return; const rect = normalizeRect(drawStart, pointFromEvent(event)); if (rect.relative_width > 0.02 && rect.relative_height > 0.02) updateDraft(rect); setDrawStart(null) }}>
      <div className="zone-editor-canvas-note">Drag over this workspace preview to define normalized zone bounds.</div>
      <ProtectedZoneOverlay zones={selectedZone ? zones.map(zone => zone.id === selectedZone.id ? previewZone : zone) : [...zones, previewZone]} state="SECURE" editorMode selectedId={previewZone.id} onSelect={zone => { const real = zones.find(item => item.id === zone.id) || null; onSelect(real); setDraft(draftFromZone(real)) }}/>
    </div>
    <div className="zone-editor-form">
      <div><label>Name</label><input value={draft.name} onChange={event => updateDraft({ name: event.target.value })}/></div>
      <div><label>Description</label><input value={draft.description} onChange={event => updateDraft({ description: event.target.value })}/></div>
      <div className="zone-form-grid"><label>X<input type="number" step="0.01" value={draft.relative_x} onChange={event => updateDraft({ relative_x: Number(event.target.value) })}/></label><label>Y<input type="number" step="0.01" value={draft.relative_y} onChange={event => updateDraft({ relative_y: Number(event.target.value) })}/></label><label>W<input type="number" step="0.01" value={draft.relative_width} onChange={event => updateDraft({ relative_width: Number(event.target.value) })}/></label><label>H<input type="number" step="0.01" value={draft.relative_height} onChange={event => updateDraft({ relative_height: Number(event.target.value) })}/></label></div>
      <div className="zone-form-grid"><label>Sensitivity<select value={draft.sensitivity} onChange={event => updateDraft({ sensitivity: event.target.value as ZoneSensitivity })}><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></label><label>Action<select value={draft.protection_action} onChange={event => updateDraft({ protection_action: event.target.value as ZoneProtectionAction })}><option>BLUR</option><option>REDACT</option><option>HIDE</option><option>WATERMARK</option></select></label></div>
      <label className="zone-toggle"><input type="checkbox" checked={draft.enabled} onChange={event => updateDraft({ enabled: event.target.checked })}/> Enabled</label>
      <div className="zone-editor-actions"><button onClick={() => selectedZone ? onUpdate(selectedZone.id, draft) : onCreate(draft)}>{selectedZone ? 'Save changes' : 'Create zone'}</button>{selectedZone && <button onClick={() => onDelete(selectedZone.id)}>Delete</button>}<button onClick={onCancel}>Cancel</button></div>
      <p>Protected zones define which parts of the workspace contain sensitive information. Precise drag and resize editing is optimized for desktop and tablet.</p>
    </div>
  </div>
}

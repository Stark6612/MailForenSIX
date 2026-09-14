/**
 * PanelRelayTable — Panel 5 (Phase 3)
 * Real: relay_hops[{ip, country, asn, isp, masked, mask_reason, vpn, geo_mode}] from API
 * New: VPN badge, geo_mode indicator, click row → highlight on map (event bus),
 *      city column, ISP truncated with full tooltip
 */

import { useState } from 'react'

const GEO_MODE_BADGE = {
  online:  { cls: 'bg-mfx-safe/20 text-mfx-safe',            label: 'live' },
  cached:  { cls: 'bg-mfx-accent/20 text-mfx-accent',         label: 'cached' },
  offline: { cls: 'bg-mfx-suspicious/20 text-mfx-suspicious', label: 'offline' },
  none:    { cls: 'bg-mfx-border text-mfx-muted',             label: 'no geo' },
}

export default function PanelRelayTable({ data, loading }) {
  const [selectedHop, setSelectedHop] = useState(null)
  if (loading) return <SkeletonRelay />

  const hops       = data?.relay_hops ?? []
  const maskedCount = hops.filter(h => h.masked).length
  const vpnCount    = hops.filter(h => h.vpn).length

  return (
    <div className="panel animate-slide-up" id="panel-relay-table">
      <div className="flex items-center justify-between mb-3">
        <p className="panel-label mb-0">Email Relay Path</p>
        <div className="flex gap-1.5">
          {maskedCount > 0 && (
            <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-mfx-suspicious/20 text-mfx-suspicious font-semibold">
              {maskedCount} masked
            </span>
          )}
          {vpnCount > 0 && (
            <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-mfx-high/20 text-mfx-high font-semibold">
              {vpnCount} VPN
            </span>
          )}
        </div>
      </div>

      {hops.length === 0 ? (
        <p className="text-xs text-mfx-muted">No relay hops extracted — headers may be minimal.</p>
      ) : (
        <div className="overflow-x-auto -mx-1">
          <table className="w-full text-xs min-w-[380px]">
            <thead>
              <tr className="text-mfx-muted border-b border-mfx-border">
                <th className="pb-2 text-left font-medium w-6">#</th>
                <th className="pb-2 text-left font-medium">IP</th>
                <th className="pb-2 text-left font-medium">Location</th>
                <th className="pb-2 text-left font-medium">ASN / ISP</th>
                <th className="pb-2 text-left font-medium">Flags</th>
              </tr>
            </thead>
            <tbody>
              {hops.map((hop) => {
                const gm    = GEO_MODE_BADGE[hop.geo_mode] ?? GEO_MODE_BADGE.none
                const isSelected = selectedHop === hop.hop_index
                return (
                  <tr
                    key={hop.hop_index}
                    onClick={() => setSelectedHop(isSelected ? null : hop.hop_index)}
                    className={`border-b border-mfx-border/50 last:border-0 cursor-pointer transition-colors
                      ${isSelected ? 'bg-mfx-accent/10' : 'hover:bg-mfx-accent/5'}`}
                  >
                    <td className="py-2 font-mono text-mfx-muted">{hop.hop_index + 1}</td>
                    <td className="py-2 font-mono text-mfx-text">{hop.ip}</td>
                    <td className="py-2 text-mfx-muted">
                      {hop.city && hop.country
                        ? `${hop.city}, ${hop.country}`
                        : hop.country ?? '—'}
                    </td>
                    <td className="py-2 text-mfx-muted max-w-[110px]" title={hop.asn ?? hop.isp ?? ''}>
                      <span className="truncate block">{hop.asn ?? hop.isp ?? '—'}</span>
                    </td>
                    <td className="py-2">
                      <div className="flex flex-wrap gap-1">
                        {hop.masked && (
                          <span className="text-[9px] px-1 py-0.5 rounded bg-mfx-suspicious/20 text-mfx-suspicious font-semibold"
                                title={hop.mask_reason ?? 'Provider masked'}>
                            ⚠ masked
                          </span>
                        )}
                        {hop.vpn && (
                          <span className="text-[9px] px-1 py-0.5 rounded bg-mfx-high/20 text-mfx-high font-semibold">
                            VPN
                          </span>
                        )}
                        <span className={`text-[9px] px-1 py-0.5 rounded font-semibold ${gm.cls}`}>
                          {gm.label}
                        </span>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Expanded detail row */}
      {selectedHop !== null && (() => {
        const hop = hops.find(h => h.hop_index === selectedHop)
        if (!hop) return null
        return (
          <div className="mt-3 p-2 bg-mfx-bg/60 rounded-md border border-mfx-accent/30 text-xs">
            <p className="font-semibold text-mfx-accent mb-1">Hop {hop.hop_index + 1} Details</p>
            <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-mfx-muted">
              <span>IP:</span>       <span className="font-mono text-mfx-text">{hop.ip}</span>
              {hop.hostname && <><span>Host:</span><span className="font-mono text-mfx-text truncate">{hop.hostname}</span></>}
              {hop.lat && <><span>Coords:</span><span className="text-mfx-text">{hop.lat.toFixed(3)}, {hop.lon.toFixed(3)}</span></>}
              <span>Geo mode:</span> <span className="text-mfx-text">{hop.geo_mode}</span>
              {hop.mask_reason && <><span>Mask reason:</span><span className="text-mfx-text">{hop.mask_reason}</span></>}
            </div>
          </div>
        )
      })()}

      <div className="divider" />
      <p className="text-xs text-mfx-muted">
        {hops.length} hop{hops.length !== 1 ? 's' : ''} total ·{' '}
        {maskedCount} masked · {vpnCount} VPN/proxy · Click row to expand
      </p>
    </div>
  )
}

function SkeletonRelay() {
  return (
    <div className="panel" id="panel-relay-table-skeleton">
      <p className="panel-label">Email Relay Path</p>
      <div className="space-y-2">
        {[1, 2, 3].map(i => <div key={i} className="skeleton h-6 w-full" />)}
      </div>
    </div>
  )
}

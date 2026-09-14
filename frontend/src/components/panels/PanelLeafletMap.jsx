/**
 * PanelLeafletMap — Panel 3
 * Displays: interactive Leaflet map with relay hop pins and geolocation paths
 * Note: Leaflet CSS is imported dynamically to avoid SSR issues
 */

import { useEffect, useRef } from 'react'

// Dynamic import — Leaflet is only loaded when this panel mounts
let L = null

async function getLeaflet() {
  if (L) return L
  await import('leaflet/dist/leaflet.css')
  const leaflet = await import('leaflet')
  L = leaflet.default
  // Fix default icon paths (broken by Vite bundler)
  delete L.Icon.Default.prototype._getIconUrl
  L.Icon.Default.mergeOptions({
    iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
    iconUrl:       'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
    shadowUrl:     'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
  })
  return L
}

const RISK_COLORS = {
  critical:   '#EF4444',
  high:       '#F97316',
  suspicious: '#F59E0B',
  safe:       '#10B981',
  default:    '#3B82F6',
}

export default function PanelLeafletMap({ data, loading, airGapped }) {
  const mapRef   = useRef(null)
  const mapInst  = useRef(null)

  useEffect(() => {
    if (loading || !data?.relay_hops?.length) return

    let mounted = true

    const initMap = async () => {
      const Leaflet = await getLeaflet()
      if (!mounted || !mapRef.current) return

      // Destroy previous instance before recreating
      if (mapInst.current) {
        mapInst.current.remove()
        mapInst.current = null
      }

      const validHops = data.relay_hops.filter(h => h.lat && h.lon)
      if (!validHops.length) return

      const center = [validHops[0].lat, validHops[0].lon]
      const map = Leaflet.map(mapRef.current, {
        center,
        zoom: 3,
        zoomControl: true,
        scrollWheelZoom: false,
      })
      mapInst.current = map

      // Dark tile layer (CartoDB Dark Matter — no API key)
      Leaflet.tileLayer(
        'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
        { attribution: '© CartoDB', maxZoom: 19 }
      ).addTo(map)

      // Draw polyline through all valid hops
      const latlngs = validHops.map(h => [h.lat, h.lon])
      Leaflet.polyline(latlngs, { color: '#3B82F6', weight: 2, opacity: 0.7, dashArray: '6,4' }).addTo(map)

      // Add markers per hop
      validHops.forEach((hop, i) => {
        const color = hop.masked ? '#94A3B8' : (RISK_COLORS[data.risk_tier] ?? RISK_COLORS.default)
        const icon = Leaflet.divIcon({
          className: '',
          html: `<div style="
            width:26px; height:26px; border-radius:50%;
            background:${color}22; border:2px solid ${color};
            display:flex; align-items:center; justify-content:center;
            font-size:10px; font-weight:700; color:${color};
          ">${i + 1}</div>`,
          iconSize: [26, 26],
          iconAnchor: [13, 13],
        })

        Leaflet.marker([hop.lat, hop.lon], { icon })
          .bindPopup(`
            <div style="font-family:monospace;font-size:11px;line-height:1.6;">
              <b>Hop ${hop.hop_index + 1}</b><br/>
              IP: ${hop.ip}<br/>
              ${hop.hostname ? `Host: ${hop.hostname}<br/>` : ''}
              ${hop.country ? `Country: ${hop.country}<br/>` : ''}
              ${hop.asn ? `ASN: ${hop.asn}<br/>` : ''}
              ${hop.masked ? `<span style="color:#F59E0B">⚠ IP masked by provider</span>` : ''}
            </div>
          `)
          .addTo(map)
      })

      // Fit bounds
      if (validHops.length > 1) map.fitBounds(latlngs, { padding: [30, 30] })
    }

    initMap()
    return () => { mounted = false }
  }, [data, loading])

  if (loading) return <SkeletonMap />

  const hasGeo = data?.relay_hops?.some(h => h.lat && h.lon)

  return (
    <div className="panel animate-slide-up" id="panel-leaflet-map">
      <p className="panel-label">Relay Path — Geolocation Map</p>
      {airGapped && (
        <div className="mb-2 text-xs text-mfx-suspicious flex items-center gap-1.5">
          <span>⚠</span> Air-gapped: local GeoLite2 DB in use
        </div>
      )}
      {hasGeo ? (
        <div ref={mapRef} className="w-full rounded-panel overflow-hidden" style={{ height: '220px' }} />
      ) : (
        <div className="flex items-center justify-center h-[220px] bg-mfx-bg/50 rounded-panel border border-mfx-border">
          <div className="text-center text-mfx-muted text-xs">
            <p className="text-2xl mb-2">🗺️</p>
            <p>No geolocatable IPs found in relay chain.</p>
            <p className="mt-1 text-mfx-muted/60">Provider may have masked originating IP.</p>
          </div>
        </div>
      )}
    </div>
  )
}

function SkeletonMap() {
  return (
    <div className="panel" id="panel-leaflet-map-skeleton">
      <p className="panel-label">Relay Path — Geolocation Map</p>
      <div className="skeleton w-full rounded-panel" style={{ height: '220px' }} />
    </div>
  )
}

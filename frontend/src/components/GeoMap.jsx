import L from 'leaflet';
import { MapContainer, Marker, Popup, TileLayer } from 'react-leaflet';
import icon from 'leaflet/dist/images/marker-icon.png';
import iconShadow from 'leaflet/dist/images/marker-shadow.png';

delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({ iconUrl: icon, shadowUrl: iconShadow });

export default function GeoMap({ geolocation }) {
  const lat = Number(geolocation?.latitude);
  const lng = Number(geolocation?.longitude);
  const valid = Number.isFinite(lat) && Number.isFinite(lng) && !(lat === 0 && lng === 0) && lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180;
  if (!valid) return <div className="tn-map-empty"><MapPinIcon /><strong>Location could not be determined</strong><span>No reliable public source coordinate was returned.</span></div>;
  return (
    <div className="tn-map">
      <MapContainer center={[lat, lng]} zoom={5} scrollWheelZoom={false} dragging={false} doubleClickZoom={false} touchZoom={false} keyboard={false} className="tn-map-container">
        <TileLayer attribution='&copy; OpenStreetMap contributors' url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
        <Marker position={[lat, lng]}>
          <Popup>
            <div style={{ fontSize: '12px', lineHeight: '1.5' }}>
              <strong style={{ fontSize: '13px', color: '#0f172a' }}>{geolocation.city || 'Unknown'}, {geolocation.country || 'Unknown'}</strong>
              <div style={{ color: '#0369a1', fontWeight: '600', marginTop: '3px' }}>
                {geolocation.resolution_source || '7-Tier Forensic Attribution'}
              </div>
              <div style={{ color: '#475569', marginTop: '2px' }}>
                Network/ISP: <strong>{geolocation.isp || 'Identified Node'}</strong>
              </div>
              <div style={{ color: '#64748b', fontSize: '11px', marginTop: '2px' }}>
                ID: <code>{geolocation.earliest_external_ip || 'Network Hop'}</code>
              </div>
            </div>
          </Popup>
        </Marker>
      </MapContainer>
      <div className="tn-map-overlay">
        {geolocation.country ? `APPROX. ORIGIN: ${geolocation.country.toUpperCase()}` : 'APPROX. SENDER ORIGIN'}
      </div>
    </div>
  );
}
function MapPinIcon(){ return <span className="tn-map-pin">●</span>; }

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
        <Marker position={[lat, lng]}><Popup><strong>{geolocation.city || 'Unknown'}, {geolocation.country || 'Unknown'}</strong><br />ISP: {geolocation.isp || 'Unknown'}<br />IP: {geolocation.earliest_external_ip || 'Unknown'}</Popup></Marker>
      </MapContainer>
      <div className="tn-map-overlay">APPROX. ORIGIN</div>
    </div>
  );
}
function MapPinIcon(){ return <span className="tn-map-pin">●</span>; }

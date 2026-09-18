import { MapPin, Server, ShieldAlert } from 'lucide-react';
import GeoMap from './GeoMap';
import { percent } from '../utils';

export default function GeolocationCard({ geolocation }) {
  if (!geolocation) return null;
  const masked = geolocation.is_vpn_or_proxy || geolocation.is_tor_exit_node;
  return (
    <section className="tn-card tn-geo-card">
      <div className="tn-card-title"><Server /> Approximate Origin Intelligence <span className="tn-title-chip">INFRASTRUCTURE</span></div>
      <div className="tn-geo-headline"><div><span className="tn-kicker">EARLIEST RELIABLE SOURCE IP</span><code>{geolocation.earliest_external_ip || 'Unknown'}</code></div><div className="tn-confidence"><strong>{percent(geolocation.confidence_level)}%</strong><span>confidence</span></div></div>
      <div className="tn-geo-details">
        <div><span>Country</span><strong>{geolocation.country || 'Unknown'}</strong></div>
        <div><span>Region / City</span><strong>{[geolocation.region, geolocation.city].filter(Boolean).join(', ') || 'Unknown'}</strong></div>
        <div><span>ISP / ASN</span><strong>{geolocation.isp || 'Unknown'} <em>{geolocation.asn || ''}</em></strong></div>
        <div><span>VPN / Proxy</span><strong className={geolocation.is_vpn_or_proxy ? 'danger-text' : 'good-text'}>{geolocation.is_vpn_or_proxy ? 'Detected' : 'Not detected'}</strong></div>
        <div><span>Tor exit node</span><strong className={geolocation.is_tor_exit_node ? 'danger-text' : 'good-text'}>{geolocation.is_tor_exit_node ? 'Detected' : 'Not detected'}</strong></div>
      </div>
      {masked && <div className="tn-uncertainty"><ShieldAlert /> Masking infrastructure may reduce attribution reliability.</div>}
      <div className="tn-map-wrap"><GeoMap geolocation={geolocation} /></div>
      <div className="tn-map-disclaimer"><MapPin /> Map shows probable infrastructure location, not the physical location of a person.</div>
    </section>
  );
}

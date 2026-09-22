import { MapPin, Server, ShieldAlert, Compass } from 'lucide-react';
import GeoMap from './GeoMap';
import { percent } from '../utils';

const getMethodMeta = (method) => {
  switch (method) {
    case 'hop0_client_ip':
      return { label: '⚡ Direct Source IP Forensics', color: '#34d399', bg: 'rgba(16, 185, 129, 0.15)', border: 'rgba(16, 185, 129, 0.35)' };
    case 'domain_infrastructure':
      return { label: '🌐 Sender Domain Mail Infrastructure (MX)', color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.15)', border: 'rgba(56, 189, 248, 0.35)' };
    case 'client_clock_timezone':
      return { label: '🕒 Client Clock Offset Leak', color: '#fbbf24', bg: 'rgba(245, 158, 11, 0.15)', border: 'rgba(245, 158, 11, 0.35)' };
    case 'cctld_jurisdiction':
      return { label: '🏛️ Sovereign ccTLD Jurisdiction', color: '#a78bfa', bg: 'rgba(129, 140, 248, 0.15)', border: 'rgba(129, 140, 248, 0.35)' };
    case 'webmail_provider_origin':
      return { label: '🏢 Regional Webmail Provider Origin', color: '#c084fc', bg: 'rgba(192, 132, 252, 0.15)', border: 'rgba(192, 132, 252, 0.35)' };
    case 'indic_linguistic':
      return { label: '📜 Indic Linguistic Context Evidence', color: '#fb923c', bg: 'rgba(251, 146, 60, 0.15)', border: 'rgba(251, 146, 60, 0.35)' };
    default:
      return { label: '📍 Approximate Origin Intelligence', color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.15)', border: 'rgba(56, 189, 248, 0.35)' };
  }
};

export default function GeolocationCard({ geolocation }) {
  if (!geolocation) return null;
  const masked = geolocation.is_vpn_or_proxy || geolocation.is_tor_exit_node;
  const methodMeta = getMethodMeta(geolocation.resolution_method);

  return (
    <section className="tn-card tn-geo-card">
      <div className="tn-card-title">
        <Server /> Approximate Origin Intelligence <span className="tn-title-chip">INFRASTRUCTURE</span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', margin: '8px 0 12px', flexWrap: 'wrap' }}>
        <span style={{
          fontSize: '11px',
          fontWeight: '700',
          padding: '3px 10px',
          borderRadius: '999px',
          background: methodMeta.bg,
          color: methodMeta.color,
          border: `1px solid ${methodMeta.border}`,
          display: 'inline-flex',
          alignItems: 'center',
          gap: '5px'
        }}>
          <Compass style={{ width: '13px', height: '13px' }} />
          {methodMeta.label}
        </span>
        {geolocation.resolution_source && (
          <span style={{ fontSize: '12px', color: '#94a3b8' }}>
            Source: <strong style={{ color: '#e2e8f0' }}>{geolocation.resolution_source}</strong>
          </span>
        )}
      </div>

      <div className="tn-geo-headline">
        <div>
          <span className="tn-kicker">RESOLVED SENDER IDENTIFIER</span>
          <code>{geolocation.earliest_external_ip || 'Identified via Forensics'}</code>
        </div>
        <div className="tn-confidence">
          <strong>{percent(geolocation.confidence_level)}%</strong>
          <span>confidence</span>
        </div>
      </div>

      <div className="tn-geo-details">
        <div><span>Country</span><strong>{geolocation.country || 'India'}</strong></div>
        <div><span>Region / City</span><strong>{[geolocation.region, geolocation.city].filter(Boolean).join(', ') || 'Approximate Region'}</strong></div>
        <div><span>ISP / Network</span><strong>{geolocation.isp || 'Identified Network'} <em>{geolocation.asn ? `(${geolocation.asn})` : ''}</em></strong></div>
        <div><span>VPN / Proxy</span><strong className={geolocation.is_vpn_or_proxy ? 'danger-text' : 'good-text'}>{geolocation.is_vpn_or_proxy ? 'Detected' : 'Not detected'}</strong></div>
        <div><span>Tor exit node</span><strong className={geolocation.is_tor_exit_node ? 'danger-text' : 'good-text'}>{geolocation.is_tor_exit_node ? 'Detected' : 'Not detected'}</strong></div>
      </div>

      {masked && <div className="tn-uncertainty"><ShieldAlert /> Masking infrastructure may reduce attribution reliability.</div>}
      <div className="tn-map-wrap"><GeoMap geolocation={geolocation} /></div>
      <div className="tn-map-disclaimer"><MapPin /> Map illustrates probable sender geographic origin derived via 7-tier forensic attribution.</div>
    </section>
  );
}

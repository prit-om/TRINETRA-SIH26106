import { Crosshair, ShieldQuestion, Target } from 'lucide-react';
import { percent } from '../utils';

export default function AttributionEngineCard({ attribution, geolocation }) {
  const confidence = Number(attribution?.confidence ?? 0);
  const reasons = attribution?.reasons || [];
  const method = attribution?.method || 'Evidence-weighted attribution support';
  return <section className="tn-card tn-attribution-card">
    <div className="tn-card-title"><Crosshair /> Attribution Engine <span className="tn-title-chip">RESPONSIBLE ATTRIBUTION</span></div>
    <div className="tn-attribution-main"><div className="tn-attribution-score"><strong>{confidence}</strong><span>/100</span></div><div><b>{attribution?.cluster_type || 'Unclustered activity'}</b><p>Attribution support confidence</p></div></div>
    <div className="tn-attribution-bar"><i style={{ width: `${Math.max(0, Math.min(100, confidence))}%` }} /></div>
    <div className="tn-attribution-factors">{reasons.length ? reasons.slice(0, 5).map((reason, i) => <div key={i}><Target />{reason}</div>) : <div><ShieldQuestion />Insufficient cross-case evidence for stronger attribution.</div>}</div>
    <div className="tn-attribution-note"><strong>What this means:</strong> {method}. It does not identify a person or prove attacker identity.</div>
    {geolocation?.confidence_level != null && <div className="tn-origin-confidence">Origin infrastructure confidence <strong>{percent(geolocation.confidence_level)}%</strong></div>}
  </section>;
}

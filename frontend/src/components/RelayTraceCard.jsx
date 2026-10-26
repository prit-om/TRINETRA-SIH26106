import { AlertTriangle, ArrowRight, Route } from 'lucide-react';

export default function RelayTraceCard({ relay }) {
  const hops = relay?.hops || [];
  const anomalies = relay?.anomalies || [];

  return (
    <section className="tn-card tn-detail-card">
      <div className="tn-card-title">
        <Route /> SMTP Relay Trace{' '}
        <span className="tn-title-chip">{relay?.hop_count || hops.length || 0} HOPS</span>
      </div>
      {!hops.length ? (
        <div className="tn-empty-inline">No parseable Received hops were found.</div>
      ) : (
        <div className="tn-trace">
          {hops.map((hop, i) => (
            <div className="tn-trace-node" key={`${hop.ip || 'hop'}-${i}`}>
              <div className="tn-trace-dot">{i + 1}</div>
              <div style={{ minWidth: 0, flex: 1 }}>
                <strong>{hop.ip || 'Unknown IP'}</strong>
                <span>{hop.by || 'Unknown mail server'}</span>
                <small>{hop.timestamp || 'Timestamp unavailable'}</small>
              </div>
              {i < hops.length - 1 && <ArrowRight className="tn-trace-arrow" />}
            </div>
          ))}
        </div>
      )}
      {anomalies.length ? (
        <div className="tn-inline-warning" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: '6px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700 }}>
            <AlertTriangle style={{ width: 16, height: 16, flexShrink: 0 }} />
            <span>{anomalies.length} relay anomaly detected:</span>
          </div>
          <ul style={{ margin: '4px 0 0 20px', padding: 0, fontSize: '12px', lineHeight: 1.5 }}>
            {anomalies.map((anom, idx) => (
              <li key={idx}>
                {typeof anom === 'string' ? anom : anom.detail || anom.anomaly || JSON.stringify(anom)}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}

import { AlertTriangle, ArrowRight, Route } from 'lucide-react';

export default function RelayTraceCard({ relay }) {
  const hops = relay?.hops || [];
  return <section className="tn-card tn-detail-card">
    <div className="tn-card-title"><Route /> SMTP Relay Trace <span className="tn-title-chip">{relay?.hop_count || hops.length || 0} HOPS</span></div>
    {!hops.length ? <div className="tn-empty-inline">No parseable Received hops were found.</div> : <div className="tn-trace">{hops.map((hop, i) => <div className="tn-trace-node" key={`${hop.ip || 'hop'}-${i}`}><div className="tn-trace-dot">{i + 1}</div><div><strong>{hop.ip || 'Unknown IP'}</strong><span>{hop.by || 'Unknown mail server'}</span><small>{hop.timestamp || 'Timestamp unavailable'}</small></div>{i < hops.length - 1 && <ArrowRight className="tn-trace-arrow" />}</div>)}</div>}
    {relay?.anomalies?.length ? <div className="tn-inline-warning"><AlertTriangle /> {relay.anomalies.length} relay anomaly/anomalies detected.</div> : null}
  </section>;
}

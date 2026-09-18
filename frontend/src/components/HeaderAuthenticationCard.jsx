import { ShieldCheck, ShieldX } from 'lucide-react';

function state(value) {
  if (value === 'pass') return { label: 'PASS', cls: 'pass' };
  if (value === 'fail') return { label: 'FAIL', cls: 'fail' };
  return { label: String(value || 'none').toUpperCase(), cls: 'neutral' };
}

export default function HeaderAuthenticationCard({ analysis }) {
  if (!analysis) return null;
  const checks = ['spf_result', 'dkim_result', 'dmarc_result'];
  return (
    <div className="tn-subcard tn-auth-card">
      <div className="tn-card-title"><ShieldCheck /> Header Authentication</div>
      <div className="tn-auth-grid">
        {checks.map((key) => {
          const s = state(analysis[key]);
          return <div key={key} className={`tn-auth-pill ${s.cls}`}><span>{key.split('_')[0].toUpperCase()}</span><strong>{s.label}</strong></div>;
        })}
      </div>
      <div className="tn-auth-findings">
        <div><span>Return-Path mismatch</span>{analysis.sender_returnpath_mismatch ? <b className="danger"><ShieldX /> Flagged</b> : <b className="good">Clear</b>}</div>
        <div><span>Reply-To anomaly</span>{analysis.replyto_anomaly ? <b className="danger"><ShieldX /> Flagged</b> : <b className="good">Clear</b>}</div>
      </div>
    </div>
  );
}

import { ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react';
import { getBadgeColor, getRiskTextColor } from '../utils';

export default function RiskSummaryCard({ report }) {
  const score = Math.max(0, Math.min(100, Number(report?.risk_score) || 0));
  const icon = score >= 75 ? ShieldAlert : score >= 40 ? AlertTriangle : ShieldCheck;
  const Icon = icon;
  return (
    <section className="tn-card tn-risk-card">
      <div className="tn-risk-accent" />
      <div className="tn-risk-copy">
        <div className={`tn-badge ${getBadgeColor(report.classification)}`}><Icon /> {report.classification || 'Unknown'}</div>
        <h2>{report.summary || 'No summary supplied by the analysis engine.'}</h2>
        <div className="tn-case-line">CASE <code>{report.case_id || '—'}</code></div>
      </div>
      <div className="tn-risk-score">
        <div className={`tn-score-ring ${getRiskTextColor(score)}`} style={{ '--tn-score': `${score * 3.6}deg` }}>
          <div><strong>{score}</strong><span>/100</span></div>
        </div>
        <span>RISK SCORE</span>
      </div>
    </section>
  );
}

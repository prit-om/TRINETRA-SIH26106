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
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <div className={`tn-badge ${getBadgeColor(report.classification)}`}><Icon /> {report.classification || 'Unknown'}</div>
          {report.engine_mode && (
            <span style={{
              fontSize: '11px',
              fontWeight: '700',
              padding: '3px 10px',
              borderRadius: '999px',
              background: report.air_gapped ? 'rgba(16, 185, 129, 0.15)' : 'rgba(56, 189, 248, 0.15)',
              color: report.air_gapped ? '#34d399' : '#38bdf8',
              border: `1px solid ${report.air_gapped ? 'rgba(16, 185, 129, 0.35)' : 'rgba(56, 189, 248, 0.35)'}`,
              letterSpacing: '0.03em'
            }}>
              {report.air_gapped ? '🛡️ Sovereign Air-Gapped' : '⚡ Dual-Engine Hybrid'}
            </span>
          )}
        </div>
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

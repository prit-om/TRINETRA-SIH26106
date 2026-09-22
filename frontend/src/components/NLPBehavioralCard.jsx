import { BrainCircuit, Sparkles } from 'lucide-react';
import { percent } from '../utils';

const metrics = [
  ['executive_impersonation_score', 'Executive impersonation'],
  ['urgent_request_score', 'Urgent request'],
  ['financial_request_score', 'Financial request'],
  ['social_engineering_score', 'Social engineering'],
  ['credential_harvesting_score', 'Credential harvesting'],
];

export default function NLPBehavioralCard({ analysis }) {
  if (!analysis) return null;
  return (
    <section className="tn-card tn-nlp-card">
      <div className="tn-card-title"><BrainCircuit /> NLP Behavioral Analysis <span className="tn-title-chip">CONTENT SIGNALS</span></div>
      <div className="tn-metric-list">
        {metrics.map(([key, label]) => {
          const value = percent(analysis[key]);
          return <div className="tn-metric" key={key}><div><span>{label}</span><strong>{value}%</strong></div><div className="tn-progress"><i style={{ width: `${value}%` }} /></div></div>;
        })}
      </div>
      <div className="tn-model-note">
        {analysis.privacy_mode && (
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '8px', flexWrap: 'wrap' }}>
            <span style={{
              fontSize: '10px',
              fontWeight: '800',
              padding: '2px 8px',
              borderRadius: '4px',
              background: analysis.privacy_mode.includes('air-gapped') ? 'rgba(16, 185, 129, 0.2)' : 'rgba(56, 189, 248, 0.15)',
              color: analysis.privacy_mode.includes('air-gapped') ? '#34d399' : '#38bdf8',
              border: `1px solid ${analysis.privacy_mode.includes('air-gapped') ? 'rgba(16, 185, 129, 0.35)' : 'rgba(56, 189, 248, 0.3)'}`,
              letterSpacing: '0.04em'
            }}>
              {analysis.privacy_mode.includes('air-gapped') ? '🛡️ AIR-GAPPED' : '⚡ HYBRID CLOUD'}
            </span>
            {analysis.model_used && (
              <span style={{ fontSize: '11px', color: '#94a3b8' }}>
                Engine: <strong style={{ color: '#e2e8f0' }}>{analysis.model_used}</strong>
              </span>
            )}
          </div>
        )}
        “{analysis.model_reasoning || 'No model reasoning supplied.'}”
      </div>
      <div className="tn-ai-likelihood"><Sparkles /> AI-generated text likelihood <strong>{percent(analysis.ai_generated_text_likelihood)}%</strong></div>
    </section>
  );
}

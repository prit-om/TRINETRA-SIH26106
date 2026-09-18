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
      <div className="tn-model-note">“{analysis.model_reasoning || 'No model reasoning supplied.'}”</div>
      <div className="tn-ai-likelihood"><Sparkles /> AI-generated text likelihood <strong>{percent(analysis.ai_generated_text_likelihood)}%</strong></div>
    </section>
  );
}

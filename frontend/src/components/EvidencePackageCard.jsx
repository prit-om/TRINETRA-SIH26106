import { BrainCircuit, Database, Fingerprint, ShieldAlert } from 'lucide-react';
import { clampScore, percent } from '../utils';

const actionClasses = { monitor: 'blue', investigate: 'amber', quarantine: 'orange', escalate: 'red' };

function Score({ value, label }) {
  const score = clampScore(value);
  return <div className="tn-layer-score"><div><span>{label}</span><strong>{score}<small>/100</small></strong></div><div className="tn-progress"><i style={{ width: `${score}%` }} /></div></div>;
}
function Findings({ items = [] }) { return items.length ? <ul className="tn-findings">{items.map((x, i) => <li key={`${x}-${i}`}>{x}</li>)}</ul> : <p className="tn-no-findings">No anomalies detected.</p>; }

export default function EvidencePackageCard({ evidence }) {
  if (!evidence) return <section className="tn-card tn-evidence-card"><div className="tn-card-title"><ShieldAlert /> Trinetra Evidence Package</div><div className="tn-degraded">The backend response did not include the evidence package.</div></section>;
  const { layer1 = {}, layer2 = {}, layer3 = {} } = evidence;
  const action = String(layer3.recommended_action || '').toLowerCase();
  const attachBonus = evidence.attachments?.bonus ?? evidence.fusion?.attachment_bonus ?? evidence.attachment_bonus ?? 0;
  const anonBonus = evidence.anonymization?.bonus ?? evidence.fusion?.anonymization_bonus ?? 0;
  return <section className="tn-card tn-evidence-card">
    <div className="tn-evidence-head">
      <div>
        <div className="tn-card-title"><ShieldAlert /> Trinetra Evidence Package</div>
        <p>Three independent evidence layers fused into one explainable forensic decision.</p>
      </div>
      <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
        <span className="tn-bonus">Attachment bonus <strong>+{attachBonus}</strong></span>
        {anonBonus > 0 && <span className="tn-bonus">Anonymization <strong>+{anonBonus}</strong></span>}
      </div>
    </div>
    <div className="tn-layer-grid">
      <article className="tn-layer layer-one"><div className="tn-layer-head"><span className="tn-layer-number">01</span><div><strong>Deterministic Forensics</strong><small>Header & routing evidence</small></div><Fingerprint /></div><Score value={layer1.score} label="Forensic score" /><Findings items={layer1.findings} /></article>
      <article className="tn-layer layer-two"><div className="tn-layer-head"><span className="tn-layer-number">02</span><div><strong>Intelligence + Correlation</strong><small>Infrastructure & reputation</small></div><Database /></div><Score value={layer2.score} label="Intelligence score" /><Findings items={layer2.findings} /><div className="tn-intel-status"><span>Local intelligence <b className={layer2.local_intelligence_used ? 'good-text' : ''}>{layer2.local_intelligence_used ? 'Used' : 'Not used'}</b></span><span>External intelligence <b className={layer2.external_intelligence_used ? 'good-text' : 'warn-text'}>{layer2.external_intelligence_used ? 'Used' : 'Unavailable'}</b></span></div>{!layer2.external_intelligence_used && <div className="tn-small-warning">Local intelligence only — external APIs unavailable for this case.</div>}</article>
      <article className="tn-layer layer-three"><div className="tn-layer-head"><span className="tn-layer-number">03</span><div><strong>AI Forensic Reasoning</strong><small>Contextual synthesis</small></div><BrainCircuit /></div><div className="tn-confidence-row"><span>Confidence</span><strong>{percent(layer3.confidence)}%</strong></div><div className="tn-progress"><i style={{ width: `${percent(layer3.confidence)}%` }} /></div><p className="tn-alignment">{layer3.evidence_alignment || 'No evidence alignment statement supplied.'}</p><div className="tn-reasoning">{layer3.forensic_reasoning || 'No forensic reasoning supplied.'}</div><div className="tn-action-row"><span className={`tn-action ${actionClasses[action] || 'neutral'}`}>Action: {layer3.recommended_action || 'Unknown'}</span><span className="tn-source">{layer3.reasoning_source === 'gemini-layer3-synthesis' ? 'AI-generated' : 'Offline synthesis'}</span></div></article>
    </div>
  </section>;
}

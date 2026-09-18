import { ExternalLink, Link2Off } from 'lucide-react';

export default function UrlFindingsCard({ findings = [] }) {
  return <section className="tn-card tn-detail-card">
    <div className="tn-card-title"><ExternalLink /> URL & Domain Findings</div>
    {!findings.length ? <div className="tn-empty-inline">No URLs found in this email.</div> : <div className="tn-url-list">{findings.map((item, i) => <div className="tn-url-item" key={`${item.original_url}-${i}`}><div className="tn-url-top"><strong>{item.domain || 'Unknown domain'}</strong><span className={`tn-mini-badge ${item.is_malicious ? 'danger' : 'good'}`}>{item.is_malicious ? 'Malicious' : 'Clean'}</span></div><div className="tn-url-value"><span>Original</span><code>{item.original_url || '—'}</code></div><div className="tn-url-value"><span>Expanded</span><code>{item.expanded_url || '—'}</code></div><div className="tn-url-tags">{item.is_shortened && <span>Shortened</span>}{item.is_lookalike_domain && <span>Look-alike domain</span>}<span>{item.redirect_chain_length ?? 0} redirect(s)</span></div></div>)}</div>}
    {!findings.length && <Link2Off className="tn-empty-icon-small" />}
  </section>;
}

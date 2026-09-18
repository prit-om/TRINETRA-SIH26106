import { Globe2, ServerCog } from 'lucide-react';

export default function DomainIntelligenceCard({ findings = [] }) {
  const domains = findings.filter((x) => x?.domain);
  return <section className="tn-card tn-detail-card">
    <div className="tn-card-title"><Globe2 /> Domain Intelligence <span className="tn-title-chip">DNS / MX</span></div>
    {!domains.length ? <div className="tn-empty-inline">No domain intelligence returned for this case.</div> : <div className="tn-domain-list">{domains.slice(0,5).map((item,i)=><div className="tn-domain-item" key={`${item.domain}-${i}`}><div className="tn-domain-top"><strong>{item.domain}</strong>{item.risk_flags?.length ? <span className="tn-mini-badge danger">{item.risk_flags.length} flag{item.risk_flags.length>1?'s':''}</span> : <span className="tn-mini-badge good">No flags</span>}</div><div className="tn-domain-grid"><div><span>A records</span><b>{item.a_records?.length || 0}</b></div><div><span>MX records</span><b>{item.mx_records?.length || 0}</b></div><div><span>Nameservers</span><b>{item.nameservers?.length || 0}</b></div></div>{item.risk_flags?.length ? <ul className="tn-domain-flags">{item.risk_flags.map((flag,j)=><li key={j}>{flag}</li>)}</ul> : null}</div>)}</div>}
    {domains.some((x)=>x.dns_available===false) && <div className="tn-domain-note"><ServerCog /> DNS resolver unavailable for one or more lookups; no domain risk is inferred from missing data.</div>}
  </section>;
}

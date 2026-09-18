import { Network, Link2 } from 'lucide-react';

const palette = { case: 'case', domain: 'domain', ip: 'ip', hash: 'hash', url: 'url', sender: 'sender', campaign: 'campaign' };

function layoutNodes(nodes) {
  const center = nodes.find((n) => n.type === 'case') || nodes[0];
  const others = nodes.filter((n) => n !== center).slice(0, 8);
  const cx = 190, cy = 120, rx = 140, ry = 85;
  return nodes.length ? [{ ...center, x: cx, y: cy }, ...others.map((n, i) => { const a = (-Math.PI / 2) + (i * (Math.PI * 2 / Math.max(others.length, 1))); return { ...n, x: cx + Math.cos(a) * rx, y: cy + Math.sin(a) * ry }; })] : [];
}

export default function GraphIntelCard({ graph, relatedCaseIds = [] }) {
  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];
  const placed = layoutNodes(nodes);
  const byId = Object.fromEntries(placed.map((n) => [n.id, n]));
  const caseNode = placed.find((n) => n.type === 'case') || placed[0];
  byId['case:'] = caseNode;
  const confidence = Number(graph?.campaign_confidence ?? 0);
  return (
    <section className="tn-card tn-graph-card">
      <div className="tn-card-title">
        <Network /> Graph Intelligence <span className="tn-title-chip">CAMPAIGN / IOC</span>
      </div>
      <div className="tn-graph-summary">
        <div><strong>{nodes.length}</strong><span>IOC Nodes</span></div>
        <div><strong>{edges.length}</strong><span>Edges</span></div>
        <div><strong>{confidence}%</strong><span>Confidence</span></div>
      </div>
      {nodes.length ? (
        <div className="tn-graph-canvas">
          <svg viewBox="0 0 380 240" role="img" aria-label="IOC relationship graph">
            {edges.map((edge, i) => {
              const a = byId[edge.source], b = byId[edge.target];
              return a && b ? <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} className="tn-graph-edge" /> : null;
            })}
            {placed.map((n) => (
              <g key={n.id}>
                <circle cx={n.x} cy={n.y} r={n.type === 'case' ? 24 : 17} className={`tn-node ${palette[n.type] || 'other'}`} />
                <text x={n.x} y={n.y + 4} textAnchor="middle" className="tn-node-text" style={{ fontSize: '10px', fontWeight: 900 }}>
                  {n.type === 'case' ? 'CASE' : (String(n.type || '?').slice(0, 3).toUpperCase())}
                </text>
                <title>{n.type}: {n.label}</title>
              </g>
            ))}
          </svg>
        </div>
      ) : (
        <div className="tn-graph-empty">
          <Network />
          <strong>No Graph Indicators Returned</strong>
          <span>The backend did not provide a relationship graph for this case.</span>
        </div>
      )}
      <div className="tn-graph-links">
        {nodes.filter((n) => n.type !== 'case').slice(0, 6).map((n) => (
          <span key={n.id}>
            <i className={`tn-dot ${palette[n.type] || 'other'}`} />
            {n.type}: {n.label}
          </span>
        ))}
      </div>
      <div className="tn-correlation">
        <Link2 />
        <span>Correlated Cases in Campaign</span>
        <strong>{relatedCaseIds.length}</strong>
      </div>
    </section>
  );
}

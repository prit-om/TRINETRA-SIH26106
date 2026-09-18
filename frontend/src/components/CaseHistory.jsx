import { useEffect, useMemo, useState } from 'react';
import { ArrowDown, ArrowUp, Eye, RefreshCw, Search, XCircle, Clock, ShieldCheck } from 'lucide-react';
import { apiFetch } from '../api';
import { formatDate, getBadgeColor } from '../utils';

export default function CaseHistory({ onOpenCase }) {
  const [cases, setCases] = useState([]);
  const [query, setQuery] = useState('');
  const [sortKey, setSortKey] = useState('uploaded_at');
  const [asc, setAsc] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await (await apiFetch('/cases')).json();
      setCases(Array.isArray(data) ? data : data.cases || []);
    } catch (e) {
      setError(e.message || 'Unable to load case history.');
    } finally {
      setLoading(false);
    }
  };

  // Initial load
  useEffect(() => {
    load();
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return [...cases]
      .filter((x) => !q || `${x.sender_email || ''} ${x.subject || ''} ${x.case_id || ''}`.toLowerCase().includes(q))
      .sort((a, b) => {
        let av = a[sortKey] ?? '', bv = b[sortKey] ?? '';
        if (sortKey === 'risk_score') {
          av = Number(av);
          bv = Number(bv);
        } else {
          av = String(av).toLowerCase();
          bv = String(bv).toLowerCase();
        }
        return (av === bv ? 0 : av > bv ? 1 : -1) * (asc ? 1 : -1);
      });
  }, [cases, query, sortKey, asc]);

  const sort = (key) => {
    if (key === sortKey) setAsc((v) => !v);
    else {
      setSortKey(key);
      setAsc(false);
    }
  };

  return (
    <section className="tn-history-shell">
      <div className="tn-card tn-history-card">
        <div className="tn-page-heading">
          <div>
            <h2>Forensic Case History</h2>
            <p>
              Archived email investigations stored in local runtime database. Select any case to resume the forensic workspace.
            </p>
          </div>
          <div className="tn-history-toolbar">
            <div className="tn-search">
              <Search />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search sender, subject, or Case ID…"
              />
            </div>
            <button className="tn-icon-button" onClick={load} disabled={loading} title="Refresh case database">
              <RefreshCw className={loading ? 'tn-spin' : ''} />
            </button>
          </div>
        </div>

        {error && (
          <div className="tn-alert tn-alert-error" style={{ marginTop: 16 }}>
            <XCircle /> <span>{error}</span>
          </div>
        )}

        <div className="tn-table-wrap">
          {loading && !cases.length ? (
            <div className="tn-table-empty">
              <RefreshCw className="tn-spin" style={{ width: 24, height: 24, margin: '0 auto 10px' }} />
              <div>Loading stored forensic cases from database…</div>
            </div>
          ) : !filtered.length ? (
            <div className="tn-table-empty">
              <ShieldCheck style={{ width: 32, height: 32, margin: '0 auto 10px', color: 'var(--tn-muted)' }} />
              <div>No forensic cases match your search query.</div>
            </div>
          ) : (
            <table className="tn-case-table">
              <thead>
                <tr>
                  <th style={{ width: '190px' }}>
                    <button type="button" onClick={() => sort('uploaded_at')}>
                      <Clock style={{ width: 14, height: 14 }} />
                      Timestamp {sortKey === 'uploaded_at' && (asc ? <ArrowUp style={{ width: 14, height: 14 }} /> : <ArrowDown style={{ width: 14, height: 14 }} />)}
                    </button>
                  </th>
                  <th>Sender Identity</th>
                  <th>Subject Line</th>
                  <th style={{ width: '110px' }}>
                    <button type="button" onClick={() => sort('risk_score')}>
                      Risk {sortKey === 'risk_score' && (asc ? <ArrowUp style={{ width: 14, height: 14 }} /> : <ArrowDown style={{ width: 14, height: 14 }} />)}
                    </button>
                  </th>
                  <th style={{ width: '150px' }}>Classification</th>
                  <th style={{ width: '150px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((item) => (
                  <tr key={item.case_id}>
                    <td>
                      <span style={{ fontSize: '13px', color: '#cbd5e1' }}>{formatDate(item.uploaded_at)}</span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 700, color: '#f8fafc', fontSize: '14px' }}>
                        {item.sender_email || '—'}
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--tn-muted)', fontFamily: 'monospace' }}>
                        {item.case_id?.slice(0, 16)}…
                      </div>
                    </td>
                    <td>
                      <div style={{ color: '#e2e8f0', fontSize: '14px', maxWidth: '380px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {item.subject || '—'}
                      </div>
                    </td>
                    <td>
                      <strong style={{ fontSize: '17px', color: '#f8fafc' }}>
                        {item.risk_score ?? '—'}
                      </strong>
                      <span style={{ fontSize: '12px', color: 'var(--tn-muted)', marginLeft: '2px' }}>/100</span>
                    </td>
                    <td>
                      <span className={`tn-badge ${getBadgeColor(item.classification)}`} style={{ padding: '4px 10px', fontSize: '12px' }}>
                        {item.classification || 'Unknown'}
                      </span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        type="button"
                        className="view-btn"
                        onClick={() => onOpenCase(item.case_id)}
                      >
                        <Eye /> Open Case
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </section>
  );
}

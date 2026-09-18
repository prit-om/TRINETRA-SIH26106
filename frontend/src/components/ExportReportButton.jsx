import { FileText, RefreshCw } from 'lucide-react';
import { API_BASE_URL, apiFetch } from '../api';
import { useState } from 'react';

export default function ExportReportButton({ caseId, disabled }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const exportReport = async () => {
    if (disabled || busy || !caseId) return;
    setBusy(true); setMessage('');
    try {
      // The current FastAPI backend exposes /cases/{case_id}/report.pdf.
      const response = await apiFetch(`/cases/${encodeURIComponent(caseId)}/report.pdf`, { method: 'GET' });
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `trinetra-${caseId}.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      setMessage(error.message || `Report service unavailable at ${API_BASE_URL}.`);
    } finally { setBusy(false); }
  };
  return <div className="tn-export-action"><button type="button" onClick={exportReport} disabled={disabled || busy} className="tn-secondary-button" title={disabled ? 'Backend health check has not succeeded' : 'Generate and download the PDF forensic report'}>{busy ? <RefreshCw className="tn-spin" /> : <FileText />} {busy ? 'Generating…' : 'Export PDF Report'}</button>{message && <span className="tn-export-error">{message}</span>}</div>;
}

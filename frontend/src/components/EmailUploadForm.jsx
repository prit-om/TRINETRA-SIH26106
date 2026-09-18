import { useRef, useState } from 'react';
import { FileText, RefreshCw, ShieldAlert, UploadCloud, XCircle } from 'lucide-react';
import { apiFetch } from '../api';

const SCENARIOS = [
  {
    id: 'bec',
    name: 'Scenario 1: Executive BEC Fraud',
    color: '#fb7185',
    tag: 'Critical',
    data: `From: John Smith <ceo@company-example.com>
Return-Path: <bounce@fakecompany.net>
Reply-To: attacker@fakecompany.net
Subject: Urgent Wire Transfer Needed
Date: Mon, 14 Sep 2026 10:00:00 +0530
Received: from attacker.example (185.220.101.5) by mail.company-example.com; Mon, 14 Sep 2026 10:00:00 +0530
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Urgent wire transfer needed immediately. Please review http://bit.ly/xyz123 , http://hacker.co/hack12`
  },
  {
    id: 'sbi',
    name: 'Scenario 2: Bank KYC Phishing',
    color: '#fbbf24',
    tag: 'Phishing',
    data: `From: ABC Bank of India Alerts <service@abc-kyc-update.com>
Return-Path: <no-reply@abc-kyc-update.com>
Reply-To: support@abc-kyc-update.com
Subject: Mandatory ABC PAN-Aadhaar KYC Verification
Date: Tue, 15 Sep 2026 14:30:00 +0530
Received: from mail.abc-kyc-update.com (198.51.100.20) by mx.target.in; Tue, 15 Sep 2026 14:30:00 +0530
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Dear Customer,
Your ABC bank account privileges will be suspended within 24 hours.
Please complete your mandatory PAN-Aadhaar KYC link update immediately at:
http://bca-portal-verify.in/kyc/update

ABC Bank of India Security Division`,
  },
  {
    id: 'clean',
    name: 'Scenario 3: Clean Corporate Notice',
    color: '#34d399',
    tag: 'Safe',
    data: `From: HR Operations <hr@corporate-legit.com>
Return-Path: <hr@corporate-legit.com>
Reply-To: hr@corporate-legit.com
Subject: Quarterly All-Hands Meeting Schedule
Date: Wed, 16 Sep 2026 09:00:00 +0530
Received: from mail.corporate-legit.com (192.0.2.10) by mail.target.in; Wed, 16 Sep 2026 09:00:00 +0530
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hello Team,
Our quarterly company-wide review will be held tomorrow at 3:00 PM IST in Conference Room A.
Attendance is optional for remote interns.
Best regards,
People & Culture Team`,
  },
];

export default function EmailUploadForm({ onSuccess }) {
  const [rawInput, setRawInput] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const fileRef = useRef(null);

  const clearFile = () => { setSelectedFile(null); if (fileRef.current) fileRef.current.value = ''; };
  const chooseFile = (event) => { const file = event.target.files?.[0] || null; setSelectedFile(file); if (file) setRawInput(''); setError(''); };

  const loadScenario = (scenarioData) => {
    clearFile();
    setRawInput(scenarioData.trim());
    setError('');
  };

  const submit = async (event) => {
    event.preventDefault();
    if (!selectedFile && !rawInput.trim()) { setError('Provide raw email content or select an email artifact first.'); return; }
    setLoading(true); setError('');
    try {
      const form = new FormData();
      if (selectedFile) form.append('file', selectedFile); else form.append('raw_text', rawInput);
      const response = await apiFetch('/analyze', { method: 'POST', body: form });
      const data = await response.json();
      onSuccess(data);
    } catch (err) { setError(err.message || 'Analysis failed. Check the backend connection and server logs.'); }
    finally { setLoading(false); }
  };

  return <section className="tn-upload-shell"><div className="tn-card tn-form-card">
    <div className="tn-page-heading">
      <div>
        <h2>Ingest & Parser</h2>
        <p>Start a real forensic investigation using the FastAPI analysis pipeline. Select a quick demo preset or upload an email artifact.</p>
      </div>
      <ShieldAlert className="text-[#2FB6C9]" />
    </div>

    {/* Quick Load Demo Presets */}
    <div style={{ marginBottom: '18px', padding: '16px 18px', background: 'rgba(11, 24, 46, 0.75)', border: '1px solid var(--tn-border)', borderRadius: '12px' }}>
      <div style={{ fontSize: '13px', fontWeight: 800, letterSpacing: '0.08em', color: 'var(--tn-cyan)', marginBottom: '12px', textTransform: 'uppercase' }}>
        ⚡ Quick Load Demo Presets (SIH Jury Presentation)
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px' }}>
        {SCENARIOS.map((s) => (
          <button
            key={s.id}
            type="button"
            className="tn-file-button"
            style={{ fontSize: '13px', padding: '9px 16px', borderLeft: `4px solid ${s.color}` }}
            onClick={() => loadScenario(s.data)}
            disabled={loading}
          >
            <strong>{s.name}</strong>
          </button>
        ))}
      </div>
    </div>

    <form onSubmit={submit} className="tn-input-zone">
      <textarea value={rawInput} onChange={(e) => { setRawInput(e.target.value); if (selectedFile) clearFile(); }} disabled={loading || Boolean(selectedFile)} placeholder="Paste raw RFC 5322/MIME content here or load a preset scenario above…" />
      <div className="tn-upload-row"><div><input ref={fileRef} hidden type="file" accept=".eml,.msg,.txt,message/rfc822,text/plain" onChange={chooseFile} /><button type="button" className="tn-file-button" onClick={() => fileRef.current?.click()} disabled={loading}><UploadCloud /> Choose .eml / .msg / .txt</button>{selectedFile && <span className="tn-selected-file"><FileText />{selectedFile.name}<button type="button" onClick={clearFile} aria-label="Remove selected file"><XCircle /></button></span>}</div><span>multipart/form-data · raw_text or file</span></div>
      {error && <div className="tn-alert tn-alert-error"><XCircle /><span>{error}</span></div>}
      <div className="tn-form-footer"><span>Local-first evidence · backend-held API keys · graceful failure states</span><button type="submit" className="tn-primary-button" disabled={loading}>{loading ? <RefreshCw className="tn-spin" /> : <ShieldAlert />}{loading ? 'Analyzing…' : 'Run Forensic Analysis'}</button></div>
    </form>
  </div></section>;
}

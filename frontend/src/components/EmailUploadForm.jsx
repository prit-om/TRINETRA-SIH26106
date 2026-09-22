import { useRef, useState } from 'react';
import { Cpu, FileText, RefreshCw, ShieldAlert, ShieldCheck, UploadCloud, XCircle } from 'lucide-react';
import { apiFetch } from '../api';

export default function EmailUploadForm({ onSuccess }) {
  const [rawInput, setRawInput] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [airGapped, setAirGapped] = useState(false);
  const fileRef = useRef(null);

  const clearFile = () => { setSelectedFile(null); if (fileRef.current) fileRef.current.value = ''; };
  const chooseFile = (event) => { const file = event.target.files?.[0] || null; setSelectedFile(file); if (file) setRawInput(''); setError(''); };

  const submit = async (event) => {
    event.preventDefault();
    if (!selectedFile && !rawInput.trim()) { setError('Provide raw email content or select an email artifact first.'); return; }
    setLoading(true); setError('');
    try {
      const form = new FormData();
      if (selectedFile) form.append('file', selectedFile); else form.append('raw_text', rawInput);
      form.append('air_gapped', airGapped ? 'true' : 'false');
      const response = await apiFetch('/analyze', { method: 'POST', body: form });
      const data = await response.json();
      onSuccess(data);
    } catch (err) { setError(err.message || 'Analysis failed. Check the backend connection and server logs.'); }
    finally { setLoading(false); }
  };

  return <section className="tn-upload-shell"><div className="tn-card tn-form-card">
    <div className="tn-page-heading">
      <div>
        <h2>Ingest &amp; Parser</h2>
        <p>Start a real forensic investigation using the FastAPI analysis pipeline. Upload an email artifact (.eml, .msg, .txt) or paste raw RFC 5322 MIME content.</p>
      </div>
      <ShieldAlert className="text-[#2FB6C9]" />
    </div>

    <form onSubmit={submit} className="tn-input-zone">
      {/* Engine & Sovereignty Selector */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '12px',
        background: 'rgba(15, 23, 42, 0.65)',
        border: airGapped ? '1px solid rgba(16, 185, 129, 0.35)' : '1px solid rgba(56, 189, 248, 0.25)',
        borderRadius: '10px',
        padding: '12px 16px',
        marginBottom: '16px',
        transition: 'all 0.2s'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {airGapped ? (
            <ShieldCheck style={{ color: '#10b981', width: '22px', height: '22px', flexShrink: 0 }} />
          ) : (
            <Cpu style={{ color: '#38bdf8', width: '22px', height: '22px', flexShrink: 0 }} />
          )}
          <div>
            <div style={{ fontSize: '13px', fontWeight: '700', color: airGapped ? '#34d399' : '#38bdf8', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <span>{airGapped ? 'Air-Gapped Sovereign Mode' : 'Hybrid Dual-Engine Mode'}</span>
              <span style={{
                fontSize: '10px',
                fontWeight: '800',
                padding: '2px 7px',
                borderRadius: '999px',
                background: airGapped ? 'rgba(16, 185, 129, 0.18)' : 'rgba(56, 189, 248, 0.18)',
                color: airGapped ? '#10b981' : '#38bdf8',
                border: `1px solid ${airGapped ? 'rgba(16, 185, 129, 0.4)' : 'rgba(56, 189, 248, 0.4)'}`,
                letterSpacing: '0.05em'
              }}>
                {airGapped ? 'ZERO DATA EXFILTRATION' : 'CLOUD GEMINI + LOCAL FAILOVER'}
              </span>
            </div>
            <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '2px' }}>
              {airGapped
                ? 'Emails analyzed strictly on-premise (Local LLM / Heuristics). Zero external network egress.'
                : 'Primary analysis via Google Gemini API with automatic instant fallback to on-premise engine.'}
            </div>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setAirGapped(!airGapped)}
          style={{
            padding: '6px 14px',
            fontSize: '12px',
            fontWeight: '700',
            borderRadius: '7px',
            cursor: 'pointer',
            transition: 'all 0.2s',
            border: airGapped ? '1px solid #10b981' : '1px solid rgba(148, 163, 184, 0.3)',
            background: airGapped ? 'rgba(16, 185, 129, 0.2)' : 'rgba(30, 41, 59, 0.6)',
            color: airGapped ? '#6ee7b7' : '#94a3b8'
          }}
        >
          {airGapped ? 'Switch to Hybrid Mode' : 'Enable Air-Gapped Mode'}
        </button>
      </div>

      <textarea value={rawInput} onChange={(e) => { setRawInput(e.target.value); if (selectedFile) clearFile(); }} disabled={loading || Boolean(selectedFile)} placeholder="Paste raw RFC 5322/MIME content here…" />
      <div className="tn-upload-row"><div><input ref={fileRef} hidden type="file" accept=".eml,.msg,.txt,message/rfc822,text/plain" onChange={chooseFile} /><button type="button" className="tn-file-button" onClick={() => fileRef.current?.click()} disabled={loading}><UploadCloud /> Choose .eml / .msg / .txt</button>{selectedFile && <span className="tn-selected-file"><FileText />{selectedFile.name}<button type="button" onClick={clearFile} aria-label="Remove selected file"><XCircle /></button></span>}</div><span>multipart/form-data · raw_text or file</span></div>
      {error && <div className="tn-alert tn-alert-error"><XCircle /><span>{error}</span></div>}
      <div className="tn-form-footer"><span>Local-first evidence · backend-held API keys · sovereign fallback</span><button type="submit" className="tn-primary-button" disabled={loading}>{loading ? <RefreshCw className="tn-spin" /> : <ShieldAlert />}{loading ? 'Analyzing…' : 'Run Forensic Analysis'}</button></div>
    </form>
  </div></section>;
}

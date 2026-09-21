import { useRef, useState } from 'react';
import { FileText, RefreshCw, ShieldAlert, UploadCloud, XCircle } from 'lucide-react';
import { apiFetch } from '../api';

export default function EmailUploadForm({ onSuccess }) {
  const [rawInput, setRawInput] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
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
      <textarea value={rawInput} onChange={(e) => { setRawInput(e.target.value); if (selectedFile) clearFile(); }} disabled={loading || Boolean(selectedFile)} placeholder="Paste raw RFC 5322/MIME content here…" />
      <div className="tn-upload-row"><div><input ref={fileRef} hidden type="file" accept=".eml,.msg,.txt,message/rfc822,text/plain" onChange={chooseFile} /><button type="button" className="tn-file-button" onClick={() => fileRef.current?.click()} disabled={loading}><UploadCloud /> Choose .eml / .msg / .txt</button>{selectedFile && <span className="tn-selected-file"><FileText />{selectedFile.name}<button type="button" onClick={clearFile} aria-label="Remove selected file"><XCircle /></button></span>}</div><span>multipart/form-data · raw_text or file</span></div>
      {error && <div className="tn-alert tn-alert-error"><XCircle /><span>{error}</span></div>}
      <div className="tn-form-footer"><span>Local-first evidence · backend-held API keys · graceful failure states</span><button type="submit" className="tn-primary-button" disabled={loading}>{loading ? <RefreshCw className="tn-spin" /> : <ShieldAlert />}{loading ? 'Analyzing…' : 'Run Forensic Analysis'}</button></div>
    </form>
  </div></section>;
}

import { FileCheck, FileWarning, Paperclip } from 'lucide-react';
import { formatBytes } from '../utils';

export default function AttachmentFindingsCard({ findings = [] }) {
  return <div className="tn-subcard">
    <div className="tn-card-title"><Paperclip /> Attachment Findings</div>
    {!findings.length ? <div className="tn-empty-inline">No attachments found.</div> : <div className="tn-attachment-list">{findings.map((item, i) => <div className="tn-attachment" key={`${item.filename}-${i}`}><div className="tn-attachment-main"><strong>{item.filename || 'Unnamed attachment'}</strong><span>{item.file_type || 'Unknown type'} · {formatBytes(item.file_size_bytes)}</span><code>SHA-256 {item.file_hash_sha256 || '—'}</code></div><span className={`tn-mini-badge ${item.hash_reputation_flagged ? 'danger' : 'good'}`}>{item.hash_reputation_flagged ? <><FileWarning /> Flagged</> : <><FileCheck /> Clean</>}</span></div>)}</div>}
  </div>;
}

import { useEffect, useState } from 'react';
import { Activity, CheckCircle2, FileSearch, FolderClock, RefreshCw, ShieldAlert, UploadCloud, XCircle } from 'lucide-react';
import { API_BASE_URL, apiFetch } from '../api';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Analysis', icon: FileSearch },
  { id: 'parser', label: 'Ingest & Parser', icon: UploadCloud },
  { id: 'history', label: 'Case History', icon: FolderClock },
  { id: 'monitor', label: 'Live Monitor', icon: Activity },
];

export default function Header({ activeTab, setActiveTab, onHealthChange }) {
  const [health, setHealth] = useState('checking');

  useEffect(() => {
    let cancelled = false;
    const checkHealth = async () => {
      try {
        const response = await apiFetch('/health', { cache: 'no-store' });
        if (!cancelled) setHealth(response.ok ? 'connected' : 'unreachable');
      } catch {
        if (!cancelled) setHealth('unreachable');
      }
    };
    checkHealth();
    const interval = window.setInterval(checkHealth, 30000);
    return () => { cancelled = true; window.clearInterval(interval); };
  }, []);

  useEffect(() => {
    onHealthChange?.(health === 'connected');
  }, [health, onHealthChange]);

  const statusText = health === 'checking' ? 'Checking' : health === 'connected' ? 'Connected' : 'Unreachable';

  return (
    <header className="tn-header">
      <div className="tn-brand-block">
        <div className="tn-brand-mark"><ShieldAlert /></div>
        <div className="tn-brand-copy">
          <div className="tn-brand-name">TRINETRA</div>
          <div className="tn-brand-tagline">AI-Powered Email Threat Detection &amp; Forensic Intelligence Platform</div>
          <div className="tn-api-chip"><span>API</span><code>{API_BASE_URL}</code></div>
        </div>
      </div>

      <div className="tn-header-actions">
        <nav className="tn-nav" aria-label="Primary navigation">
          {NAV_ITEMS.map(({ id, label, icon: Icon }) => (
            <button key={id} type="button" onClick={() => setActiveTab(id)} className={`tn-nav-item ${activeTab === id ? 'is-active' : ''}`}>
              <Icon />
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <div className={`tn-health ${health}`} title={`Backend health: ${statusText}`}>
          {health === 'checking' ? <RefreshCw className="tn-spin" /> : health === 'connected' ? <CheckCircle2 /> : <XCircle />}
          <span>Backend</span>
          <strong>{statusText}</strong>
        </div>
      </div>
    </header>
  );
}

import { useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  FileSearch,
  Fingerprint,
  Link2,
  Network,
  Paperclip,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Server,
  Route,
  ExternalLink,
  Layers,
  LayoutGrid,
  Sparkles,
  Download,
} from 'lucide-react';
import { apiFetch } from '../api';
import { getBadgeColor, getRiskTextColor } from '../utils';
import HeaderAuthenticationCard from './HeaderAuthenticationCard';
import RiskSummaryCard from './RiskSummaryCard';
import NLPBehavioralCard from './NLPBehavioralCard';
import GeolocationCard from './GeolocationCard';
import AttachmentFindingsCard from './AttachmentFindingsCard';
import EvidencePackageCard from './EvidencePackageCard';
import UrlFindingsCard from './UrlFindingsCard';
import ExportReportButton from './ExportReportButton';
import RelayTraceCard from './RelayTraceCard';
import GraphIntelCard from './GraphIntelCard';
import AttributionEngineCard from './AttributionEngineCard';
import DomainIntelligenceCard from './DomainIntelligenceCard';

const DEMO_PRESETS = [
  {
    id: 'bec',
    name: 'Executive BEC Fraud',
    desc: 'Spoofed CEO wire transfer with reply-to mismatch & malicious URLs',
    badge: 'Critical',
    badgeColor: 'bg-rose-950',
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
    name: 'Bank KYC Phishing',
    desc: 'Indian banking credential harvest impersonation with fake portal',
    badge: 'Phishing',
    badgeColor: 'bg-amber-950',
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

ABC Bank of India Security Division`
  },
  {
    id: 'clean',
    name: 'Clean Corporate Notice',
    desc: 'Legitimate internal HR notice with matching Return-Path',
    badge: 'Safe',
    badgeColor: 'bg-emerald-950',
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
People & Culture Team`
  }
];

export default function AnalysisView({ report, setActiveTab, backendHealthy, onSelectReport }) {
  const [activeSection, setActiveSection] = useState('overview');
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  const [demoLoading, setDemoLoading] = useState(false);
  const [demoError, setDemoError] = useState('');

  const handleVerify = async () => {
    if (!report?.case_id) return;
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await apiFetch(`/cases/${encodeURIComponent(report.case_id)}/verify`);
      const data = await res.json();
      setVerifyResult(data);
    } catch (err) {
      setVerifyResult({ valid: false, error: err.message || 'Verification failed' });
    } finally {
      setVerifying(false);
    }
  };

  const handleRunPreset = async (presetText) => {
    setDemoLoading(true);
    setDemoError('');
    try {
      const form = new FormData();
      form.append('raw_text', presetText.trim());
      const response = await apiFetch('/analyze', { method: 'POST', body: form });
      const data = await response.json();
      if (onSelectReport) {
        onSelectReport(data);
      }
    } catch (err) {
      setDemoError(err.message || 'Quick demo analysis failed.');
    } finally {
      setDemoLoading(false);
    }
  };

  if (!report) {
    return (
      <div className="tn-empty-workspace">
        <div className="tn-empty-icon">
          <FileSearch />
        </div>
        <div>
          <span className="tn-kicker">FORENSIC CASE WORKSPACE</span>
          <h2>No Forensic Case Analyzed Yet</h2>
          <p>
            Upload an email artifact (.eml, .msg, .txt) or click any preset attack scenario below to run a real-time investigation.
          </p>

          <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
            <button
              type="button"
              className="tn-primary-button"
              onClick={() => setActiveTab('parser')}
            >
              <FileSearch /> Open Ingest & Parser
            </button>
          </div>

          {demoError && (
            <div className="tn-alert tn-alert-error" style={{ marginTop: '16px' }}>
              <AlertCircle /> <span>{demoError}</span>
            </div>
          )}

          <div className="tn-empty-presets">
            <div className="tn-preset-label">⚡ Instant 1-Click Forensic Demonstrations (SIH Jury Presentation)</div>
            <div className="tn-preset-row">
              {DEMO_PRESETS.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  className="tn-preset-chip"
                  onClick={() => handleRunPreset(preset.data)}
                  disabled={demoLoading}
                >
                  <span className={`tn-badge ${preset.badgeColor}`} style={{ padding: '2px 8px', fontSize: '11px' }}>
                    {preset.badge}
                  </span>
                  <span>{preset.name}</span>
                  {demoLoading && <RefreshCw className="tn-spin" style={{ width: 14, height: 14 }} />}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  const urlCount = report.url_findings?.length || 0;
  const attachmentCount = report.attachment_findings?.length || 0;
  const graphNodes = report.graph?.nodes?.length || 0;
  const hops = report.relay_forensics?.hop_count || report.relay_forensics?.hops?.length || 0;
  const hash = report.evidence?.sha256 || report.evidence_sha256;
  const score = Math.max(0, Math.min(100, Number(report?.risk_score) || 0));

  return (
    <div className="tn-analysis">
      {/* Workspace Top Meta Bar */}
      <div className="tn-workspace-bar">
        <div>
          <span className="tn-kicker">ACTIVE INVESTIGATION WORKSPACE</span>
          <code>CASE {report.case_id}</code>
          <div className="tn-case-context">
            <strong>From:</strong>
            <span>{report.sender_email || 'Sender unavailable'}</span>
            <b>·</b>
            <strong>Subject:</strong>
            <span>{report.subject || 'No subject'}</span>
          </div>
        </div>
        <div className="tn-stat-strip">
          <span><Link2 /> {urlCount} URLs</span>
          <span><Paperclip /> {attachmentCount} Attachments</span>
          <span><Network /> {graphNodes} Graph Nodes</span>
          <span><Fingerprint /> {hops} Relay Hops</span>
        </div>
      </div>

      {/* Executive Hero Banner / Primary Verdict */}
      <section className="tn-card tn-hero-verdict">
        <div className="tn-hero-content">
          <div className="tn-hero-left">
            <div className="tn-hero-badge-row">
              <span className={`tn-badge ${getBadgeColor(report.classification)}`}>
                <ShieldAlert /> {report.classification || 'Unknown Risk'}
              </span>
              <span className="tn-title-chip" style={{ fontSize: '12px' }}>
                SECTION 63 BSA 2023 COMPLIANT
              </span>
            </div>
            <h2 style={{ fontSize: '20px', fontWeight: 800, color: '#f8fafc', margin: '6px 0 10px', lineHeight: 1.4 }}>
              {report.summary || 'No forensic summary available.'}
            </h2>
            <div className="tn-meta-line" style={{ fontSize: '13px' }}>
              Cryptographic Seal: <span style={{ fontFamily: 'monospace', color: '#7dd3fc' }}>{hash ? `${hash.slice(0, 24)}…${hash.slice(-16)}` : 'SHA-256 seal pending'}</span>
            </div>

            {/* Quick Actions in Hero */}
            <div className="tn-hero-actions">
              <ExportReportButton caseId={report.case_id} disabled={!backendHealthy} />
              <button
                type="button"
                className="tn-secondary-button"
                onClick={handleVerify}
                disabled={verifying}
              >
                {verifying ? <RefreshCw className="tn-spin" /> : <ShieldCheck />}
                {verifying ? 'Verifying Seal…' : 'Verify Evidence Hash'}
              </button>
              {verifyResult && (
                <span
                  style={{
                    padding: '8px 14px',
                    borderRadius: '8px',
                    fontSize: '13px',
                    fontWeight: 700,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '7px',
                    background: verifyResult.valid ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                    color: verifyResult.valid ? '#34d399' : '#f87171',
                    border: `1.5px solid ${verifyResult.valid ? '#10b981' : '#ef4444'}`,
                  }}
                >
                  {verifyResult.valid ? <CheckCircle2 style={{ width: 16, height: 16 }} /> : <AlertCircle style={{ width: 16, height: 16 }} />}
                  {verifyResult.valid ? 'SHA-256 Integrity Sealed (Untampered)' : `Tamper Warning: ${verifyResult.error || 'Mismatch'}`}
                </span>
              )}
            </div>
          </div>

          {/* Right Risk Ring */}
          <div className="tn-risk-score" style={{ borderLeft: '1.5px solid var(--tn-border)' }}>
            <div className={`tn-score-ring ${getRiskTextColor(score)}`} style={{ '--tn-score': `${score * 3.6}deg` }}>
              <div>
                <strong>{score}</strong>
                <span>/100</span>
              </div>
            </div>
            <span>TOTAL RISK</span>
          </div>
        </div>
      </section>

      {/* Investigation Section Navigation Tabs */}
      <nav className="tn-investigation-tabs" aria-label="Investigation sections">
        <button
          type="button"
          className={`tn-tab-btn ${activeSection === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveSection('overview')}
        >
          <Layers /> 🎯 Overview & 3-Layer Evidence
        </button>
        <button
          type="button"
          className={`tn-tab-btn ${activeSection === 'headers' ? 'active' : ''}`}
          onClick={() => setActiveSection('headers')}
        >
          <Fingerprint /> 🔍 Headers & Relay Trace
        </button>
        <button
          type="button"
          className={`tn-tab-btn ${activeSection === 'geo' ? 'active' : ''}`}
          onClick={() => setActiveSection('geo')}
        >
          <Server /> 🗺️ GeoIP & Infrastructure
        </button>
        <button
          type="button"
          className={`tn-tab-btn ${activeSection === 'graph' ? 'active' : ''}`}
          onClick={() => setActiveSection('graph')}
        >
          <Network /> 🕸️ Campaign Graph & Attribution
        </button>
        <button
          type="button"
          className={`tn-tab-btn ${activeSection === 'files' ? 'active' : ''}`}
          onClick={() => setActiveSection('files')}
        >
          <ExternalLink /> 📂 URLs & Attachments
        </button>
        <button
          type="button"
          className={`tn-tab-btn ${activeSection === 'all' ? 'active' : ''}`}
          onClick={() => setActiveSection('all')}
        >
          <LayoutGrid /> 📊 Full SOC Dashboard (All Signals)
        </button>
      </nav>

      {/* SECTION CONTENT BASED ON SELECTED TAB */}
      {activeSection === 'overview' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <EvidencePackageCard evidence={report.evidence_package} />
          <div className="tn-split-grid">
            <NLPBehavioralCard analysis={report.nlp_analysis} />
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <HeaderAuthenticationCard analysis={report.header_analysis} />
              <AttributionEngineCard attribution={report.attribution} geolocation={report.geolocation} />
            </div>
          </div>
        </div>
      )}

      {activeSection === 'headers' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div className="tn-split-grid">
            <HeaderAuthenticationCard analysis={report.header_analysis} />
            <section className="tn-card tn-detail-card">
              <div className="tn-card-title"><ShieldCheck /> Evidence Sealing Details</div>
              <div className="tn-hash">{hash || 'SHA-256 unavailable'}</div>
              <div className="tn-meta-line">{report.evidence?.byte_length ?? '—'} raw bytes preserved before redaction</div>
              <div className="tn-meta-line">PII Findings: {(report.pii_detected || []).join(', ') || 'None (Safe)'}</div>
            </section>
          </div>
          <RelayTraceCard relay={report.relay_forensics} />
        </div>
      )}

      {activeSection === 'geo' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <GeolocationCard geolocation={report.geolocation} />
          <DomainIntelligenceCard findings={report.domain_intelligence} />
        </div>
      )}

      {activeSection === 'graph' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <GraphIntelCard graph={report.graph} relatedCaseIds={report.related_case_ids} />
          <AttributionEngineCard attribution={report.attribution} geolocation={report.geolocation} />
        </div>
      )}

      {activeSection === 'files' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <UrlFindingsCard findings={report.url_findings} />
          <AttachmentFindingsCard findings={report.attachment_findings} />
          <DomainIntelligenceCard findings={report.domain_intelligence} />
        </div>
      )}

      {activeSection === 'all' && (
        <div className="tn-dashboard-grid">
          <aside className="tn-column tn-left-column">
            <section className="tn-card tn-ingest-card">
              <div className="tn-card-title"><FileSearch /> New Ingest</div>
              <button type="button" className="tn-ingest-button" onClick={() => setActiveTab('parser')}>
                <FileSearch />
                <strong>Ingest a new email artifact</strong>
                <span>.eml / .msg / .txt / raw MIME</span>
              </button>
              <HeaderAuthenticationCard analysis={report.header_analysis} />
            </section>
            <section className="tn-card tn-detail-card">
              <div className="tn-card-title"><ShieldCheck /> Evidence Integrity</div>
              <div className="tn-hash">{hash || 'SHA-256 unavailable'}</div>
              <div className="tn-meta-line">{report.evidence?.byte_length ?? '—'} bytes sealed</div>
              <div className="tn-meta-line">PII: {(report.pii_detected || []).join(', ') || 'none'}</div>
            </section>
            <AttachmentFindingsCard findings={report.attachment_findings} />
          </aside>

          <main className="tn-column tn-center-column">
            <NLPBehavioralCard analysis={report.nlp_analysis} />
            <EvidencePackageCard evidence={report.evidence_package} />
            <div className="tn-split-grid">
              <RelayTraceCard relay={report.relay_forensics} />
              <UrlFindingsCard findings={report.url_findings} />
            </div>
            <DomainIntelligenceCard findings={report.domain_intelligence} />
          </main>

          <aside className="tn-column tn-right-column">
            <GeolocationCard geolocation={report.geolocation} />
            <GraphIntelCard graph={report.graph} relatedCaseIds={report.related_case_ids} />
            <AttributionEngineCard attribution={report.attribution} geolocation={report.geolocation} />
          </aside>
        </div>
      )}
    </div>
  );
}

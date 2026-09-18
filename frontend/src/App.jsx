import { useCallback, useState } from 'react';
import Header from './components/Header';
import EmailUploadForm from './components/EmailUploadForm';
import AnalysisView from './components/AnalysisView';
import CaseHistory from './components/CaseHistory';
import MonitoringPanel from './components/MonitoringPanel';
import { apiFetch } from './api';

export default function App() {
  const [report, setReport] = useState(null);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [backendHealthy, setBackendHealthy] = useState(false);
  const [caseLoading, setCaseLoading] = useState(false);
  const [caseError, setCaseError] = useState('');

  const openCase = useCallback(async (caseId) => {
    setCaseLoading(true);
    setCaseError('');
    try {
      const response = await apiFetch(`/cases/${encodeURIComponent(caseId)}`);
      setReport(await response.json());
      setActiveTab('dashboard');
    } catch (error) {
      setCaseError(error.message || 'Unable to open this forensic case.');
    } finally {
      setCaseLoading(false);
    }
  }, []);

  const handleAnalysisSuccess = useCallback((data) => {
    setReport(data);
    setCaseError('');
    setActiveTab('dashboard');
  }, []);

  return (
    <div className="tn-app-shell">
      <div className="tn-bg-orb tn-bg-orb-a" />
      <div className="tn-bg-orb tn-bg-orb-b" />
      <main className="tn-app-container">
        <Header activeTab={activeTab} setActiveTab={setActiveTab} onHealthChange={setBackendHealthy} />

        {caseError && (
          <div className="tn-alert tn-alert-error" role="alert">
            <strong>Case request failed.</strong>
            <span>{caseError}</span>
          </div>
        )}

        {caseLoading ? (
          <div className="tn-loading-card">
            <div className="tn-spinner" />
            <strong>Loading forensic case</strong>
            <span>Retrieving the stored evidence package…</span>
          </div>
        ) : activeTab === 'parser' ? (
          <EmailUploadForm onSuccess={handleAnalysisSuccess} />
        ) : activeTab === 'history' ? (
          <CaseHistory onOpenCase={openCase} />
        ) : activeTab === 'monitor' ? (
          <MonitoringPanel />
        ) : (
          <AnalysisView report={report} setActiveTab={setActiveTab} backendHealthy={backendHealthy} onSelectReport={handleAnalysisSuccess} />
        )}
      </main>
    </div>
  );
}

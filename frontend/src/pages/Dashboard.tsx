import { useEffect } from 'react';
import { Link } from 'react-router-dom';
import Button from '../components/common/Button';
import { useDomainStore, useScanStore } from '../store';
import LiveStatsCards from '../components/dashboard/LiveStatsCards';
import LiveScanProgress from '../components/dashboard/LiveScanProgress';
import LiveSubdomainFeed from '../components/dashboard/LiveSubdomainFeed';
import LiveVulnerabilityFeed from '../components/dashboard/LiveVulnerabilityFeed';

const Dashboard = () => {
  const { domains, fetchDomains, isLoading, error } = useDomainStore();
  const { scans, fetchScans } = useScanStore();

  useEffect(() => {
    fetchDomains();
    fetchScans();
  }, [fetchDomains, fetchScans]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-2xl font-bold text-blue-600">Loading Dashboard...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="bg-red-100 border border-red-400 text-red-700 px-6 py-4 rounded-lg max-w-2xl">
          <h2 className="text-xl font-bold mb-2">⚠️ Connection Error</h2>
          <p className="mb-2">{error}</p>
          <p className="text-sm">
            Make sure the backend API is running on http://localhost:8000
          </p>
          <button
            onClick={() => fetchDomains()}
            className="mt-4 bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const runningScans = scans.filter((s) => s.status === 'running');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-3xl font-bold text-gray-900 dark:text-white">
            Live Dashboard
          </h2>
          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
            Real-time monitoring of reconnaissance operations
          </p>
        </div>
        <Link to="/domains">
          <Button>View All Domains</Button>
        </Link>
      </div>

      {/* Live Statistics Cards */}
      <LiveStatsCards
        initialStats={{
          totalDomains: domains.length,
          totalSubdomains: 0,
          totalVulnerabilities: 0,
          runningScans: runningScans.length
        }}
      />

      {/* Live Scan Progress */}
      <LiveScanProgress />

      {/* Two-column layout for feeds */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Live Subdomain Feed */}
        <LiveSubdomainFeed maxItems={50} />

        {/* Live Vulnerability Feed */}
        <LiveVulnerabilityFeed maxItems={20} />
      </div>

      {/* Info Card */}
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <div className="text-2xl">ℹ️</div>
          <div>
            <h3 className="font-semibold text-blue-900 dark:text-blue-100 mb-1">
              Real-Time Updates
            </h3>
            <p className="text-sm text-blue-800 dark:text-blue-200">
              This dashboard connects to the WebSocket server and displays live updates as scans progress.
              Subdomains and vulnerabilities appear as they are discovered, and scan progress updates in real-time.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

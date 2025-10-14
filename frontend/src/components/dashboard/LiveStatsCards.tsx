import { useEffect, useState } from 'react';
import { useWebSocket } from '../../hooks/useWebSocket';
import Card from '../common/Card';
import type {
  SubdomainDiscoveredMessage,
  VulnerabilityDetectedMessage,
  ScanProgress,
  ScanCompletedMessage
} from '../../types';

interface LiveStatsCardsProps {
  initialStats?: {
    totalDomains: number;
    totalSubdomains: number;
    totalVulnerabilities: number;
    runningScans: number;
  };
}

const LiveStatsCards = ({ initialStats }: LiveStatsCardsProps) => {
  const { subscribe } = useWebSocket({ autoConnect: true });

  const [stats, setStats] = useState({
    totalSubdomains: initialStats?.totalSubdomains || 0,
    totalVulnerabilities: initialStats?.totalVulnerabilities || 0,
    criticalVulnerabilities: 0,
    runningScans: initialStats?.runningScans || 0,
    completedScansToday: 0
  });

  const [recentUpdates, setRecentUpdates] = useState({
    subdomains: 0,
    vulnerabilities: 0,
    criticalVulns: 0
  });

  useEffect(() => {
    // Subscribe to subdomain discoveries
    const unsubscribeSubdomains = subscribe<SubdomainDiscoveredMessage>(
      'subdomain_discovered',
      () => {
        setStats(prev => ({ ...prev, totalSubdomains: prev.totalSubdomains + 1 }));
        setRecentUpdates(prev => ({ ...prev, subdomains: prev.subdomains + 1 }));

        // Reset recent update indicator after animation
        setTimeout(() => {
          setRecentUpdates(prev => ({ ...prev, subdomains: Math.max(0, prev.subdomains - 1) }));
        }, 2000);
      }
    );

    // Subscribe to vulnerability detections
    const unsubscribeVulns = subscribe<VulnerabilityDetectedMessage>(
      'vulnerability_detected',
      (data) => {
        setStats(prev => ({
          ...prev,
          totalVulnerabilities: prev.totalVulnerabilities + 1,
          criticalVulnerabilities: data.severity.toLowerCase() === 'critical'
            ? prev.criticalVulnerabilities + 1
            : prev.criticalVulnerabilities
        }));

        setRecentUpdates(prev => ({
          ...prev,
          vulnerabilities: prev.vulnerabilities + 1,
          criticalVulns: data.severity.toLowerCase() === 'critical'
            ? prev.criticalVulns + 1
            : prev.criticalVulns
        }));

        // Reset recent update indicator after animation
        setTimeout(() => {
          setRecentUpdates(prev => ({
            ...prev,
            vulnerabilities: Math.max(0, prev.vulnerabilities - 1),
            criticalVulns: data.severity.toLowerCase() === 'critical'
              ? Math.max(0, prev.criticalVulns - 1)
              : prev.criticalVulns
          }));
        }, 2000);
      }
    );

    // Subscribe to scan progress (to track running scans)
    const unsubscribeProgress = subscribe<ScanProgress>('scan_progress', (data) => {
      if (data.status === 'running') {
        // This is handled by the LiveScanProgress component
      }
    });

    // Subscribe to scan completion
    const unsubscribeCompleted = subscribe<ScanCompletedMessage>('scan_completed', () => {
      setStats(prev => ({
        ...prev,
        runningScans: Math.max(0, prev.runningScans - 1),
        completedScansToday: prev.completedScansToday + 1
      }));
    });

    return () => {
      unsubscribeSubdomains();
      unsubscribeVulns();
      unsubscribeProgress();
      unsubscribeCompleted();
    };
  }, [subscribe]);

  const StatCard = ({
    title,
    value,
    icon,
    color,
    isUpdating
  }: {
    title: string;
    value: number;
    icon: string;
    color: string;
    isUpdating?: boolean;
  }) => (
    <Card>
      <div className="text-center relative">
        {isUpdating && (
          <div className="absolute top-0 right-0 w-2 h-2 bg-green-500 rounded-full animate-ping" />
        )}
        <div className="text-2xl mb-2">{icon}</div>
        <div className={`text-3xl font-bold ${color} transition-all duration-300 ${isUpdating ? 'scale-110' : ''}`}>
          {value.toLocaleString()}
        </div>
        <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">
          {title}
        </div>
      </div>
    </Card>
  );

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <StatCard
        title="Total Subdomains"
        value={stats.totalSubdomains}
        icon="🌐"
        color="text-blue-600"
        isUpdating={recentUpdates.subdomains > 0}
      />

      <StatCard
        title="Running Scans"
        value={stats.runningScans}
        icon="⚡"
        color="text-green-600"
      />

      <StatCard
        title="Total Vulnerabilities"
        value={stats.totalVulnerabilities}
        icon="🔍"
        color="text-orange-600"
        isUpdating={recentUpdates.vulnerabilities > 0}
      />

      <StatCard
        title="Critical Vulnerabilities"
        value={stats.criticalVulnerabilities}
        icon="🔴"
        color="text-red-600"
        isUpdating={recentUpdates.criticalVulns > 0}
      />
    </div>
  );
};

export default LiveStatsCards;

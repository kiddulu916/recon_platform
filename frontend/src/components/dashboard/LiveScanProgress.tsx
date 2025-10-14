import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useWebSocket } from '../../hooks/useWebSocket';
import { useScanStore } from '../../store';
import Card from '../common/Card';
import Badge from '../common/Badge';
import Button from '../common/Button';
import type { ScanProgress, ScanCompletedMessage, ScanFailedMessage } from '../../types';

interface RunningScanInfo extends ScanProgress {
  domain_id?: number;
}

const LiveScanProgress = () => {
  const { updateScanProgress } = useScanStore();
  const { subscribe, isConnected } = useWebSocket({ autoConnect: true });
  const [runningScans, setRunningScans] = useState<Map<number, RunningScanInfo>>(new Map());

  useEffect(() => {
    // Subscribe to scan progress updates
    const unsubscribeProgress = subscribe<ScanProgress>('scan_progress', (data) => {
      console.log('Received scan progress:', data);

      // Update scan store
      updateScanProgress(data);

      // Update local state
      setRunningScans((prev) => {
        const updated = new Map(prev);
        updated.set(data.job_id, data);
        return updated;
      });
    });

    // Subscribe to scan completion
    const unsubscribeCompleted = subscribe<ScanCompletedMessage>('scan_completed', (data) => {
      console.log('Scan completed:', data);

      // Remove from running scans
      setRunningScans((prev) => {
        const updated = new Map(prev);
        updated.delete(data.job_id);
        return updated;
      });
    });

    // Subscribe to scan failures
    const unsubscribeFailed = subscribe<ScanFailedMessage>('scan_failed', (data) => {
      console.log('Scan failed:', data);

      // Remove from running scans
      setRunningScans((prev) => {
        const updated = new Map(prev);
        updated.delete(data.job_id);
        return updated;
      });
    });

    return () => {
      unsubscribeProgress();
      unsubscribeCompleted();
      unsubscribeFailed();
    };
  }, [subscribe, updateScanProgress]);

  const getPhaseLabel = (phase: string | null | undefined): string => {
    if (!phase) return 'Initializing';

    const phaseLabels: Record<string, string> = {
      horizontal: 'Horizontal Enumeration',
      passive: 'Passive Enumeration',
      active: 'Active Enumeration',
      probing: 'Web Probing',
      web_discovery: 'Web Discovery',
      recursive: 'Recursive Enumeration'
    };

    return phaseLabels[phase] || phase;
  };

  const scansArray = Array.from(runningScans.values());

  if (scansArray.length === 0) {
    return null;
  }

  return (
    <Card
      title={
        <div className="flex items-center justify-between">
          <span>Live Scan Progress</span>
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
            <span className="text-sm font-normal text-gray-600 dark:text-gray-400">
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>
      }
    >
      <div className="space-y-4">
        {scansArray.map((scan) => (
          <div
            key={scan.job_id}
            className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 bg-white dark:bg-gray-800"
          >
            <div className="flex items-center justify-between mb-3">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <h3 className="font-semibold text-gray-900 dark:text-white">
                    Scan #{scan.job_id}
                  </h3>
                  <Badge variant="info">Running</Badge>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  {getPhaseLabel(scan.current_phase)}
                </p>
              </div>
              <Link to={`/scans/${scan.job_id}`}>
                <Button size="sm" variant="secondary">
                  View Details
                </Button>
              </Link>
            </div>

            {/* Progress Bar */}
            <div className="mb-3">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium text-gray-700 dark:text-gray-300">
                  Progress
                </span>
                <span className="text-xs font-medium text-gray-700 dark:text-gray-300">
                  {scan.progress_percentage}%
                </span>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2.5">
                <div
                  className="bg-blue-600 h-2.5 rounded-full transition-all duration-500"
                  style={{ width: `${scan.progress_percentage}%` }}
                />
              </div>
            </div>

            {/* Phase Details */}
            {scan.phase_details && (
              <div className="bg-gray-50 dark:bg-gray-900 rounded p-3 mb-3">
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-gray-600 dark:text-gray-400">Phase:</span>
                    <span className="ml-2 font-medium text-gray-900 dark:text-white">
                      {getPhaseLabel(scan.phase_details.phase)}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-600 dark:text-gray-400">Status:</span>
                    <span className="ml-2 font-medium text-gray-900 dark:text-white">
                      {scan.phase_details.status}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-600 dark:text-gray-400">Processed:</span>
                    <span className="ml-2 font-medium text-gray-900 dark:text-white">
                      {scan.phase_details.items_processed} / {scan.phase_details.items_total}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Warnings */}
            {scan.warnings && scan.warnings.length > 0 && (
              <div className="mb-2">
                <div className="text-xs font-medium text-yellow-700 dark:text-yellow-400 mb-1">
                  Warnings ({scan.warnings.length})
                </div>
                <div className="space-y-1">
                  {scan.warnings.slice(-3).map((warning, idx) => (
                    <div
                      key={idx}
                      className="text-xs text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/20 px-2 py-1 rounded"
                    >
                      {warning}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Errors */}
            {scan.errors && scan.errors.length > 0 && (
              <div>
                <div className="text-xs font-medium text-red-700 dark:text-red-400 mb-1">
                  Errors ({scan.errors.length})
                </div>
                <div className="space-y-1">
                  {scan.errors.slice(-3).map((error, idx) => (
                    <div
                      key={idx}
                      className="text-xs text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 px-2 py-1 rounded"
                    >
                      {error}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </Card>
  );
};

export default LiveScanProgress;

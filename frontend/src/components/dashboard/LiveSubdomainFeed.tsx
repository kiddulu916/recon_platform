import { useEffect, useState } from 'react';
import { useWebSocket } from '../../hooks/useWebSocket';
import Card from '../common/Card';
import Badge from '../common/Badge';
import type { SubdomainDiscoveredMessage } from '../../types';

interface SubdomainWithTimestamp extends SubdomainDiscoveredMessage {
  timestamp: string;
}

interface LiveSubdomainFeedProps {
  maxItems?: number;
  domainId?: number;
}

const LiveSubdomainFeed = ({ maxItems = 50, domainId }: LiveSubdomainFeedProps) => {
  const { subscribe, isConnected } = useWebSocket({
    domainId,
    autoConnect: true
  });
  const [discoveries, setDiscoveries] = useState<SubdomainWithTimestamp[]>([]);

  useEffect(() => {
    const unsubscribe = subscribe<SubdomainDiscoveredMessage>('subdomain_discovered', (data) => {
      console.log('Subdomain discovered:', data);

      setDiscoveries((prev) => {
        const newDiscovery: SubdomainWithTimestamp = {
          ...data,
          timestamp: new Date().toISOString()
        };

        // Add to beginning and keep only maxItems
        return [newDiscovery, ...prev].slice(0, maxItems);
      });
    });

    return unsubscribe;
  }, [subscribe, maxItems]);

  const getMethodBadgeVariant = (method: string) => {
    const variants: Record<string, 'success' | 'info' | 'warning' | 'default'> = {
      subfinder: 'success',
      assetfinder: 'info',
      amass: 'warning',
      ct_logs: 'default',
      dns_bruteforce: 'success',
      permutations: 'info'
    };
    return variants[method] || 'default';
  };

  return (
    <Card
      title={
        <div className="flex items-center justify-between">
          <span>Live Subdomain Discoveries</span>
          <div className="flex items-center gap-2">
            {discoveries.length > 0 && (
              <Badge variant="info">{discoveries.length}</Badge>
            )}
            <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
          </div>
        </div>
      }
    >
      {discoveries.length === 0 ? (
        <div className="text-center py-8 text-gray-500 dark:text-gray-400">
          <div className="mb-2">Waiting for subdomain discoveries...</div>
          <div className="text-xs">
            {isConnected ? 'Connected and listening' : 'Not connected'}
          </div>
        </div>
      ) : (
        <div className="space-y-2 max-h-96 overflow-y-auto">
          {discoveries.map((discovery, idx) => (
            <div
              key={`${discovery.subdomain_id}-${idx}`}
              className="border border-gray-200 dark:border-gray-700 rounded-lg p-3 bg-gradient-to-r from-green-50 to-transparent dark:from-green-900/10 dark:to-transparent animate-fade-in"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-sm font-semibold text-gray-900 dark:text-white truncate">
                      {discovery.subdomain}
                    </span>
                    <Badge variant={getMethodBadgeVariant(discovery.discovery_method)}>
                      {discovery.discovery_method}
                    </Badge>
                  </div>

                  {discovery.sources && discovery.sources.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {discovery.sources.map((source, sourceIdx) => (
                        <span
                          key={sourceIdx}
                          className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 rounded"
                        >
                          {source}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap">
                  {new Date(discovery.timestamp).toLocaleTimeString()}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
};

export default LiveSubdomainFeed;

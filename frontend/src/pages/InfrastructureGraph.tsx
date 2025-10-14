import { useState, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import InfrastructureGraph from '../components/graph/InfrastructureGraph';
import Card from '../components/common/Card';
import apiService from '../services/api';
import type { Domain, GraphData, GraphNode } from '../types';

const InfrastructureGraphPage = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const domainIdParam = searchParams.get('domain');
  const [selectedDomainId, setSelectedDomainId] = useState<number | null>(
    domainIdParam ? parseInt(domainIdParam) : null
  );
  const [includeIps, setIncludeIps] = useState(true);
  const [includePorts, setIncludePorts] = useState(false);
  const [resolvesOnly, setResolvesOnly] = useState(true);

  // Fetch domains list
  const { data: domainsResponse, isLoading: domainsLoading } = useQuery({
    queryKey: ['domains'],
    queryFn: () => apiService.getDomains()
  });

  // Fetch graph data
  const { data: graphData, isLoading: graphLoading, error: graphError, refetch } = useQuery({
    queryKey: ['graph', selectedDomainId, includeIps, includePorts, resolvesOnly],
    queryFn: () => {
      if (!selectedDomainId) return null;
      return apiService.getGraph(selectedDomainId, {
        include_ips: includeIps,
        include_ports: includePorts,
        resolves_only: resolvesOnly
      });
    },
    enabled: selectedDomainId !== null
  });

  // Extract domains array from response
  const domains = domainsResponse?.domains || [];

  // Update URL when domain is selected
  const handleDomainChange = (domainId: number | null) => {
    setSelectedDomainId(domainId);
    if (domainId) {
      setSearchParams({ domain: domainId.toString() });
    } else {
      setSearchParams({});
    }
  };

  // Handle node clicks
  const handleNodeClick = (node: GraphNode) => {
    console.log('Node clicked:', node);
    // You can add navigation or modal display here
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Infrastructure Graph
          </h1>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Visualize domain infrastructure, subdomains, IP addresses, and their relationships
          </p>
        </div>
      </div>

      {/* Domain Selection and Filters */}
      <Card>
        <div className="space-y-4">
          {/* Domain Selector */}
          <div>
            <label htmlFor="domain-select" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Select Domain
            </label>
            <select
              id="domain-select"
              value={selectedDomainId || ''}
              onChange={(e) => handleDomainChange(e.target.value ? parseInt(e.target.value) : null)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              disabled={domainsLoading}
            >
              <option value="">-- Select a domain --</option>
              {domains.map((domain: Domain) => (
                <option key={domain.id} value={domain.id}>
                  {domain.domain}
                </option>
              ))}
            </select>
          </div>

          {/* Filters */}
          {selectedDomainId && (
            <div className="flex flex-wrap gap-4 pt-4 border-t border-gray-200 dark:border-gray-700">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeIps}
                  onChange={(e) => setIncludeIps(e.target.checked)}
                  className="w-4 h-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500"
                />
                <span className="text-sm text-gray-700 dark:text-gray-300">Include IP Addresses</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includePorts}
                  onChange={(e) => setIncludePorts(e.target.checked)}
                  className="w-4 h-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500"
                />
                <span className="text-sm text-gray-700 dark:text-gray-300">Include Ports</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={resolvesOnly}
                  onChange={(e) => setResolvesOnly(e.target.checked)}
                  className="w-4 h-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500"
                />
                <span className="text-sm text-gray-700 dark:text-gray-300">Resolving Subdomains Only</span>
              </label>
            </div>
          )}
        </div>
      </Card>

      {/* Statistics */}
      {graphData && (
        <Card>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Graph Statistics
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                {graphData.statistics.total_nodes}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Total Nodes</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-600 dark:text-gray-400">
                {graphData.statistics.total_edges}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Total Edges</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                {graphData.statistics.subdomains}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Subdomains</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
                {graphData.statistics.ips}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">IP Addresses</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                {graphData.statistics.asns}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">ASNs</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                {graphData.statistics.ports}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Ports</div>
            </div>
          </div>
        </Card>
      )}

      {/* Graph Visualization */}
      {selectedDomainId && (
        <Card>
          {graphLoading && (
            <div className="flex items-center justify-center h-96">
              <div className="text-center">
                <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
                <p className="mt-4 text-gray-600 dark:text-gray-400">Loading graph data...</p>
              </div>
            </div>
          )}

          {graphError && (
            <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
              <p className="text-red-800 dark:text-red-200">
                Error loading graph: {graphError instanceof Error ? graphError.message : 'Unknown error'}
              </p>
            </div>
          )}

          {graphData && !graphLoading && (
            <>
              {graphData.nodes.length === 0 ? (
                <div className="text-center py-12">
                  <p className="text-gray-600 dark:text-gray-400">
                    No data available for this domain. Try running a scan first.
                  </p>
                </div>
              ) : (
                <InfrastructureGraph
                  data={graphData}
                  height="700px"
                  onNodeClick={handleNodeClick}
                />
              )}
            </>
          )}
        </Card>
      )}

      {/* No Domain Selected */}
      {!selectedDomainId && (
        <Card>
          <div className="text-center py-12">
            <svg
              className="mx-auto h-12 w-12 text-gray-400"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7"
              />
            </svg>
            <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">
              No domain selected
            </h3>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              Select a domain from the dropdown above to visualize its infrastructure.
            </p>
            <div className="mt-6">
              <Link
                to="/domains"
                className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
              >
                View All Domains
              </Link>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
};

export default InfrastructureGraphPage;

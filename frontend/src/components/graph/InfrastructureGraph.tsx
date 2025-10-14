import { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import type { Core, EdgeSingular, NodeSingular } from 'cytoscape';
import type { GraphData, GraphNode } from '../../types';

interface InfrastructureGraphProps {
  data: GraphData;
  height?: string;
  onNodeClick?: (node: GraphNode) => void;
}

const InfrastructureGraph = ({
  data,
  height = '600px',
  onNodeClick
}: InfrastructureGraphProps) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    // Initialize Cytoscape
    const cy = cytoscape({
      container: containerRef.current,
      elements: {
        nodes: data.nodes.map(node => ({
          data: {
            id: node.id,
            label: node.label,
            type: node.type,
            ...node.data
          }
        })),
        edges: data.edges.map(edge => ({
          data: {
            id: edge.id,
            source: edge.source,
            target: edge.target,
            type: edge.type
          }
        }))
      },
      style: [
        // Base node styles
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'text-valign': 'center',
            'text-halign': 'center',
            'font-size': '12px',
            'width': '60px',
            'height': '60px',
            'border-width': '2px',
            'border-color': '#666',
            'background-color': '#fff',
            'text-wrap': 'wrap',
            'text-max-width': '80px',
            'font-weight': '500'
          }
        },
        // Domain nodes
        {
          selector: 'node[type="domain"]',
          style: {
            'background-color': '#3b82f6',
            'border-color': '#2563eb',
            'color': '#fff',
            'width': '80px',
            'height': '80px',
            'font-size': '14px',
            'font-weight': 'bold',
            'shape': 'round-rectangle'
          }
        },
        // Subdomain nodes
        {
          selector: 'node[type="subdomain"]',
          style: {
            'background-color': '#10b981',
            'border-color': '#059669',
            'color': '#fff',
            'shape': 'ellipse'
          }
        },
        // IP nodes
        {
          selector: 'node[type="ip"]',
          style: {
            'background-color': '#f59e0b',
            'border-color': '#d97706',
            'color': '#fff',
            'shape': 'rectangle'
          }
        },
        // ASN nodes
        {
          selector: 'node[type="asn"]',
          style: {
            'background-color': '#8b5cf6',
            'border-color': '#7c3aed',
            'color': '#fff',
            'shape': 'hexagon'
          }
        },
        // Port nodes
        {
          selector: 'node[type="port"]',
          style: {
            'background-color': '#ef4444',
            'border-color': '#dc2626',
            'color': '#fff',
            'width': '40px',
            'height': '40px',
            'font-size': '10px',
            'shape': 'diamond'
          }
        },
        // Highlighted nodes
        {
          selector: 'node:selected',
          style: {
            'border-width': '4px',
            'border-color': '#fbbf24',
            'overlay-opacity': 0.3,
            'overlay-color': '#fbbf24'
          }
        },
        // Base edge styles
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': '#94a3b8',
            'target-arrow-color': '#94a3b8',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 1.5
          }
        },
        // Different edge types
        {
          selector: 'edge[type="contains"]',
          style: {
            'line-color': '#3b82f6',
            'target-arrow-color': '#3b82f6',
            'line-style': 'solid'
          }
        },
        {
          selector: 'edge[type="resolves_to"]',
          style: {
            'line-color': '#10b981',
            'target-arrow-color': '#10b981',
            'line-style': 'dashed'
          }
        },
        {
          selector: 'edge[type="belongs_to"]',
          style: {
            'line-color': '#8b5cf6',
            'target-arrow-color': '#8b5cf6',
            'line-style': 'dotted'
          }
        },
        {
          selector: 'edge[type="has_port"]',
          style: {
            'line-color': '#ef4444',
            'target-arrow-color': '#ef4444',
            'line-style': 'solid',
            'width': 1
          }
        },
        // Highlighted edges
        {
          selector: 'edge:selected',
          style: {
            'width': 4,
            'line-color': '#fbbf24',
            'target-arrow-color': '#fbbf24'
          }
        }
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        spacingFactor: 1.5,
        avoidOverlap: true,
        nodeDimensionsIncludeLabels: true
      },
      minZoom: 0.2,
      maxZoom: 3,
      wheelSensitivity: 0.2
    });

    // Handle node clicks
    cy.on('tap', 'node', (event) => {
      const node = event.target;
      const nodeData = data.nodes.find(n => n.id === node.id());

      if (nodeData) {
        setSelectedNode(nodeData);
        if (onNodeClick) {
          onNodeClick(nodeData);
        }
      }
    });

    // Handle background clicks (deselect)
    cy.on('tap', (event) => {
      if (event.target === cy) {
        setSelectedNode(null);
      }
    });

    cyRef.current = cy;

    // Cleanup
    return () => {
      cy.destroy();
    };
  }, [data, onNodeClick]);

  // Re-run layout when data changes
  useEffect(() => {
    if (cyRef.current) {
      const layout = cyRef.current.layout({
        name: 'breadthfirst',
        directed: true,
        spacingFactor: 1.5,
        avoidOverlap: true,
        nodeDimensionsIncludeLabels: true
      });
      layout.run();
    }
  }, [data]);

  const handleFit = () => {
    if (cyRef.current) {
      cyRef.current.fit(undefined, 50);
    }
  };

  const handleCenter = () => {
    if (cyRef.current) {
      cyRef.current.center();
    }
  };

  const handleResetZoom = () => {
    if (cyRef.current) {
      cyRef.current.zoom(1);
      cyRef.current.center();
    }
  };

  return (
    <div className="relative">
      {/* Graph Controls */}
      <div className="absolute top-4 right-4 z-10 flex gap-2">
        <button
          onClick={handleFit}
          className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          title="Fit to screen"
        >
          Fit
        </button>
        <button
          onClick={handleCenter}
          className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          title="Center graph"
        >
          Center
        </button>
        <button
          onClick={handleResetZoom}
          className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          title="Reset zoom"
        >
          Reset
        </button>
      </div>

      {/* Selected Node Info */}
      {selectedNode && (
        <div className="absolute top-4 left-4 z-10 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg shadow-lg p-4 max-w-xs">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white capitalize">
              {selectedNode.type}
            </h3>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
            >
              ✕
            </button>
          </div>
          <div className="space-y-1 text-sm">
            <div className="font-medium text-gray-900 dark:text-white break-all">
              {selectedNode.label}
            </div>
            {Object.entries(selectedNode.data).map(([key, value]) => {
              if (key === 'id' || value === null || value === undefined) return null;
              return (
                <div key={key} className="text-gray-600 dark:text-gray-300">
                  <span className="font-medium">{key.replace(/_/g, ' ')}:</span>{' '}
                  {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Graph Container */}
      <div
        ref={containerRef}
        style={{ height }}
        className="w-full border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900"
      />

      {/* Legend */}
      <div className="mt-4 flex flex-wrap gap-4 text-sm">
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded bg-blue-500"></div>
          <span className="text-gray-700 dark:text-gray-300">Domain</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded-full bg-green-500"></div>
          <span className="text-gray-700 dark:text-gray-300">Subdomain</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 bg-orange-500"></div>
          <span className="text-gray-700 dark:text-gray-300">IP Address</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 bg-purple-500" style={{ clipPath: 'polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)' }}></div>
          <span className="text-gray-700 dark:text-gray-300">ASN</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 bg-red-500" style={{ transform: 'rotate(45deg)' }}></div>
          <span className="text-gray-700 dark:text-gray-300">Port</span>
        </div>
      </div>
    </div>
  );
};

export default InfrastructureGraph;

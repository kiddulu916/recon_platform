import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Layout from './components/common/Layout';
import Dashboard from './pages/Dashboard';
import Domains from './pages/Domains';
import Subdomains from './pages/Subdomains';
import Vulnerabilities from './pages/Vulnerabilities';
import HTTPTraffic from './pages/HTTPTraffic';
import Patterns from './pages/Patterns';
import ScanDetails from './pages/ScanDetails';
import InfrastructureGraph from './pages/InfrastructureGraph';
import './App.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="domains" element={<Domains />} />
            <Route path="domains/:domainId/subdomains" element={<Subdomains />} />
            <Route path="domains/:domainId/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="domains/:domainId/traffic" element={<HTTPTraffic />} />
            <Route path="domains/:domainId/patterns" element={<Patterns />} />
            <Route path="scans/:scanId" element={<ScanDetails />} />
            <Route path="graph" element={<InfrastructureGraph />} />
          </Route>
        </Routes>
      </Router>
    </QueryClientProvider>
  );
}

export default App;

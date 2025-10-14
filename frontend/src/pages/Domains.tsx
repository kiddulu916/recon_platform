import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import Card from '../components/common/Card';
import Button from '../components/common/Button';
import Badge from '../components/common/Badge';
import { useDomainStore, useScanStore } from '../store';

const Domains = () => {
  const { domains, fetchDomains, createDomain, isLoading } = useDomainStore();
  const { startScan } = useScanStore();
  const [showAddForm, setShowAddForm] = useState(false);
  const [showScanForm, setShowScanForm] = useState<number | null>(null);
  const [formData, setFormData] = useState({
    domain: '',
    is_authorized: false,
    scan_profile: 'normal',
  });
  const [scanFormData, setScanFormData] = useState({
    scan_type: 'full',
    enable_recursion: false,
  });
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    fetchDomains();
  }, [fetchDomains]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      await createDomain(formData);
      setShowAddForm(false);
      setFormData({ domain: '', is_authorized: false, scan_profile: 'normal' });
    } catch (error) {
      console.error('Failed to add domain:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleStartScan = async (e: React.FormEvent, domainId: number) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      await startScan({
        domain_id: domainId,
        scan_type: scanFormData.scan_type,
        enable_recursion: scanFormData.enable_recursion,
      });
      setShowScanForm(null);
      setScanFormData({ scan_type: 'full', enable_recursion: false });
      alert('Scan started successfully! Check the dashboard for progress.');
    } catch (error) {
      console.error('Failed to start scan:', error);
      alert('Failed to start scan. Check console for details.');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-600 dark:text-gray-400">Loading...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-3xl font-bold text-gray-900 dark:text-white">
          Domains
        </h2>
        <Button onClick={() => setShowAddForm(true)}>Add Domain</Button>
      </div>

      {showAddForm && (
        <Card>
          <form onSubmit={handleSubmit} className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Add New Domain
            </h3>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Domain Name
              </label>
              <input
                type="text"
                value={formData.domain}
                onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
                placeholder="example.com"
                required
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
            </div>

            <div>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={formData.is_authorized}
                  onChange={(e) => setFormData({ ...formData, is_authorized: e.target.checked })}
                  className="rounded"
                />
                <span className="text-sm text-gray-700 dark:text-gray-300">
                  I have authorization to scan this domain
                </span>
              </label>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Scan Profile
              </label>
              <select
                value={formData.scan_profile}
                onChange={(e) => setFormData({ ...formData, scan_profile: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              >
                <option value="passive">Passive (Slow, Stealthy)</option>
                <option value="normal">Normal (Balanced)</option>
                <option value="aggressive">Aggressive (Fast, Loud)</option>
              </select>
            </div>

            <div className="flex space-x-3 pt-4">
              <Button type="submit" isLoading={isSubmitting}>
                Add Domain
              </Button>
              <Button
                type="button"
                variant="secondary"
                onClick={() => {
                  setShowAddForm(false);
                  setFormData({ domain: '', is_authorized: false, scan_profile: 'normal' });
                }}
              >
                Cancel
              </Button>
            </div>
          </form>
        </Card>
      )}

      {domains.length === 0 && !showAddForm && (
        <Card>
          <div className="text-center py-12">
            <p className="text-gray-500 dark:text-gray-400 mb-4">
              No domains added yet. Add your first domain to start reconnaissance.
            </p>
            <Button onClick={() => setShowAddForm(true)}>Add Your First Domain</Button>
          </div>
        </Card>
      )}

      {domains.length > 0 && (
        <div className="grid grid-cols-1 gap-6">
          {domains.map((domain) => (
            <div key={domain.id} className="space-y-4">
              <Card>
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                      {domain.domain}
                    </h3>
                    <div className="flex items-center space-x-4 mt-2">
                      <Badge variant={domain.is_authorized ? 'success' : 'danger'}>
                        {domain.is_authorized ? 'Authorized' : 'Unauthorized'}
                      </Badge>
                      <Badge variant="info">{domain.scan_profile}</Badge>
                      <span className="text-sm text-gray-500 dark:text-gray-400">
                        Added {new Date(domain.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                  <div className="flex space-x-2">
                    <Link to={`/domains/${domain.id}/subdomains`}>
                      <Button size="sm" variant="secondary">
                        Subdomains
                      </Button>
                    </Link>
                    <Link to={`/domains/${domain.id}/vulnerabilities`}>
                      <Button size="sm" variant="secondary">
                        Vulnerabilities
                      </Button>
                    </Link>
                    <Button size="sm" onClick={() => setShowScanForm(domain.id)}>
                      Start Scan
                    </Button>
                  </div>
                </div>
              </Card>

              {showScanForm === domain.id && (
                <Card>
                  <form onSubmit={(e) => handleStartScan(e, domain.id)} className="space-y-4">
                    <h4 className="text-md font-semibold text-gray-900 dark:text-white">
                      Start Scan for {domain.domain}
                    </h4>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Scan Type
                      </label>
                      <select
                        value={scanFormData.scan_type}
                        onChange={(e) => setScanFormData({ ...scanFormData, scan_type: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                      >
                        <option value="full">Full Scan (All Phases)</option>
                        <option value="passive">Passive Only</option>
                        <option value="active">Active Only</option>
                      </select>
                    </div>

                    <div>
                      <label className="flex items-center space-x-2">
                        <input
                          type="checkbox"
                          checked={scanFormData.enable_recursion}
                          onChange={(e) => setScanFormData({ ...scanFormData, enable_recursion: e.target.checked })}
                          className="rounded"
                        />
                        <span className="text-sm text-gray-700 dark:text-gray-300">
                          Enable recursive enumeration on discovered subdomains
                        </span>
                      </label>
                    </div>

                    <div className="flex space-x-3">
                      <Button type="submit" isLoading={isSubmitting}>
                        Start Scan
                      </Button>
                      <Button
                        type="button"
                        variant="secondary"
                        onClick={() => {
                          setShowScanForm(null);
                          setScanFormData({ scan_type: 'full', enable_recursion: false });
                        }}
                      >
                        Cancel
                      </Button>
                    </div>
                  </form>
                </Card>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Domains;

// Enhanced CPECVELookup.js with CPE database initialization
import React, { useState, useEffect } from 'react';
import { Search, Shield, AlertTriangle, Info, Target, Database, ExternalLink, Loader, CheckCircle, XCircle, Eye, Download, RefreshCw, Clock } from 'lucide-react';
import { api } from '../../services/api';

const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-100 text-red-800 border-red-200',
  HIGH: 'bg-orange-100 text-orange-800 border-orange-200',
  MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  LOW: 'bg-green-100 text-green-800 border-green-200',
  UNKNOWN: 'bg-gray-100 text-gray-800 border-gray-200'
};

const CONFIDENCE_COLORS = {
  high: 'bg-green-100 text-green-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-red-100 text-red-800'
};

// CPE Database Status Component
const CPEDatabaseStatus = ({ status, onRefresh, onInitialize, loading }) => {
  const getStatusColor = () => {
    if (!status) return 'gray';
    if (status.has_data && status.total_products > 0) return 'green';
    if (status.has_data && status.needs_refresh) return 'yellow';
    return 'red';
  };

  const getStatusIcon = () => {
    const color = getStatusColor();
    if (loading) return <Loader className="h-5 w-5 animate-spin" />;
    if (color === 'green') return <CheckCircle className="h-5 w-5 text-green-600" />;
    if (color === 'yellow') return <AlertTriangle className="h-5 w-5 text-yellow-600" />;
    return <XCircle className="h-5 w-5 text-red-600" />;
  };

  const getStatusMessage = () => {
    if (loading) return 'Checking CPE database status...';
    if (!status) return 'Unable to check CPE status';

    if (status.has_data && status.total_products > 0) {
      return `CPE database ready with ${status.total_products?.toLocaleString()} products`;
    }

    if (status.has_data && status.needs_refresh) {
      return 'CPE database needs refresh';
    }

    return 'CPE database not initialized - required for lookups';
  };

  const canInitialize = () => {
    return !loading && (!status?.has_data || status?.needs_refresh);
  };

  return (
    <div className="bg-white rounded-lg shadow p-6 mb-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-3">
          <Database className="h-6 w-6 text-blue-600" />
          <h3 className="text-lg font-medium text-gray-900">CPE Database Status</h3>
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="text-gray-400 hover:text-gray-600 disabled:opacity-50"
        >
          <RefreshCw className={`h-5 w-5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          {getStatusIcon()}
          <div>
            <div className="font-medium text-gray-900">Database Status</div>
            <div className="text-sm text-gray-600">{getStatusMessage()}</div>
          </div>
        </div>

        {canInitialize() && (
          <button
            onClick={onInitialize}
            disabled={loading}
            className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 flex items-center space-x-2"
          >
            <Download className="h-4 w-4" />
            <span>
              {status?.has_data ? 'Refresh Database' : 'Initialize Database'}
            </span>
          </button>
        )}
      </div>

      {/* Details */}
      {status && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4 pt-4 border-t border-gray-200">
          <div className="text-center">
            <div className="text-sm text-gray-500">Total Products</div>
            <div className="text-lg font-semibold text-gray-900">
              {status.total_products?.toLocaleString() || '0'}
            </div>
          </div>

          <div className="text-center">
            <div className="text-sm text-gray-500">Cache Age</div>
            <div className="text-lg font-semibold text-gray-900">
              {status.cache_age_hours ? `${Math.round(status.cache_age_hours)}h` : 'N/A'}
            </div>
          </div>

          <div className="text-center">
            <div className="text-sm text-gray-500">Last Updated</div>
            <div className="text-sm font-medium text-gray-900">
              {status.last_refresh ? new Date(status.last_refresh).toLocaleDateString() : 'Never'}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Initialization Progress Component
const InitializationProgress = ({ isInitializing, onClose }) => {
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState('Starting initialization...');

  useEffect(() => {
    if (!isInitializing) return;

    // Simulate progress updates
    const interval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 90) return prev;
        const increment = Math.random() * 10;
        return Math.min(prev + increment, 90);
      });
    }, 1000);

    // Update status messages
    const statusUpdates = [
      'Downloading CPE data from NIST...',
      'Processing CPE entries...',
      'Building search index...',
      'Finalizing database...'
    ];

    let statusIndex = 0;
    const statusInterval = setInterval(() => {
      if (statusIndex < statusUpdates.length - 1) {
        setStatus(statusUpdates[statusIndex]);
        statusIndex++;
      }
    }, 2000);

    return () => {
      clearInterval(interval);
      clearInterval(statusInterval);
    };
  }, [isInitializing]);

  if (!isInitializing) return null;

  return (
    <div className="fixed inset-0 bg-gray-800 bg-opacity-75 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
        <div className="text-center">
          <Database className="h-12 w-12 text-blue-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">Initializing CPE Database</h3>
          <p className="text-sm text-gray-600 mb-6">{status}</p>

          <div className="w-full bg-gray-200 rounded-full h-2 mb-4">
            <div
              className="bg-blue-600 h-2 rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            ></div>
          </div>

          <p className="text-xs text-gray-500 mb-4">
            This process may take 5-10 minutes. Please do not close this window.
          </p>

          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            Run in Background
          </button>
        </div>
      </div>
    </div>
  );
};

// Main CPE to CVE Lookup Component
const CPECVELookup = () => {
  const [activeTab, setActiveTab] = useState('status');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // CPE Database Status
  const [cpeStatus, setCpeStatus] = useState(null);
  const [statusLoading, setStatusLoading] = useState(false);
  const [isInitializing, setIsInitializing] = useState(false);

  // CPE Lookup State
  const [cpeQuery, setCpeQuery] = useState('');
  const [cpeResults, setCpeResults] = useState(null);
  const [vulnerabilityMatches, setVulnerabilityMatches] = useState([]);

  // Search State
  const [searchForm, setSearchForm] = useState({
    vendor: '',
    product: '',
    version: '',
    severity: '',
    confidence_min: 0.7
  });
  const [searchResults, setSearchResults] = useState(null);

  // Check CPE status on component mount
  useEffect(() => {
    checkCPEStatus();
  }, []);

  const checkCPEStatus = async () => {
    setStatusLoading(true);
    setError('');

    try {
      const status = await api.getCPEStatus();
      setCpeStatus(status);
    } catch (err) {
      setError(`Error checking CPE status: ${err.message}`);
    } finally {
      setStatusLoading(false);
    }
  };

  const initializeCPEDatabase = async () => {
    setIsInitializing(true);
    setError('');

    try {
      const result = await api.triggerCPEIngestion(true);

      if (result.success) {
        // Poll for completion
        pollForCompletion();
      } else {
        setError('Failed to start CPE database initialization');
        setIsInitializing(false);
      }
    } catch (err) {
      setError(`Error initializing CPE database: ${err.message}`);
      setIsInitializing(false);
    }
  };

  const pollForCompletion = () => {
    const pollInterval = setInterval(async () => {
      try {
        const status = await api.getCPEStatus();
        setCpeStatus(status);

        if (status.has_data && status.total_products > 0) {
          // Initialization complete
          setIsInitializing(false);
          clearInterval(pollInterval);

          // Auto-switch to CPE lookup tab
          setActiveTab('cpe-lookup');
        }
      } catch (err) {
        console.error('Error polling CPE status:', err);
      }
    }, 3000); // Poll every 3 seconds

    // Stop polling after 10 minutes to avoid infinite polling
    setTimeout(() => {
      clearInterval(pollInterval);
      if (isInitializing) {
        setIsInitializing(false);
        setError('Initialization took longer than expected. Please check status manually.');
      }
    }, 600000);
  };

  const handleCPELookup = async () => {
    if (!cpeQuery.trim()) {
      setError('Please enter a CPE name');
      return;
    }

    if (!cpeStatus?.has_data) {
      setError('CPE database not available. Please initialize the database first.');
      return;
    }

    setLoading(true);
    setError('');

    try {
      // Get vulnerability summary for the CPE
      const summary = await api.request(`/cpe-cve-correlation/cpe/${encodeURIComponent(cpeQuery)}/vulnerabilities`);
      setCpeResults(summary);

      // Get detailed matches
      const matches = await api.request('/cpe-cve-correlation/correlate-cpe', {
        method: 'POST',
        body: JSON.stringify({
          cpe_name: cpeQuery,
          include_version_range: true,
          confidence_threshold: 0.5,
          max_results: 50
        })
      });

      setVulnerabilityMatches(matches);

    } catch (err) {
      setError(`Lookup failed: ${err.message}`);
      setCpeResults(null);
      setVulnerabilityMatches([]);
    } finally {
      setLoading(false);
    }
  };

  const handleVulnerabilitySearch = async () => {
    setLoading(true);
    setError('');

    try {
      const params = {};
      if (searchForm.vendor) params.vendor = searchForm.vendor;
      if (searchForm.product) params.product = searchForm.product;
      if (searchForm.version) params.version = searchForm.version;
      if (searchForm.severity) params.severity = searchForm.severity;
      params.confidence_min = searchForm.confidence_min;

      const results = await api.request('/cpe-cve-correlation/vulnerabilities/search?' + new URLSearchParams(params));
      setSearchResults(results);

    } catch (err) {
      setError(`Search failed: ${err.message}`);
      setSearchResults(null);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'Unknown';
    return new Date(dateString).toLocaleDateString();
  };

  const getSeverityBadge = (severity) => {
    const colorClass = SEVERITY_COLORS[severity] || SEVERITY_COLORS.UNKNOWN;
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${colorClass}`}>
        {severity || 'UNKNOWN'}
      </span>
    );
  };

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <div className="flex items-center space-x-3">
        <Shield className="h-8 w-8 text-blue-600" />
        <div>
          <h1 className="text-2xl font-bold text-gray-900">CPE to CVE Correlation</h1>
          <p className="text-gray-600">Search for vulnerabilities using Common Platform Enumeration identifiers</p>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('status')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${activeTab === 'status'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
          >
            Database Status
          </button>
          <button
            onClick={() => setActiveTab('cpe-lookup')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${activeTab === 'cpe-lookup'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            disabled={!cpeStatus?.has_data}
          >
            CPE Lookup
          </button>
          <button
            onClick={() => setActiveTab('vulnerability-search')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${activeTab === 'vulnerability-search'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            disabled={!cpeStatus?.has_data}
          >
            Vulnerability Search
          </button>
        </nav>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-center">
            <XCircle className="h-5 w-5 text-red-600 mr-2" />
            <span className="text-red-800">{error}</span>
          </div>
        </div>
      )}

      {/* Database Status Tab */}
      {activeTab === 'status' && (
        <div>
          <CPEDatabaseStatus
            status={cpeStatus}
            onRefresh={checkCPEStatus}
            onInitialize={initializeCPEDatabase}
            loading={statusLoading}
          />

          {/* Instructions */}
          <div className="bg-blue-50 rounded-lg p-6">
            <h3 className="font-medium text-blue-900 mb-2">Getting Started</h3>
            <div className="text-sm text-blue-800 space-y-2">
              <p>
                The CPE (Common Platform Enumeration) database provides standardized names for
                software products, operating systems, and hardware platforms from NIST.
              </p>
              <p>
                <strong>Before using CPE lookup:</strong> Initialize the database by clicking
                "Initialize Database" above. This downloads the latest CPE data from NIST
                (~5-10 minutes).
              </p>
              <p>
                <strong>After initialization:</strong> Use the CPE Lookup and Vulnerability Search
                tabs to find security vulnerabilities for specific software products.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* CPE Lookup Tab */}
      {activeTab === 'cpe-lookup' && (
        <div className="space-y-6">
          {/* CPE Input */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold mb-4">Look up vulnerabilities for a CPE</h3>
            <div className="flex gap-4 items-end">
              <div className="flex-1">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  CPE Name (e.g., cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*)
                </label>
                <input
                  type="text"
                  value={cpeQuery}
                  onChange={(e) => setCpeQuery(e.target.value)}
                  placeholder="Enter CPE 2.3 formatted name..."
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  onKeyDown={(e) => e.key === 'Enter' && handleCPELookup()}
                />
              </div>
              <button
                onClick={handleCPELookup}
                disabled={loading || !cpeStatus?.has_data}
                className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2"
              >
                {loading ? (
                  <Loader className="h-4 w-4 animate-spin" />
                ) : (
                  <Search className="h-4 w-4" />
                )}
                Search
              </button>
            </div>
          </div>

          {/* CPE Results */}
          {cpeResults && (
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold mb-4">Vulnerability Summary</h3>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div className="text-center">
                  <div className="text-2xl font-bold text-gray-900">{cpeResults.total_vulnerabilities || 0}</div>
                  <div className="text-sm text-gray-600">Total CVEs</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-600">{cpeResults.critical_count || 0}</div>
                  <div className="text-sm text-gray-600">Critical</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-orange-600">{cpeResults.high_count || 0}</div>
                  <div className="text-sm text-gray-600">High</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-600">{cpeResults.risk_score?.toFixed(1) || 'N/A'}</div>
                  <div className="text-sm text-gray-600">Risk Score</div>
                </div>
              </div>

              {/* Detailed Vulnerability List */}
              {vulnerabilityMatches.length > 0 && (
                <div>
                  <h4 className="font-medium mb-4">Detailed Vulnerabilities</h4>
                  <div className="space-y-3 max-h-96 overflow-y-auto">
                    {vulnerabilityMatches.map((vuln, index) => (
                      <div key={index} className="border border-gray-200 rounded-lg p-4">
                        <div className="flex justify-between items-start">
                          <div className="flex-1">
                            <div className="flex items-center gap-3 mb-2">
                              <h5 className="font-medium text-gray-900">{vuln.cve_id}</h5>
                              {getSeverityBadge(vuln.severity)}
                              {vuln.cvss_score && (
                                <span className="text-sm text-gray-600">CVSS: {vuln.cvss_score}</span>
                              )}
                            </div>
                            <p className="text-sm text-gray-600 mb-2">
                              {vuln.description ? (vuln.description.length > 200 ?
                                vuln.description.substring(0, 200) + '...' : vuln.description) : 'No description available'}
                            </p>
                            <div className="flex items-center gap-4 text-xs text-gray-500">
                              <span>Published: {formatDate(vuln.published_date)}</span>
                              {vuln.correlation_confidence && (
                                <span>Confidence: {Math.round(vuln.correlation_confidence * 100)}%</span>
                              )}
                            </div>
                          </div>

                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="p-1 text-gray-400 hover:text-gray-600 ml-4"
                            title="View on NIST NVD"
                          >
                            <ExternalLink className="h-4 w-4" />
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Vulnerability Search Tab */}
      {activeTab === 'vulnerability-search' && (
        <div className="space-y-6">
          {/* Search Form */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold mb-4">Search vulnerabilities by software criteria</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Vendor</label>
                <input
                  type="text"
                  value={searchForm.vendor}
                  onChange={(e) => setSearchForm(prev => ({ ...prev, vendor: e.target.value }))}
                  placeholder="e.g., microsoft, apache"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Product</label>
                <input
                  type="text"
                  value={searchForm.product}
                  onChange={(e) => setSearchForm(prev => ({ ...prev, product: e.target.value }))}
                  placeholder="e.g., windows, apache_http_server"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Version</label>
                <input
                  type="text"
                  value={searchForm.version}
                  onChange={(e) => setSearchForm(prev => ({ ...prev, version: e.target.value }))}
                  placeholder="e.g., 2.4.41"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
                <select
                  value={searchForm.severity}
                  onChange={(e) => setSearchForm(prev => ({ ...prev, severity: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">Any</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Min Confidence</label>
                <select
                  value={searchForm.confidence_min}
                  onChange={(e) => setSearchForm(prev => ({ ...prev, confidence_min: parseFloat(e.target.value) }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                >
                  <option value={0.9}>90% (High)</option>
                  <option value={0.7}>70% (Medium)</option>
                  <option value={0.5}>50% (Low)</option>
                </select>
              </div>
              <div className="flex items-end">
                <button
                  onClick={handleVulnerabilitySearch}
                  disabled={loading || !cpeStatus?.has_data}
                  className="w-full bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <Loader className="h-4 w-4 animate-spin" />
                  ) : (
                    <Search className="h-4 w-4" />
                  )}
                  Search
                </button>
              </div>
            </div>
          </div>

          {/* Search Results */}
          {searchResults && (
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold mb-4">
                Search Results ({searchResults.total_count || 0} found)
              </h3>

              <div className="space-y-3 max-h-96 overflow-y-auto">
                {searchResults.vulnerabilities?.length === 0 && (
                  <div className="p-8 text-center">
                    <Shield className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 mb-2">No vulnerabilities found</h3>
                    <p className="text-gray-500">
                      No CVEs match your search criteria. Try adjusting your search terms or lowering the confidence threshold.
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Initialization Progress Modal */}
      <InitializationProgress
        isInitializing={isInitializing}
        onClose={() => setIsInitializing(false)}
      />
    </div>
  );
};

export default CPECVELookup;
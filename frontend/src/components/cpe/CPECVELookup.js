// Update your existing frontend/src/components/cpe/CPECVELookup.js
// Replace the CPE Lookup tab section with this enhanced version

import React, { useState, useEffect } from 'react';
import { Shield, XCircle, RefreshCw, Database, Search } from 'lucide-react';
import api from '../../services/api';
import CPEDatabaseStatus from './CPEDatabaseStatus';
import EnhancedCPESearch from './EnhancedCPESearch';
import CPESearchResults from './CPESearchResults';

const CPECVELookup = () => {
  const [activeTab, setActiveTab] = useState('status');
  const [cpeStatus, setCpeStatus] = useState(null);
  const [statusLoading, setStatusLoading] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Enhanced search state
  const [searchResults, setSearchResults] = useState(null);
  const [selectedProduct, setSelectedProduct] = useState(null);
  const [vulnerabilityData, setVulnerabilityData] = useState(null);

  // Traditional CPE lookup state (for backward compatibility)
  const [cpeQuery, setCpeQuery] = useState('');
  const [cpeResults, setCpeResults] = useState(null);
  const [vulnerabilityMatches, setVulnerabilityMatches] = useState([]);

  // Vulnerability search state
  const [searchForm, setSearchForm] = useState({
    vendor: '',
    product: '',
    version: '',
    severity: '',
    confidence_min: 0.7
  });

  useEffect(() => {
    checkCPEStatus();

    // Set up status polling
    const statusInterval = setInterval(() => {
      if (cpeStatus?.has_data) {
        checkCPEStatus();
      }
    }, 300000); // Check every 5 minutes

    return () => clearInterval(statusInterval);
  }, []);

  const checkCPEStatus = async () => {
    setStatusLoading(true);
    try {
      const status = await api.getCPEStatus();
      setCpeStatus(status);
      setError('');
    } catch (err) {
      setError(`Failed to check CPE status: ${err.message}`);
    } finally {
      setStatusLoading(false);
    }
  };

  const initializeCPEDatabase = async (forceRefresh = false) => {
    setStatusLoading(true);
    setError('');
    try {
      await api.initializeCPE(forceRefresh);
      
      setTimeout(() => {
        checkCPEStatus();
      }, 2000);

      setTimeout(() => {
        if (!cpeStatus?.has_data) {
          setError('Database initialization is taking longer than expected. Please check status manually.');
        }
      }, 600000);
    } catch (err) {
      setError(`Failed to initialize CPE database: ${err.message}`);
    } finally {
      setStatusLoading(false);
    }
  };

  // Enhanced search handlers
  const handleEnhancedSearchResults = (results) => {
    setSearchResults(results);
    setSelectedProduct(null);
    setVulnerabilityData(null);
  };

  const handleProductSelect = (product) => {
    setSelectedProduct(product);
    // Auto-navigate to traditional CPE lookup with the selected product
    setCpeQuery(product.cpe_name);
    setActiveTab('cpe-lookup');
  };

  const handleViewVulnerabilities = async (product) => {
    setLoading(true);
    try {
      // Get vulnerability data for the selected product
      const vulnerabilities = await api.request(`/cpe-cve-correlation/cpe/${encodeURIComponent(product.cpe_name)}/vulnerabilities`);
      setVulnerabilityData(vulnerabilities);
      setSelectedProduct(product);
      setActiveTab('vulnerability-search');
    } catch (err) {
      setError(`Failed to get vulnerability data: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Traditional CPE lookup (existing functionality)
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
      const summary = await api.request(`/cpe-cve-correlation/cpe/${encodeURIComponent(cpeQuery)}/vulnerabilities`);
      setCpeResults(summary);

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
    const SEVERITY_COLORS = {
      CRITICAL: 'bg-red-100 text-red-800 border-red-200',
      HIGH: 'bg-orange-100 text-orange-800 border-orange-200',
      MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      LOW: 'bg-green-100 text-green-800 border-green-200',
      UNKNOWN: 'bg-gray-100 text-gray-800 border-gray-200'
    };
    
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
          <h1 className="text-2xl font-bold text-gray-900">CPE Vulnerability Search</h1>
          <p className="text-gray-600">Search for software vulnerabilities using enhanced CPE lookup</p>
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
            onClick={() => setActiveTab('enhanced-search')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${activeTab === 'enhanced-search'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            disabled={!cpeStatus?.has_data}
          >
            Smart Search
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

          <div className="mt-6 bg-blue-50 rounded-lg p-6">
            <h3 className="font-medium text-blue-900 mb-2">Getting Started</h3>
            <div className="text-sm text-blue-800 space-y-2">
              <p>
                The enhanced CPE search provides multiple ways to find software vulnerabilities:
              </p>
              <ul className="list-disc list-inside space-y-1 ml-4">
                <li><strong>Smart Search:</strong> Use natural language to find software (recommended)</li>
                <li><strong>CPE Lookup:</strong> Traditional CPE name lookup for exact matches</li>
                <li><strong>Vulnerability Search:</strong> Search by software characteristics</li>
              </ul>
              <p className="mt-3">
                <strong>Before using any search:</strong> Initialize the database by clicking
                "Initialize Database" above.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Enhanced Search Tab */}
      {activeTab === 'enhanced-search' && (
        <div className="space-y-6">
          <EnhancedCPESearch
            onResults={handleEnhancedSearchResults}
            onSelect={handleProductSelect}
            mode="smart"
          />
          
          {searchResults && (
            <CPESearchResults
              results={searchResults}
              onSelect={handleProductSelect}
              onViewVulnerabilities={handleViewVulnerabilities}
            />
          )}
        </div>
      )}

      {/* Traditional CPE Lookup Tab */}
      {activeTab === 'cpe-lookup' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold mb-4">Traditional CPE Lookup</h3>
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
                {selectedProduct && (
                  <p className="mt-2 text-sm text-green-600">
                    ✓ Pre-filled from Smart Search: {selectedProduct.display_name}
                  </p>
                )}
              </div>
              <button
                onClick={handleCPELookup}
                disabled={loading || !cpeStatus?.has_data}
                className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2"
              >
                {loading ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin" />
                    Searching...
                  </>
                ) : (
                  <>
                    <Search className="h-4 w-4" />
                    Search CVEs
                  </>
                )}
              </button>
            </div>
          </div>

          {/* CPE Results Display */}
          {cpeResults && (
            <div className="bg-white rounded-lg shadow p-6">
              <h4 className="text-lg font-semibold mb-4">Vulnerability Summary</h4>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-red-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">{cpeResults.critical_count || 0}</div>
                  <div className="text-sm text-red-600">Critical</div>
                </div>
                <div className="bg-orange-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-orange-600">{cpeResults.high_count || 0}</div>
                  <div className="text-sm text-orange-600">High</div>
                </div>
                <div className="bg-yellow-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-yellow-600">{cpeResults.medium_count || 0}</div>
                  <div className="text-sm text-yellow-600">Medium</div>
                </div>
                <div className="bg-green-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-green-600">{cpeResults.low_count || 0}</div>
                  <div className="text-sm text-green-600">Low</div>
                </div>
              </div>

              {vulnerabilityMatches.length > 0 && (
                <div>
                  <h5 className="font-medium text-gray-900 mb-3">Vulnerability Matches</h5>
                  <div className="space-y-3 max-h-96 overflow-y-auto">
                    {vulnerabilityMatches.map((match, index) => (
                      <div key={index} className="border border-gray-200 rounded-lg p-4">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center space-x-3">
                              <h6 className="font-medium text-gray-900">{match.cve_id}</h6>
                              {getSeverityBadge(match.severity)}
                              <span className="text-sm text-gray-600">
                                Score: {match.cvss_score || 'N/A'}
                              </span>
                            </div>
                            <p className="text-sm text-gray-600 mt-1">{match.description}</p>
                            <div className="mt-2 text-xs text-gray-500">
                              Published: {formatDate(match.published_date)} • 
                              Confidence: {Math.round((match.confidence_score || 0) * 100)}%
                            </div>
                          </div>
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
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold mb-4">Search Vulnerabilities by Software Details</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
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
                  <option value="">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Min Confidence ({Math.round(searchForm.confidence_min * 100)}%)
                </label>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.1"
                  value={searchForm.confidence_min}
                  onChange={(e) => setSearchForm(prev => ({ ...prev, confidence_min: parseFloat(e.target.value) }))}
                  className="w-full"
                />
              </div>
              <div className="flex items-end">
                <button
                  onClick={handleVulnerabilitySearch}
                  disabled={loading || !cpeStatus?.has_data}
                  className="w-full bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 disabled:opacity-50"
                >
                  Search Vulnerabilities
                </button>
              </div>
            </div>

            {selectedProduct && (
              <div className="mt-4 p-3 bg-blue-50 rounded-md">
                <p className="text-sm text-blue-800">
                  ✓ Searching vulnerabilities for: <strong>{selectedProduct.display_name}</strong>
                </p>
              </div>
            )}
          </div>

          {/* Vulnerability Results */}
          {vulnerabilityData && (
            <div className="bg-white rounded-lg shadow p-6">
              <h4 className="text-lg font-semibold mb-4">Vulnerability Results</h4>
              {/* Display vulnerability data here */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-red-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">{vulnerabilityData.critical_count || 0}</div>
                  <div className="text-sm text-red-600">Critical</div>
                </div>
                <div className="bg-orange-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-orange-600">{vulnerabilityData.high_count || 0}</div>
                  <div className="text-sm text-orange-600">High</div>
                </div>
                <div className="bg-yellow-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-yellow-600">{vulnerabilityData.medium_count || 0}</div>
                  <div className="text-sm text-yellow-600">Medium</div>
                </div>
                <div className="bg-green-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-green-600">{vulnerabilityData.low_count || 0}</div>
                  <div className="text-sm text-green-600">Low</div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default CPECVELookup;
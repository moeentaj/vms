import React, { useState, useEffect } from 'react';
import { Search, Shield, AlertTriangle, Info, Target, Database, ExternalLink, Loader, CheckCircle, XCircle, Eye } from 'lucide-react';

// Mock API service that extends your existing api service
const cpeApi = {
  baseURL: 'http://localhost:8000/api/v1',
  
  request: async function(endpoint, options = {}) {
    const token = localStorage.getItem('token');
    const url = `${this.baseURL}${endpoint}`;
    
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers,
      },
      ...options,
    };

    try {
      const response = await fetch(url, config);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      return response.json();
    } catch (error) {
      console.error(`API Error (${endpoint}):`, error);
      throw error;
    }
  },

  // CPE to CVE correlation
  correlateCPEToCVEs: async function(cpeData) {
    return this.request('/cpe-cve-correlation/correlate-cpe', {
      method: 'POST',
      body: JSON.stringify(cpeData)
    });
  },

  // Get vulnerability summary for CPE
  getCPEVulnerabilities: async function(cpeName) {
    const encoded = encodeURIComponent(cpeName);
    return this.request(`/cpe-cve-correlation/cpe/${encoded}/vulnerabilities`);
  },

  // Asset vulnerability assessment
  assessAssetVulnerabilities: async function(assetId) {
    return this.request(`/cpe-cve-correlation/assets/${assetId}/vulnerabilities`);
  },

  // Search vulnerabilities by criteria
  searchVulnerabilities: async function(params) {
    const query = new URLSearchParams(params).toString();
    return this.request(`/cpe-cve-correlation/vulnerabilities/search?${query}`);
  }
};

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

// Main CPE to CVE Lookup Component
const CPECVELookup = () => {
  const [activeTab, setActiveTab] = useState('cpe-lookup');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
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

  const handleCPELookup = async () => {
    if (!cpeQuery.trim()) {
      setError('Please enter a CPE name');
      return;
    }

    setLoading(true);
    setError('');
    
    try {
      // Get vulnerability summary for the CPE
      const summary = await cpeApi.getCPEVulnerabilities(cpeQuery);
      setCpeResults(summary);
      
      // Get detailed matches
      const matches = await cpeApi.correlateCPEToCVEs({
        cpe_name: cpeQuery,
        include_version_range: true,
        confidence_threshold: 0.5,
        max_results: 50
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
    if (!searchForm.vendor && !searchForm.product) {
      setError('Please enter at least vendor or product name');
      return;
    }

    setLoading(true);
    setError('');
    
    try {
      const params = {};
      if (searchForm.vendor) params.vendor = searchForm.vendor;
      if (searchForm.product) params.product = searchForm.product;
      if (searchForm.version) params.version = searchForm.version;
      if (searchForm.severity) params.severity = searchForm.severity;
      params.confidence_min = searchForm.confidence_min;
      
      const results = await cpeApi.searchVulnerabilities(params);
      setSearchResults(results);
      
    } catch (err) {
      setError(`Search failed: ${err.message}`);
      setSearchResults(null);
    } finally {
      setLoading(false);
    }
  };

  const getConfidenceLevel = (score) => {
    if (score >= 0.8) return 'high';
    if (score >= 0.6) return 'medium';
    return 'low';
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">CPE to CVE Lookup</h2>
        <div className="flex items-center gap-2 text-sm text-gray-600">
          <Info className="h-4 w-4" />
          Correlate Common Platform Enumeration (CPE) identifiers with vulnerabilities
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('cpe-lookup')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'cpe-lookup'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            CPE Lookup
          </button>
          <button
            onClick={() => setActiveTab('vulnerability-search')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'vulnerability-search'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
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
                disabled={loading}
                className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2"
              >
                {loading ? (
                  <>
                    <Loader className="h-4 w-4 animate-spin" />
                    Searching...
                  </>
                ) : (
                  <>
                    <Search className="h-4 w-4" />
                    Lookup
                  </>
                )}
              </button>
            </div>
          </div>

          {/* CPE Results Summary */}
          {cpeResults && (
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Target className="h-5 w-5 text-blue-600" />
                Vulnerability Summary
              </h3>
              
              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-gray-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-gray-900">{cpeResults.total_cves}</div>
                  <div className="text-sm text-gray-600">Total CVEs</div>
                </div>
                <div className="bg-red-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">
                    {cpeResults.severity_breakdown?.critical || 0}
                  </div>
                  <div className="text-sm text-gray-600">Critical</div>
                </div>
                <div className="bg-orange-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-orange-600">
                    {cpeResults.severity_breakdown?.high || 0}
                  </div>
                  <div className="text-sm text-gray-600">High Severity</div>
                </div>
                <div className="bg-green-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-green-600">
                    {cpeResults.high_confidence_matches}
                  </div>
                  <div className="text-sm text-gray-600">High Confidence</div>
                </div>
              </div>

              {/* Risk Score */}
              <div className="mb-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-700">Risk Score</span>
                  <span className="text-sm text-gray-600">{cpeResults.risk_score}/100</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full ${
                      cpeResults.risk_score >= 80 ? 'bg-red-600' :
                      cpeResults.risk_score >= 60 ? 'bg-orange-500' :
                      cpeResults.risk_score >= 40 ? 'bg-yellow-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${Math.min(cpeResults.risk_score, 100)}%` }}
                  ></div>
                </div>
              </div>

              {/* Recommendations */}
              {cpeResults.recommendations && cpeResults.recommendations.length > 0 && (
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                  <h4 className="font-medium text-blue-900 mb-2">Recommendations</h4>
                  <ul className="text-sm text-blue-800 space-y-1">
                    {cpeResults.recommendations.map((rec, index) => (
                      <li key={index} className="flex items-start gap-2">
                        <CheckCircle className="h-4 w-4 mt-0.5 text-blue-600" />
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Detailed CVE Matches */}
          {vulnerabilityMatches.length > 0 && (
            <div className="bg-white rounded-lg shadow">
              <div className="p-6 border-b">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Database className="h-5 w-5 text-purple-600" />
                  CVE Matches ({vulnerabilityMatches.length})
                </h3>
              </div>
              
              <div className="divide-y divide-gray-200 max-h-96 overflow-y-auto">
                {vulnerabilityMatches.map((match, index) => (
                  <div key={index} className="p-4 hover:bg-gray-50">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <button className="text-blue-600 hover:text-blue-800 font-medium">
                            {match.cve_id}
                          </button>
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full border ${
                            SEVERITY_COLORS[match.severity] || SEVERITY_COLORS.UNKNOWN
                          }`}>
                            {match.severity || 'UNKNOWN'}
                          </span>
                          <span className={`inline-flex px-2 py-1 text-xs font-medium rounded ${
                            CONFIDENCE_COLORS[getConfidenceLevel(match.confidence_score)]
                          }`}>
                            {Math.round(match.confidence_score * 100)}% confidence
                          </span>
                        </div>
                        
                        <p className="text-sm text-gray-600 mb-2 line-clamp-2">
                          {match.description}
                        </p>
                        
                        <div className="flex items-center gap-4 text-xs text-gray-500">
                          <span>CVSS: {match.cvss_score || 'N/A'}</span>
                          <span>Published: {formatDate(match.published_date)}</span>
                          <span>Match Type: {match.match_type}</span>
                          {match.version_affected && (
                            <span>Version: {match.version_affected}</span>
                          )}
                        </div>
                      </div>
                      
                      <div className="flex items-center gap-2 ml-4">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${match.cve_id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="p-1 text-gray-400 hover:text-gray-600"
                          title="View on NIST NVD"
                        >
                          <ExternalLink className="h-4 w-4" />
                        </a>
                        <button
                          className="p-1 text-gray-400 hover:text-gray-600"
                          title="View details"
                        >
                          <Eye className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Vulnerability Search Tab */}
      {activeTab === 'vulnerability-search' && (
        <div className="space-y-6">
          {/* Search Form */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold mb-4">Search vulnerabilities by software</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Vendor</label>
                <input
                  type="text"
                  value={searchForm.vendor}
                  onChange={(e) => setSearchForm({...searchForm, vendor: e.target.value})}
                  placeholder="e.g., nginx, microsoft, apache"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Product</label>
                <input
                  type="text"
                  value={searchForm.product}
                  onChange={(e) => setSearchForm({...searchForm, product: e.target.value})}
                  placeholder="e.g., nginx, windows, tomcat"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Version (optional)</label>
                <input
                  type="text"
                  value={searchForm.version}
                  onChange={(e) => setSearchForm({...searchForm, version: e.target.value})}
                  placeholder="e.g., 1.18.0, 2021"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
                <select
                  value={searchForm.severity}
                  onChange={(e) => setSearchForm({...searchForm, severity: e.target.value})}
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
                  Min Confidence: {Math.round(searchForm.confidence_min * 100)}%
                </label>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.1"
                  value={searchForm.confidence_min}
                  onChange={(e) => setSearchForm({...searchForm, confidence_min: parseFloat(e.target.value)})}
                  className="w-full"
                />
              </div>
            </div>
            
            <button
              onClick={handleVulnerabilitySearch}
              disabled={loading}
              className="bg-purple-600 text-white px-6 py-2 rounded-md hover:bg-purple-700 disabled:opacity-50 flex items-center gap-2"
            >
              {loading ? (
                <>
                  <Loader className="h-4 w-4 animate-spin" />
                  Searching...
                </>
              ) : (
                <>
                  <Search className="h-4 w-4" />
                  Search Vulnerabilities
                </>
              )}
            </button>
          </div>

          {/* Search Results */}
          {searchResults && (
            <div className="bg-white rounded-lg shadow">
              <div className="p-6 border-b">
                <h3 className="text-lg font-semibold">
                  Search Results ({searchResults.total_results})
                </h3>
                <div className="text-sm text-gray-600 mt-1">
                  Criteria: {Object.entries(searchResults.search_criteria)
                    .filter(([_, value]) => value)
                    .map(([key, value]) => `${key}: ${value}`)
                    .join(', ')}
                </div>
              </div>
              
              <div className="divide-y divide-gray-200 max-h-96 overflow-y-auto">
                {searchResults.vulnerabilities.map((vuln, index) => (
                  <div key={index} className="p-4 hover:bg-gray-50">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <button className="text-blue-600 hover:text-blue-800 font-medium">
                            {vuln.cve_id}
                          </button>
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full border ${
                            SEVERITY_COLORS[vuln.severity] || SEVERITY_COLORS.UNKNOWN
                          }`}>
                            {vuln.severity || 'UNKNOWN'}
                          </span>
                          {vuln.ai_risk_score && (
                            <span className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-purple-100 text-purple-800 rounded">
                              <Database className="h-3 w-3" />
                              AI: {vuln.ai_risk_score.toFixed(1)}
                            </span>
                          )}
                        </div>
                        
                        <p className="text-sm text-gray-600 mb-2">
                          {vuln.description}
                        </p>
                        
                        <div className="flex items-center gap-4 text-xs text-gray-500">
                          <span>CVSS: {vuln.cvss_score || 'N/A'}</span>
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
              
              {searchResults.vulnerabilities.length === 0 && (
                <div className="p-8 text-center">
                  <Shield className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No vulnerabilities found</h3>
                  <p className="text-gray-500">
                    No CVEs match your search criteria. Try adjusting your search terms or lowering the confidence threshold.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default CPECVELookup;
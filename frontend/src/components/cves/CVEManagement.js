import React, { useState, useEffect } from 'react';
import { Plus, Info, Search, Loader, X, AlertTriangle, Shield, Calendar, ExternalLink, Target, Server, CheckCircle, XCircle, Clock, Database, Monitor } from 'lucide-react';

// Enhanced API service with better error handling and graceful degradation
const api = {
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
        let errorData;
        try {
          errorData = await response.json();
        } catch (parseError) {
          errorData = { detail: `HTTP ${response.status}: ${response.statusText}` };
        }
        throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
      }
      return response.json();
    } catch (error) {
      console.error(`API Error (${endpoint}):`, error);
      throw error;
    }
  },

  // Enhanced CVE fetching with better error handling
  getCVEs: async function(params = {}) {
    try {
      const query = new URLSearchParams(params).toString();
      return await this.request(`/cves/?${query}`);
    } catch (error) {
      console.error('Failed to fetch CVEs:', error);
      
      // If it's a 404, the endpoint might not exist
      if (error.message.includes('404')) {
        throw new Error('CVE endpoint not found. Please check your API configuration.');
      }
      
      // If it's a 500, there might be a database issue
      if (error.message.includes('500')) {
        throw new Error('Server error. The database might be empty or misconfigured.');
      }
      
      throw error;
    }
  },

  // Check if correlation features are available
  checkCorrelationFeatures: async function() {
    try {
      // Try to access a simple correlation endpoint
      await this.request('/cves/correlation-stats');
      return true;
    } catch (error) {
      console.info('Correlation features not available:', error.message);
      return false;
    }
  },

  // Enhanced method with optional correlation data
  getCVE: async function(cveId, includeCorrelations = false) {
    try {
      const params = includeCorrelations ? '?include_correlations=true' : '';
      return await this.request(`/cves/${cveId}${params}`);
    } catch (error) {
      if (error.message.includes('404')) {
        throw new Error(`CVE ${cveId} not found in the database.`);
      }
      throw error;
    }
  },


  getCVE: async function(cveId) {
    return this.request(`/cves/${cveId}`);
  },

  collectCVEs: async function(daysBack = 7) {
    return this.request('/cves/enhance-collection', {
      method: 'POST',
      body: JSON.stringify({ days_back: daysBack }),
    });
  },

  analyzeCVE: async function(cveId) {
    return this.request(`/cves/${cveId}/analyze`, {
      method: 'POST',
    });
  },

  // Safe correlation endpoint
  getAffectedServices: async function(cveId) {
    try {
      return await this.request(`/cves/${cveId}/affected-services`);
    } catch (error) {
      console.warn(`Affected services not available for ${cveId}:`, error);
      return [];
    }
  },

  // Safe correlation trigger
  correlateCVE: async function(cveId, options = {}) {
    try {
      const payload = {
        confidence_threshold: options.confidence_threshold || 0.7,
        include_low_confidence: options.include_low_confidence || false
      };
      
      return await this.request(`/cves/${cveId}/correlate`, {
        method: 'POST',
        body: JSON.stringify(payload)
      });
    } catch (error) {
      console.warn(`Correlation not available for ${cveId}:`, error);
      return { 
        correlations_found: 0, 
        message: 'Correlation feature not available',
        error: error.message 
      };
    }
  },

  // Enhanced method with better error handling and fallbacks
  getCorrelationStats: async function() {
    try {
      // Try the correlation stats endpoint
      return await this.request('/cves/correlation-stats');
    } catch (error) {
      console.warn('Correlation stats endpoint not available, calculating basic stats:', error);
      
      try {
        // Fallback: get basic CVE stats and calculate what we can
        const cves = await this.request('/cves/?limit=1000'); // Get more CVEs for better stats
        
        // Calculate basic statistics from available data
        const stats = this.calculateBasicStats(cves);
        return stats;
      } catch (fallbackError) {
        console.warn('CVE endpoint also failed, returning empty stats:', fallbackError);
        
        // Return empty stats structure to prevent UI crashes
        return {
          total_cves: 0,
          correlated_cves: 0,
          correlation_coverage: 0,
          confidence_breakdown: { high: 0, medium: 0, low: 0 },
          verification_status: { verified: 0, false_positives: 0, pending: 0 },
          error: 'Statistics temporarily unavailable'
        };
      }
    }
  },

  // Helper method to calculate basic stats from CVE data
  calculateBasicStats: function(cves) {
    if (!Array.isArray(cves) || cves.length === 0) {
      return {
        total_cves: 0,
        correlated_cves: 0,
        correlation_coverage: 0,
        confidence_breakdown: { high: 0, medium: 0, low: 0 },
        verification_status: { verified: 0, false_positives: 0, pending: 0 },
        calculated: true
      };
    }

    const total_cves = cves.length;
    const correlated_cves = cves.filter(cve => 
      cve.correlation_confidence && cve.correlation_confidence > 0
    ).length;
    
    const correlation_coverage = total_cves > 0 ? (correlated_cves / total_cves * 100) : 0;
    
    // Count confidence levels based on available data
    const high_confidence = cves.filter(cve => 
      cve.correlation_confidence && cve.correlation_confidence >= 0.8
    ).length;
    
    const medium_confidence = cves.filter(cve => 
      cve.correlation_confidence && 
      cve.correlation_confidence >= 0.5 && 
      cve.correlation_confidence < 0.8
    ).length;
    
    const low_confidence = cves.filter(cve => 
      cve.correlation_confidence && cve.correlation_confidence < 0.5
    ).length;

    return {
      total_cves,
      correlated_cves,
      correlation_coverage,
      confidence_breakdown: {
        high: high_confidence,
        medium: medium_confidence,
        low: low_confidence
      },
      verification_status: {
        verified: 0, // Would need correlation table data
        false_positives: 0, // Would need correlation table data
        pending: high_confidence + medium_confidence // Rough estimate
      },
      calculated: true,
      note: 'Statistics calculated from available CVE data'
    };
  },

  // Service endpoints
  getServices: async function() {
    try {
      return this.request('/services/instances');
    } catch (error) {
      console.warn('Services endpoint not available:', error);
      return [];
    }
  }
};

// Constants
const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-100 text-red-800 border-red-200',
  HIGH: 'bg-orange-100 text-orange-800 border-orange-200',
  MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  LOW: 'bg-green-100 text-green-800 border-green-200',
  UNKNOWN: 'bg-gray-100 text-gray-800 border-gray-200'
};

// Service Impact Component
const ServiceImpactCard = ({ cveId, services = [] }) => {
  const [affectedServices, setAffectedServices] = useState([]);
  const [loading, setLoading] = useState(false);
  const [correlating, setCorrelating] = useState(false);

  useEffect(() => {
    if (cveId) {
      loadAffectedServices();
    }
  }, [cveId]);

  const loadAffectedServices = async () => {
    setLoading(true);
    try {
      const services = await api.getAffectedServices(cveId);
      setAffectedServices(services);
    } catch (error) {
      console.error('Failed to load affected services:', error);
      setAffectedServices([]);
    } finally {
      setLoading(false);
    }
  };

  const handleCorrelate = async () => {
    setCorrelating(true);
    try {
      const result = await api.correlateCVE(cveId);
      await loadAffectedServices();
      console.log('Correlation result:', result);
    } catch (error) {
      console.error('Correlation failed:', error);
    } finally {
      setCorrelating(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-4">
        <Loader className="h-6 w-6 animate-spin text-blue-600" />
        <span className="ml-2 text-gray-600">Loading affected services...</span>
      </div>
    );
  }

  return (
    <div className="bg-gray-50 p-4 rounded-lg">
      <div className="flex items-center justify-between mb-3">
        <h4 className="font-medium text-gray-900 flex items-center gap-2">
          <Target className="h-4 w-4" />
          Potentially Affected Services
        </h4>
        <button
          onClick={handleCorrelate}
          disabled={correlating}
          className="px-3 py-1 bg-blue-600 text-white rounded-md text-sm hover:bg-blue-700 disabled:opacity-50 flex items-center gap-1"
        >
          {correlating ? (
            <>
              <Loader className="h-3 w-3 animate-spin" />
              Analyzing...
            </>
          ) : (
            <>
              <Target className="h-3 w-3" />
              Analyze Impact
            </>
          )}
        </button>
      </div>

      {affectedServices.length === 0 ? (
        <div className="text-center py-6">
          <Server className="h-8 w-8 text-gray-400 mx-auto mb-2" />
          <p className="text-gray-500 text-sm">
            No affected services identified yet.
          </p>
          <p className="text-gray-400 text-xs mt-1">
            Click "Analyze Impact" to check for correlations.
          </p>
        </div>
      ) : (
        <div className="space-y-2 max-h-48 overflow-y-auto">
          {affectedServices.map((service, index) => (
            <div key={index} className="bg-white p-3 rounded border flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-blue-600" />
                <div>
                  <div className="font-medium text-sm">{service.name}</div>
                  <div className="text-xs text-gray-500">
                    {service.service_type_name} • {service.environment}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className={`px-2 py-1 text-xs rounded ${
                  service.criticality === 'critical' ? 'bg-red-100 text-red-800' :
                  service.criticality === 'high' ? 'bg-orange-100 text-orange-800' :
                  service.criticality === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                  'bg-green-100 text-green-800'
                }`}>
                  {service.criticality}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// Enhanced CVE Modal Component
const CVEModal = ({ cve, isOpen, onClose, onUpdate }) => {
  const [analyzing, setAnalyzing] = useState(false);
  const [services, setServices] = useState([]);

  useEffect(() => {
    if (isOpen) {
      loadServices();
    }
  }, [isOpen]);

  const loadServices = async () => {
    try {
      const serviceData = await api.getServices();
      setServices(serviceData);
    } catch (error) {
      console.error('Failed to load services:', error);
    }
  };

  const handleAnalyze = async () => {
    setAnalyzing(true);
    try {
      const result = await api.analyzeCVE(cve.cve_id);
      console.log('Analysis result:', result);
      onUpdate && onUpdate();
    } catch (error) {
      console.error('Analysis failed:', error);
    } finally {
      setAnalyzing(false);
    }
  };

  if (!isOpen || !cve) return null;

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    try {
      return new Date(dateString).toLocaleDateString();
    } catch {
      return dateString;
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return <AlertTriangle className="h-5 w-5 text-red-600" />;
      case 'HIGH':
        return <AlertTriangle className="h-5 w-5 text-orange-600" />;
      case 'MEDIUM':
        return <Shield className="h-5 w-5 text-yellow-600" />;
      case 'LOW':
        return <Shield className="h-5 w-5 text-green-600" />;
      default:
        return <Shield className="h-5 w-5 text-gray-600" />;
    }
  };

  const parseJsonField = (field) => {
    if (!field) return [];
    try {
      return typeof field === 'string' ? JSON.parse(field) : field;
    } catch {
      return [];
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg max-w-6xl w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex justify-between items-center p-6 border-b">
          <div className="flex items-center gap-3">
            {getSeverityIcon(cve.severity)}
            <h2 className="text-2xl font-bold text-gray-900">{cve.cve_id}</h2>
            <span className={`inline-flex px-3 py-1 text-sm font-semibold rounded-full border ${SEVERITY_COLORS[cve.severity] || SEVERITY_COLORS.UNKNOWN}`}>
              {cve.severity || 'UNKNOWN'}
            </span>
            {cve.ai_risk_score && (
              <span className="inline-flex items-center gap-1 px-2 py-1 text-sm bg-purple-100 text-purple-800 rounded-full">
                <Database className="h-3 w-3" />
                AI Risk: {cve.ai_risk_score.toFixed(1)}
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        <div className="flex">
          {/* Left side - CVE Details */}
          <div className="flex-1 p-6 space-y-6">
            {/* Basic Information */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="text-sm font-medium text-gray-500 mb-1">CVSS Score</h3>
                <p className="text-2xl font-bold text-gray-900">{cve.cvss_score || 'N/A'}</p>
              </div>
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="text-sm font-medium text-gray-500 mb-1">AI Risk Score</h3>
                <p className="text-2xl font-bold text-orange-600">
                  {cve.ai_risk_score ? cve.ai_risk_score.toFixed(1) : 'Not analyzed'}
                </p>
              </div>
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="text-sm font-medium text-gray-500 mb-1">Published</h3>
                <p className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                  <Calendar className="h-4 w-4" />
                  {formatDate(cve.published_date)}
                </p>
              </div>
            </div>

            {/* Actions */}
            <div className="flex gap-3">
              <button
                onClick={handleAnalyze}
                disabled={analyzing}
                className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50 flex items-center gap-2"
              >
                {analyzing ? (
                  <>
                    <Loader className="h-4 w-4 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Database className="h-4 w-4" />
                    Run AI Analysis
                  </>
                )}
              </button>
            </div>

            {/* Description */}
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-3">Description</h3>
              <div className="bg-gray-50 p-4 rounded-lg">
                <p className="text-gray-700 leading-relaxed">{cve.description}</p>
              </div>
            </div>

            {/* AI Analysis Results */}
            {cve.ai_summary && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">AI Analysis Summary</h3>
                <div className="bg-blue-50 border border-blue-200 p-4 rounded-lg">
                  <p className="text-blue-800 leading-relaxed">{cve.ai_summary}</p>
                </div>
              </div>
            )}

            {/* Mitigation Suggestions */}
            {cve.mitigation_suggestions && cve.mitigation_suggestions !== '[]' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">Recommended Mitigations</h3>
                <div className="bg-green-50 border border-green-200 p-4 rounded-lg">
                  <div className="text-green-800">
                    {(() => {
                      const suggestions = parseJsonField(cve.mitigation_suggestions);
                      if (suggestions.length > 0) {
                        return (
                          <ul className="list-disc list-inside space-y-1">
                            {suggestions.map((suggestion, index) => (
                              <li key={index}>{suggestion}</li>
                            ))}
                          </ul>
                        );
                      }
                      return <p>{cve.mitigation_suggestions}</p>;
                    })()}
                  </div>
                </div>
              </div>
            )}

            {/* Detection Methods */}
            {cve.detection_methods && cve.detection_methods !== '[]' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">Detection Methods</h3>
                <div className="bg-yellow-50 border border-yellow-200 p-4 rounded-lg">
                  <div className="text-yellow-800">
                    {(() => {
                      const methods = parseJsonField(cve.detection_methods);
                      if (methods.length > 0) {
                        return (
                          <ul className="list-disc list-inside space-y-1">
                            {methods.map((method, index) => (
                              <li key={index}>{method}</li>
                            ))}
                          </ul>
                        );
                      }
                      return <p>{cve.detection_methods}</p>;
                    })()}
                  </div>
                </div>
              </div>
            )}

            {/* Upgrade Paths */}
            {cve.upgrade_paths && cve.upgrade_paths !== '[]' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">Upgrade Paths</h3>
                <div className="bg-indigo-50 border border-indigo-200 p-4 rounded-lg">
                  <div className="text-indigo-800">
                    {(() => {
                      const paths = parseJsonField(cve.upgrade_paths);
                      if (paths.length > 0) {
                        return (
                          <ul className="list-disc list-inside space-y-1">
                            {paths.map((path, index) => (
                              <li key={index}>{path}</li>
                            ))}
                          </ul>
                        );
                      }
                      return <p>{cve.upgrade_paths}</p>;
                    })()}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Right side - Service Impact */}
          <div className="w-1/3 border-l bg-gray-50">
            <div className="p-6">
              <ServiceImpactCard cveId={cve.cve_id} services={services} />
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t p-6">
          <div className="flex justify-between items-center">
            <div className="flex gap-2">
              <a
                href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                <ExternalLink className="h-4 w-4" />
                NIST NVD
              </a>
              <a
                href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors"
              >
                <ExternalLink className="h-4 w-4" />
                MITRE CVE
              </a>
            </div>
            <div className="flex gap-3">
              <button
                onClick={onClose}
                className="px-4 py-2 text-gray-600 hover:text-gray-800 transition-colors"
              >
                Close
              </button>
              <button className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors">
                Create Assignment
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Enhanced React component with better error boundaries
const CorrelationStats = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [correlationAvailable, setCorrelationAvailable] = useState(false);

  useEffect(() => {
    checkFeaturesAndLoadStats();
  }, []);

  const checkFeaturesAndLoadStats = async () => {
    try {
      // First check if correlation features are available
      const available = await api.checkCorrelationFeatures();
      setCorrelationAvailable(available);
      
      // Load stats regardless, but handle gracefully if not available
      const data = await api.getCorrelationStats();
      setStats(data);
      setError(null);
    } catch (error) {
      console.error('Failed to load correlation stats:', error);
      setError(error.message);
      setStats(null);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="animate-pulse bg-gray-200 h-32 rounded-lg mb-6"></div>;
  }

  // Don't show anything if correlation features aren't available and no stats
  if (!stats && !correlationAvailable) {
    return null;
  }

  // Show error state if needed
  if (error && !stats) {
    return (
      <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
        <div className="flex items-center">
          <AlertTriangle className="h-5 w-5 text-yellow-600 mr-2" />
          <div>
            <h3 className="text-yellow-800 font-medium">Correlation Statistics Unavailable</h3>
            <p className="text-yellow-700 text-sm mt-1">
              {error.includes('CVE not found') 
                ? 'No CVEs found in database. Try collecting CVEs first.'
                : 'Correlation features may not be configured. Basic CVE management is still available.'}
            </p>
          </div>
        </div>
      </div>
    );
  }

  // Show stats if available
  if (stats && stats.total_cves > 0) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 rounded-lg">
              <Target className="h-6 w-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">
                {stats.calculated ? 'Estimated Coverage' : 'Correlation Coverage'}
              </p>
              <p className="text-2xl font-semibold text-gray-900">
                {stats.correlation_coverage.toFixed(1)}%
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-green-100 rounded-lg">
              <CheckCircle className="h-6 w-6 text-green-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">High Confidence</p>
              <p className="text-2xl font-semibold text-gray-900">
                {stats.confidence_breakdown.high}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-yellow-100 rounded-lg">
              <Clock className="h-6 w-6 text-yellow-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Pending Review</p>
              <p className="text-2xl font-semibold text-gray-900">
                {stats.verification_status.pending}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-purple-100 rounded-lg">
              <Database className="h-6 w-6 text-purple-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Total CVEs</p>
              <p className="text-2xl font-semibold text-gray-900">
                {stats.total_cves}
              </p>
            </div>
          </div>
        </div>
        
        {stats.calculated && (
          <div className="col-span-full">
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
              <p className="text-blue-800 text-sm">
                <Info className="h-4 w-4 inline mr-1" />
                {stats.note || 'Statistics calculated from available data. Enable correlation features for more detailed metrics.'}
              </p>
            </div>
          </div>
        )}
      </div>
    );
  }
  return null
};

// Main CVE Management Component
const CVEManagement = () => {
  const [cves, setCVEs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [selectedCVE, setSelectedCVE] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [collecting, setCollecting] = useState(false);
  const [analyzingCVEs, setAnalyzingCVEs] = useState(new Set());

  useEffect(() => {
    loadCVEs();
  }, [severityFilter]);

  const loadCVEs = async () => {
    setLoading(true);
    try {
      const params = {};
      if (severityFilter) params.severity = severityFilter;
      
      const data = await api.getCVEs(params);
      setCVEs(data);
    } catch (error) {
      console.error('Failed to load CVEs:', error);
      setCVEs([]);
    } finally {
      setLoading(false);
    }
  };

  const handleCollectCVEs = async () => {
    setCollecting(true);
    try {
      await api.collectCVEs(7);
      // Reload CVEs after collection
      setTimeout(() => {
        loadCVEs();
        setCollecting(false);
      }, 3000);
    } catch (error) {
      console.error('CVE collection failed:', error);
      setCollecting(false);
    }
  };

  const handleAnalyzeCVE = async (cveId) => {
    setAnalyzingCVEs(prev => new Set(prev).add(cveId));
    
    try {
      const result = await api.analyzeCVE(cveId);
      console.log('Analysis result:', result);
      
      // Update the CVE in the local state
      setCVEs(prevCVEs => 
        prevCVEs.map(cve => 
          cve.cve_id === cveId 
            ? { 
                ...cve, 
                ai_risk_score: result.analysis?.risk_score,
                ai_summary: result.analysis?.summary,
                mitigation_suggestions: JSON.stringify(result.analysis?.mitigations || []),
                detection_methods: JSON.stringify(result.analysis?.detection_methods || []),
                upgrade_paths: JSON.stringify(result.analysis?.upgrade_paths || []),
                processed: true
              }
            : cve
        )
      );
      
    } catch (error) {
      console.error('Failed to analyze CVE:', error);
    } finally {
      setAnalyzingCVEs(prev => {
        const newSet = new Set(prev);
        newSet.delete(cveId);
        return newSet;
      });
    }
  };

  const handleCVEClick = async (cve) => {
    try {
      const fullCVE = await api.getCVE(cve.cve_id);
      setSelectedCVE(fullCVE);
    } catch (error) {
      console.error('Failed to fetch CVE details:', error);
      setSelectedCVE(cve);
    }
    setIsModalOpen(true);
  };

  const filteredCVEs = cves.filter(cve => {
    const matchesSearch = cve.cve_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         cve.description.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSearch;
  });

  if (loading) {
    return <div className="flex justify-center p-8"><div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div></div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">CVE Management</h2>
        <div className="flex gap-3">
          <button 
            onClick={handleCollectCVEs}
            disabled={collecting}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center gap-2 disabled:opacity-50"
          >
            {collecting ? (
              <>
                <Loader className="h-4 w-4 animate-spin" />
                Collecting...
              </>
            ) : (
              <>
                <Plus className="h-4 w-4" />
                Collect CVEs
              </>
            )}
          </button>
        </div>
      </div>

      {/* Correlation Statistics (Optional) */}
      <CorrelationStats />

      {/* Filters */}
      <div className="bg-white p-4 rounded-lg shadow">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="relative">
            <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
            <input
              type="text"
              placeholder="Search CVEs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <div className="flex items-center">
            <span className="text-sm text-gray-600">
              {filteredCVEs.length} CVE{filteredCVEs.length !== 1 ? 's' : ''} found
            </span>
          </div>
        </div>
      </div>

      {/* CVE List */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">CVE ID</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">CVSS Score</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Description</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">AI Risk Score</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {filteredCVEs.map((cve) => (
              <tr key={cve.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                  <button
                    onClick={() => handleCVEClick(cve)}
                    className="text-blue-600 hover:text-blue-800 hover:underline"
                  >
                    {cve.cve_id}
                  </button>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  <span className="font-medium">
                    {cve.cvss_score || 'N/A'}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full border ${SEVERITY_COLORS[cve.severity] || SEVERITY_COLORS.UNKNOWN}`}>
                    {cve.severity || 'UNKNOWN'}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-900 max-w-md">
                  <div className="truncate" title={cve.description}>
                    {cve.description.substring(0, 100)}...
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  {cve.ai_risk_score ? (
                    <div className="flex items-center gap-1">
                      <Database className="h-4 w-4 text-purple-600" />
                      <span className="text-purple-600 font-semibold">
                        {cve.ai_risk_score.toFixed(1)}
                      </span>
                    </div>
                  ) : (
                    <span className="text-gray-400">Not analyzed</span>
                  )}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  <div className="flex items-center gap-2">
                    {cve.processed ? (
                      <div className="flex items-center gap-1 text-green-600">
                        <CheckCircle className="h-4 w-4" />
                        <span className="text-xs">Processed</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1 text-gray-500">
                        <Clock className="h-4 w-4" />
                        <span className="text-xs">Pending</span>
                      </div>
                    )}
                    {cve.correlation_confidence && (
                      <div className="flex items-center gap-1 text-blue-600">
                        <Target className="h-3 w-3" />
                        <span className="text-xs">
                          {(cve.correlation_confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                    )}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  <div className="flex items-center gap-2">
                    <button 
                      onClick={() => handleAnalyzeCVE(cve.cve_id)}
                      disabled={analyzingCVEs.has(cve.cve_id)}
                      className={`px-3 py-1 rounded text-sm font-medium ${
                        analyzingCVEs.has(cve.cve_id)
                          ? 'bg-gray-200 text-gray-500 cursor-not-allowed'
                          : 'text-purple-600 hover:text-purple-900 hover:bg-purple-50'
                      }`}
                    >
                      {analyzingCVEs.has(cve.cve_id) ? (
                        <div className="flex items-center gap-1">
                          <Loader className="h-3 w-3 animate-spin" />
                          Analyzing...
                        </div>
                      ) : (
                        <div className="flex items-center gap-1">
                          <Database className="h-3 w-3" />
                          Analyze
                        </div>
                      )}
                    </button>
                    <button 
                      onClick={() => handleCVEClick(cve)}
                      className="text-blue-600 hover:text-blue-900 hover:bg-blue-50 px-3 py-1 rounded text-sm"
                    >
                      View
                    </button>
                    <button className="text-green-600 hover:text-green-900 hover:bg-green-50 px-3 py-1 rounded text-sm">
                      Assign
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {filteredCVEs.length === 0 && (
          <div className="text-center py-12">
            <Database className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No CVEs Found</h3>
            <p className="text-gray-500 mb-4">
              {searchTerm || severityFilter 
                ? 'No CVEs match your current filters.' 
                : 'No CVEs have been collected yet.'}
            </p>
            {!searchTerm && !severityFilter && (
              <button 
                onClick={handleCollectCVEs}
                className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
              >
                Collect CVEs
              </button>
            )}
          </div>
        )}
      </div>

      {/* CVE Detail Modal */}
      <CVEModal 
        cve={selectedCVE} 
        isOpen={isModalOpen} 
        onClose={() => setIsModalOpen(false)}
        onUpdate={loadCVEs}
      />
    </div>
  );
};

export default CVEManagement;
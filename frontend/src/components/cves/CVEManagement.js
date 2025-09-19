// Enhanced CVEManagement.js with fixed state management and real-time updates
import React, { useState, useEffect, useCallback } from 'react';
import { Plus, Info, Search, Loader, X, AlertTriangle, Shield, Calendar, ExternalLink, Target, Server, CheckCircle, XCircle, Clock, Database, Monitor, RefreshCw } from 'lucide-react';
import { api } from '../../services/api';

// Enhanced Error Boundary Component
const ErrorBoundary = ({ children, fallback }) => {
  const [hasError, setHasError] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const handleError = (error) => {
      setHasError(true);
      setError(error);
    };

    window.addEventListener('error', handleError);
    return () => window.removeEventListener('error', handleError);
  }, []);

  if (hasError) {
    return fallback || (
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <div className="flex items-center">
          <AlertTriangle className="h-5 w-5 text-red-600 mr-2" />
          <span className="text-red-800">Something went wrong. Please refresh the page.</span>
        </div>
      </div>
    );
  }

  return children;
};

// Enhanced Toast Notification System
const Toast = ({ message, type = 'info', onClose }) => {
  useEffect(() => {
    const timer = setTimeout(onClose, 5000);
    return () => clearTimeout(timer);
  }, [onClose]);

  const typeStyles = {
    success: 'bg-green-100 border-green-400 text-green-700',
    error: 'bg-red-100 border-red-400 text-red-700',
    warning: 'bg-yellow-100 border-yellow-400 text-yellow-700',
    info: 'bg-blue-100 border-blue-400 text-blue-700'
  };

  return (
    <div className={`fixed top-4 right-4 border-l-4 p-4 rounded shadow-lg z-50 ${typeStyles[type]}`}>
      <div className="flex items-center">
        <span className="flex-1">{message}</span>
        <button onClick={onClose} className="ml-2 text-gray-500 hover:text-gray-700">
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
};

// Severity color mappings
const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-100 text-red-800 border-red-200',
  HIGH: 'bg-orange-100 text-orange-800 border-orange-200',
  MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  LOW: 'bg-green-100 text-green-800 border-green-200',
  UNKNOWN: 'bg-gray-100 text-gray-800 border-gray-200'
};

// Enhanced CVE Modal Component with proper state management
const CVEModal = ({ cve, isOpen, onClose, onUpdate }) => {
  const [analyzing, setAnalyzing] = useState(false);
  const [currentCVE, setCurrentCVE] = useState(cve);
  const [refreshing, setRefreshing] = useState(false);
  const [toast, setToast] = useState(null);

  // Update current CVE when prop changes
  useEffect(() => {
    if (cve && cve.cve_id !== currentCVE?.cve_id) {
      setCurrentCVE(cve);
      console.log('Modal received new CVE data:', cve);
    }
  }, [cve, currentCVE?.cve_id]);

  // Refresh CVE data from server
  const refreshCVEData = useCallback(async () => {
    if (!currentCVE?.cve_id) return;
    
    setRefreshing(true);
    try {
      const response = await api.getCVE(currentCVE.cve_id);
      const updatedCVE = response.cve || response;
      setCurrentCVE(updatedCVE);
      
      // Notify parent component about the update
      if (onUpdate) {
        onUpdate(updatedCVE);
      }
      
      console.log('CVE data refreshed successfully');
    } catch (error) {
      console.error('Failed to refresh CVE data:', error);
      setToast({ 
        message: `Failed to refresh CVE data: ${error.message}`, 
        type: 'error' 
      });
    } finally {
      setRefreshing(false);
    }
  }, [currentCVE?.cve_id, onUpdate]);

  const handleAnalyze = async () => {
    if (!currentCVE?.cve_id) return;
    
    setAnalyzing(true);
    try {
      console.log('Starting analysis for CVE:', currentCVE.cve_id);
      const result = await api.analyzeCVE(currentCVE.cve_id);
      console.log('Analysis result received:', result);

      // Create updated CVE object with proper field mapping
      const updatedCVE = {
        ...currentCVE,
        ai_risk_score: result.ai_analysis?.risk_score || result.risk_assessment?.base_risk_score || currentCVE.ai_risk_score,
        ai_summary: result.ai_analysis?.summary || currentCVE.ai_summary,
        mitigation_suggestions: result.ai_analysis?.mitigations ? 
          JSON.stringify(result.ai_analysis.mitigations) : currentCVE.mitigation_suggestions,
        detection_methods: result.ai_analysis?.detection_methods ? 
          JSON.stringify(result.ai_analysis.detection_methods) : currentCVE.detection_methods,
        upgrade_paths: result.ai_analysis?.upgrade_paths ? 
          JSON.stringify(result.ai_analysis.upgrade_paths) : currentCVE.upgrade_paths,
        correlation_confidence: result.asset_correlation?.correlation_confidence || currentCVE.correlation_confidence,
        potentially_affected_assets: result.asset_correlation?.total_potentially_affected || currentCVE.potentially_affected_assets,
        processed: true,
        last_analyzed: new Date().toISOString()
      };

      setCurrentCVE(updatedCVE);
      
      // Notify parent component about the analysis completion
      if (onUpdate) {
        onUpdate(updatedCVE);
      }

      setToast({ 
        message: 'CVE analysis completed successfully!', 
        type: 'success' 
      });

    } catch (error) {
      console.error('Analysis failed:', error);
      setToast({ 
        message: `Analysis failed: ${error.message}`, 
        type: 'error' 
      });
    } finally {
      setAnalyzing(false);
    }
  };

  if (!isOpen || !currentCVE) return null;

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
      let parsed = field;
      
      if (typeof field === 'string') {
        parsed = JSON.parse(field);
        if (typeof parsed === 'string') {
          parsed = JSON.parse(parsed);
        }
      }
      
      return Array.isArray(parsed) ? parsed : [parsed];
    } catch (error) {
      console.warn('Failed to parse JSON field:', error);
      return typeof field === 'string' ? [field] : [];
    }
  };

  const isAnalyzed = currentCVE.ai_summary || currentCVE.processed;

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50 p-4">
      {toast && (
        <Toast
          message={toast.message}
          type={toast.type}
          onClose={() => setToast(null)}
        />
      )}
      
      <div className="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b bg-gray-50 flex justify-between items-center">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">CVE Details</h2>
            <p className="text-sm text-gray-600">Comprehensive vulnerability information</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={refreshCVEData}
              disabled={refreshing}
              className="p-2 text-gray-400 hover:text-gray-600 disabled:opacity-50"
              title="Refresh CVE data"
            >
              <RefreshCw className={`h-5 w-5 ${refreshing ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={onClose}
              className="p-2 text-gray-400 hover:text-gray-600"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        <div className="overflow-y-auto max-h-[calc(90vh-140px)]">
          <div className="p-6 space-y-6">
            {/* CVE Header */}
            <div className="flex justify-between items-start">
              <div>
                <h3 className="text-2xl font-bold text-gray-900">{currentCVE.cve_id}</h3>
                <div className="flex items-center gap-4 mt-2">
                  <div className="flex items-center gap-2">
                    {getSeverityIcon(currentCVE.severity)}
                    <span className={`px-2 py-1 text-xs font-semibold rounded-full ${SEVERITY_COLORS[currentCVE.severity] || SEVERITY_COLORS.UNKNOWN}`}>
                      {currentCVE.severity || 'UNKNOWN'}
                    </span>
                  </div>
                  {currentCVE.cvss_score && (
                    <span className="text-sm text-gray-600">
                      CVSS: <span className="font-semibold">{currentCVE.cvss_score}</span>
                    </span>
                  )}
                  <span className="text-sm text-gray-600">
                    Published: {formatDate(currentCVE.published_date)}
                  </span>
                </div>
              </div>

              {/* Analysis Section */}
              <div className="flex flex-col items-end gap-3">
                <div className={`flex items-center gap-2 ${isAnalyzed ? 'text-green-600' : 'text-gray-500'}`}>
                  {isAnalyzed ? (
                    <>
                      <CheckCircle className="h-5 w-5" />
                      <span className="font-medium">Analysis Complete</span>
                    </>
                  ) : (
                    <>
                      <Clock className="h-5 w-5" />
                      <span className="font-medium">Not Analyzed</span>
                    </>
                  )}
                </div>
                {currentCVE.correlation_confidence && (
                  <span className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded-full">
                    <Target className="h-3 w-3" />
                    {(currentCVE.correlation_confidence * 100).toFixed(0)}% confidence
                  </span>
                )}
                <button
                  onClick={handleAnalyze}
                  disabled={analyzing}
                  className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 transition-colors"
                >
                  {analyzing ? (
                    <>
                      <Loader className="h-4 w-4 animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Database className="h-4 w-4" />
                      {isAnalyzed ? 'Re-analyze' : 'Analyze CVE'}
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* CVE Description */}
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-3">Description</h3>
              <p className="text-gray-700 leading-relaxed">{currentCVE.description}</p>
            </div>

            {/* AI Summary */}
            {currentCVE.ai_summary && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">AI Analysis Summary</h3>
                <div className="bg-purple-50 border border-purple-200 p-4 rounded-lg">
                  <p className="text-purple-800">{currentCVE.ai_summary}</p>
                </div>
              </div>
            )}

            {/* Mitigation Suggestions */}
            {currentCVE.mitigation_suggestions && currentCVE.mitigation_suggestions !== '[]' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">Mitigation Suggestions</h3>
                <div className="bg-green-50 border border-green-200 p-4 rounded-lg">
                  <div className="text-green-800">
                    {(() => {
                      const suggestions = parseJsonField(currentCVE.mitigation_suggestions);
                      if (suggestions.length > 0) {
                        return (
                          <ul className="list-disc list-inside space-y-1">
                            {suggestions.map((suggestion, index) => (
                              <li key={index}>{suggestion}</li>
                            ))}
                          </ul>
                        );
                      }
                      return <p>{currentCVE.mitigation_suggestions}</p>;
                    })()}
                  </div>
                </div>
              </div>
            )}

            {/* Detection Methods */}
            {currentCVE.detection_methods && currentCVE.detection_methods !== '[]' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">Detection Methods</h3>
                <div className="bg-yellow-50 border border-yellow-200 p-4 rounded-lg">
                  <div className="text-yellow-800">
                    {(() => {
                      const methods = parseJsonField(currentCVE.detection_methods);
                      if (methods.length > 0) {
                        return (
                          <ul className="list-disc list-inside space-y-1">
                            {methods.map((method, index) => (
                              <li key={index}>{method}</li>
                            ))}
                          </ul>
                        );
                      }
                      return <p>{currentCVE.detection_methods}</p>;
                    })()}
                  </div>
                </div>
              </div>
            )}

            {/* Upgrade Paths */}
            {currentCVE.upgrade_paths && currentCVE.upgrade_paths !== '[]' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">Upgrade Paths</h3>
                <div className="bg-indigo-50 border border-indigo-200 p-4 rounded-lg">
                  <div className="text-indigo-800">
                    {(() => {
                      const paths = parseJsonField(currentCVE.upgrade_paths);
                      if (paths.length > 0) {
                        return (
                          <div className="space-y-3">
                            {paths.map((path, index) => (
                              <div key={index}>
                                {typeof path === 'object' && path.patching_steps ? (
                                  <div>
                                    <div className="font-medium">{path.product || `Upgrade Path ${index + 1}`}</div>
                                    <div className="text-sm mt-1">{path.patching_steps}</div>
                                  </div>
                                ) : (
                                  <div>{typeof path === 'string' ? path : JSON.stringify(path)}</div>
                                )}
                              </div>
                            ))}
                          </div>
                        );
                      }
                      return <p>{currentCVE.upgrade_paths}</p>;
                    })()}
                  </div>
                </div>
              </div>
            )}

            {/* Asset Correlation */}
            {currentCVE.potentially_affected_assets && currentCVE.potentially_affected_assets > 0 && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">Asset Impact</h3>
                <div className="bg-orange-50 border border-orange-200 p-4 rounded-lg">
                  <div className="text-orange-800">
                    <div className="flex items-center gap-2">
                      <Server className="h-5 w-5" />
                      <span className="font-medium">
                        {currentCVE.potentially_affected_assets} potentially affected assets
                      </span>
                    </div>
                    {currentCVE.correlation_confidence && (
                      <div className="text-sm mt-1">
                        Correlation confidence: {(currentCVE.correlation_confidence * 100).toFixed(1)}%
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// Main CVE Management Component with enhanced state management
const CVEManagement = () => {
  const [cves, setCVEs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [selectedCVE, setSelectedCVE] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [collecting, setCollecting] = useState(false);
  const [analyzingCVEs, setAnalyzingCVEs] = useState(new Set());
  const [toasts, setToasts] = useState([]);

  // Toast management
  const addToast = (message, type = 'info') => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
  };

  const removeToast = (id) => {
    setToasts(prev => prev.filter(toast => toast.id !== id));
  };

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
      console.log('CVEs loaded:', data.length);
    } catch (error) {
      console.error('Failed to load CVEs:', error);
      setCVEs([]);
      addToast(`Failed to load CVEs: ${error.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  // Enhanced CVE analysis with proper state management
  const handleAnalyzeCVE = async (cveId) => {
    console.log('Starting analysis for CVE:', cveId);
    setAnalyzingCVEs(prev => new Set(prev).add(cveId));

    try {
      const result = await api.analyzeCVE(cveId);
      console.log('Analysis result received:', result);

      // Update the CVE in local state with proper field mapping
      setCVEs(prevCVEs =>
        prevCVEs.map(cve =>
          cve.cve_id === cveId
            ? {
                ...cve,
                ai_risk_score: result.ai_analysis?.risk_score || result.risk_assessment?.base_risk_score || cve.ai_risk_score,
                ai_summary: result.ai_analysis?.summary || cve.ai_summary,
                mitigation_suggestions: result.ai_analysis?.mitigations ? 
                  JSON.stringify(result.ai_analysis.mitigations) : cve.mitigation_suggestions,
                detection_methods: result.ai_analysis?.detection_methods ? 
                  JSON.stringify(result.ai_analysis.detection_methods) : cve.detection_methods,
                upgrade_paths: result.ai_analysis?.upgrade_paths ? 
                  JSON.stringify(result.ai_analysis.upgrade_paths) : cve.upgrade_paths,
                correlation_confidence: result.asset_correlation?.correlation_confidence || cve.correlation_confidence,
                potentially_affected_assets: result.asset_correlation?.total_potentially_affected || cve.potentially_affected_assets,
                processed: true,
                last_analyzed: new Date().toISOString()
              }
            : cve
        )
      );

      // Update selected CVE if it's the one being analyzed
      if (selectedCVE && selectedCVE.cve_id === cveId) {
        setSelectedCVE(prev => ({
          ...prev,
          ai_risk_score: result.ai_analysis?.risk_score || result.risk_assessment?.base_risk_score || prev.ai_risk_score,
          ai_summary: result.ai_analysis?.summary || prev.ai_summary,
          mitigation_suggestions: result.ai_analysis?.mitigations ? 
            JSON.stringify(result.ai_analysis.mitigations) : prev.mitigation_suggestions,
          detection_methods: result.ai_analysis?.detection_methods ? 
            JSON.stringify(result.ai_analysis.detection_methods) : prev.detection_methods,
          upgrade_paths: result.ai_analysis?.upgrade_paths ? 
            JSON.stringify(result.ai_analysis.upgrade_paths) : prev.upgrade_paths,
          correlation_confidence: result.asset_correlation?.correlation_confidence || prev.correlation_confidence,
          potentially_affected_assets: result.asset_correlation?.total_potentially_affected || prev.potentially_affected_assets,
          processed: true,
          last_analyzed: new Date().toISOString()
        }));
      }

      addToast(`CVE ${cveId} analysis completed successfully!`, 'success');
      console.log('CVE table updated for:', cveId);

    } catch (error) {
      console.error('Failed to analyze CVE:', error);
      addToast(`Analysis failed for ${cveId}: ${error.message}`, 'error');
    } finally {
      setAnalyzingCVEs(prev => {
        const newSet = new Set(prev);
        newSet.delete(cveId);
        return newSet;
      });
    }
  };

  // Handle CVE updates from modal
  const handleCVEUpdate = (updatedCVE) => {
    setCVEs(prevCVEs =>
      prevCVEs.map(cve =>
        cve.cve_id === updatedCVE.cve_id ? { ...cve, ...updatedCVE } : cve
      )
    );
    setSelectedCVE(updatedCVE);
  };

  const handleCVEClick = async (cve) => {
    try {
      // Always fetch fresh data when opening modal
      console.log('Fetching fresh CVE data for modal:', cve.cve_id);
      const response = await api.getCVE(cve.cve_id);
      
      // Handle the nested response structure
      const fullCVE = response.cve || response;
      setSelectedCVE(fullCVE);
      console.log('Fresh CVE data loaded:', fullCVE);
    } catch (error) {
      console.error('Failed to fetch CVE details:', error);
      setSelectedCVE(cve); // Fallback to existing data
      addToast(`Failed to fetch CVE details: ${error.message}`, 'warning');
    }
    setIsModalOpen(true);
  };

  const handleCollectCVEs = async () => {
    setCollecting(true);

    try {
      const response = await api.request('/cves/collect', {
        method: 'POST',
        body: JSON.stringify({
          days_back: 7,
          use_files: true
        })
      });

      addToast('CVE collection started in background! Check back in a few minutes.', 'success');
      
      // Refresh CVE list after a delay
      setTimeout(() => {
        loadCVEs();
      }, 30000);

    } catch (error) {
      console.error('CVE collection failed:', error);
      addToast(`CVE collection failed: ${error.message}`, 'error');
    } finally {
      setCollecting(false);
    }
  };

  // Filter CVEs based on search term
  const filteredCVEs = cves.filter(cve => {
    const matchesSearch = !searchTerm || 
      cve.cve_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      cve.description.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesSearch;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader className="h-8 w-8 animate-spin text-blue-600" />
        <span className="ml-2 text-gray-600">Loading CVEs...</span>
      </div>
    );
  }

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        {/* Toast Notifications */}
        {toasts.map(toast => (
          <Toast
            key={toast.id}
            message={toast.message}
            type={toast.type}
            onClose={() => removeToast(toast.id)}
          />
        ))}

        {/* Header */}
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">CVE Management</h1>
            <p className="text-gray-600">Manage and analyze Common Vulnerabilities and Exposures</p>
          </div>
          <button
            onClick={handleCollectCVEs}
            disabled={collecting}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
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

        {/* Filters */}
        <div className="bg-white p-4 rounded-lg shadow flex gap-4 flex-wrap items-center">
          <div className="flex-1 max-w-md relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
            <input
              type="text"
              placeholder="Search CVEs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        {/* CVE Table */}
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">CVE ID</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">CVSS Score</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">AI Score</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Published</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Analysis Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredCVEs.map((cve) => {
                  const isAnalyzing = analyzingCVEs.has(cve.cve_id);
                  const isAnalyzed = cve.ai_summary || cve.processed;
                  
                  return (
                    <tr key={cve.cve_id} className="hover:bg-gray-50 cursor-pointer" onClick={() => handleCVEClick(cve)}>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm font-medium text-blue-600 hover:text-blue-800">
                          {cve.cve_id}
                        </div>
                        <div className="text-sm text-gray-500 truncate max-w-xs">
                          {cve.description?.substring(0, 60)}...
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${SEVERITY_COLORS[cve.severity] || SEVERITY_COLORS.UNKNOWN}`}>
                          {cve.severity || 'UNKNOWN'}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {cve.cvss_score ? (
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                            cve.cvss_score >= 9 ? 'bg-red-100 text-red-800' :
                            cve.cvss_score >= 7 ? 'bg-orange-100 text-orange-800' :
                            cve.cvss_score >= 4 ? 'bg-yellow-100 text-yellow-800' :
                            'bg-green-100 text-green-800'
                          }`}>
                            {cve.cvss_score}
                          </span>
                        ) : (
                          <span className="text-gray-400">N/A</span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {cve.ai_risk_score ? (
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                            cve.ai_risk_score >= 8 ? 'bg-purple-100 text-purple-800' :
                            cve.ai_risk_score >= 6 ? 'bg-indigo-100 text-indigo-800' :
                            cve.ai_risk_score >= 4 ? 'bg-blue-100 text-blue-800' :
                            'bg-gray-100 text-gray-800'
                          }`}>
                            {Number(cve.ai_risk_score).toFixed(1)}
                          </span>
                        ) : (
                          <span className="text-gray-400">-</span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {cve.published_date ? new Date(cve.published_date).toLocaleDateString() : 'N/A'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          {isAnalyzing ? (
                            <div className="flex items-center gap-1 text-blue-600">
                              <Loader className="h-4 w-4 animate-spin" />
                              <span className="text-xs">Analyzing...</span>
                            </div>
                          ) : isAnalyzed ? (
                            <div className="flex items-center gap-1 text-green-600">
                              <CheckCircle className="h-4 w-4" />
                              <span className="text-xs">Analyzed</span>
                            </div>
                          ) : (
                            <div className="flex items-center gap-1 text-gray-500">
                              <Clock className="h-4 w-4" />
                              <span className="text-xs">Pending</span>
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleAnalyzeCVE(cve.cve_id);
                          }}
                          disabled={isAnalyzing}
                          className="text-purple-600 hover:text-purple-900 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {isAnalyzing ? 'Analyzing...' : isAnalyzed ? 'Re-analyze' : 'Analyze'}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            
            {filteredCVEs.length === 0 && (
              <div className="text-center py-8 text-gray-500">
                <div className="flex flex-col items-center">
                  <Search className="h-12 w-12 text-gray-300 mb-4" />
                  <p className="text-lg font-medium">No CVEs found</p>
                  <p className="text-sm">Try adjusting your search criteria or collect new CVEs</p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* CVE Modal */}
        {isModalOpen && selectedCVE && (
          <CVEModal
            cve={selectedCVE}
            isOpen={isModalOpen}
            onClose={() => {
              setIsModalOpen(false);
              setSelectedCVE(null);
            }}
            onUpdate={handleCVEUpdate}
          />
        )}
      </div>
    </ErrorBoundary>
  );
};

export default CVEManagement;
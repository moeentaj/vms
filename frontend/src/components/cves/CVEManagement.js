// Updated CVEManagement.js with real-time table updates and proper modal refresh

import React, { useState, useEffect } from 'react';
import { Plus, Info, Search, Loader, X, AlertTriangle, Shield, Calendar, ExternalLink, Target, Server, CheckCircle, XCircle, Clock, Database, Monitor } from 'lucide-react';
import { api } from '../../services/api';

// Severity color mappings
const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-100 text-red-800 border-red-200',
  HIGH: 'bg-orange-100 text-orange-800 border-orange-200',
  MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  LOW: 'bg-green-100 text-green-800 border-green-200',
  UNKNOWN: 'bg-gray-100 text-gray-800 border-gray-200'
};

// Enhanced CVE Modal Component
const CVEModal = ({ cve, isOpen, onClose, onUpdate, onAnalysisComplete }) => {
  const [analyzing, setAnalyzing] = useState(false);
  const [currentCVE, setCurrentCVE] = useState(cve);
  const [refreshing, setRefreshing] = useState(false);

  // Update current CVE when prop changes
  useEffect(() => {
    setCurrentCVE(cve);
    if (cve) {
      console.log('Modal received CVE data:', cve);
      console.log('CVE analysis fields:', {
        ai_risk_score: cve.ai_risk_score,
        ai_summary: cve.ai_summary,
        processed: cve.processed,
        mitigation_suggestions: cve.mitigation_suggestions,
        detection_methods: cve.detection_methods,
        upgrade_paths: cve.upgrade_paths
      });
    }
  }, [cve]);

  // Refresh CVE data from server
  const refreshCVEData = async () => {
    if (!currentCVE?.cve_id) return;
    
    setRefreshing(true);
    try {
      const response = await api.getCVE(currentCVE.cve_id);
      
      // Handle the nested response structure
      const updatedCVE = response.cve || response;
      setCurrentCVE(updatedCVE);
      console.log('CVE data refreshed:', updatedCVE);
      console.log('API response structure:', response);
    } catch (error) {
      console.error('Failed to refresh CVE data:', error);
    } finally {
      setRefreshing(false);
    }
  };

  const handleAnalyze = async () => {
    if (!currentCVE?.cve_id) return;
    
    setAnalyzing(true);
    try {
      console.log('Starting analysis for CVE:', currentCVE.cve_id);
      const result = await api.analyzeCVE(currentCVE.cve_id);
      console.log('Analysis result received:', result);

      // Update current CVE with analysis results
      const updatedCVE = {
        ...currentCVE,
        ai_risk_score: result.ai_analysis?.risk_score || result.risk_assessment?.base_risk_score,
        ai_summary: result.ai_analysis?.summary,
        mitigation_suggestions: JSON.stringify(result.ai_analysis?.mitigations || []),
        detection_methods: JSON.stringify(result.ai_analysis?.detection_methods || []),
        upgrade_paths: JSON.stringify(result.ai_analysis?.upgrade_paths || []),
        processed: true,
        correlation_confidence: result.asset_correlation?.correlation_confidence,
        last_analyzed: new Date().toISOString()
      };

      setCurrentCVE(updatedCVE);
      
      // Notify parent components about the analysis completion
      if (onAnalysisComplete) {
        onAnalysisComplete(currentCVE.cve_id, updatedCVE);
      }
      
      if (onUpdate) {
        onUpdate();
      }

    } catch (error) {
      console.error('Analysis failed:', error);
      alert(`Analysis failed: ${error.message}`);
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
      // Handle double-encoded JSON strings like "\"[\\\"item1\\\", \\\"item2\\\"]\""
      let parsed = field;
      
      // If it's a string, try to parse it
      if (typeof field === 'string') {
        // First, try to parse as JSON
        parsed = JSON.parse(field);
        
        // If the result is still a string (double-encoded), parse again
        if (typeof parsed === 'string') {
          parsed = JSON.parse(parsed);
        }
      }
      
      // Ensure it's an array
      return Array.isArray(parsed) ? parsed : [parsed];
    } catch (error) {
      console.error('Failed to parse JSON field:', field, error);
      // If parsing fails, try to extract as plain string
      if (typeof field === 'string' && field !== '[]' && field !== '{}') {
        return [field];
      }
      return [];
    }
  };

  const isAnalyzed = currentCVE.processed || currentCVE.ai_risk_score || currentCVE.ai_summary;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg max-w-6xl w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex justify-between items-center p-6 border-b">
          <div className="flex items-center gap-3">
            {getSeverityIcon(currentCVE.severity)}
            <h2 className="text-2xl font-bold text-gray-900">{currentCVE.cve_id}</h2>
            <span className={`inline-flex px-3 py-1 text-sm font-semibold rounded-full border ${SEVERITY_COLORS[currentCVE.severity] || SEVERITY_COLORS.UNKNOWN}`}>
              {currentCVE.severity || 'UNKNOWN'}
            </span>
            {isAnalyzed && (
              <span className="inline-flex items-center gap-1 px-2 py-1 text-sm bg-green-100 text-green-800 rounded-full">
                <CheckCircle className="h-3 w-3" />
                Analyzed
              </span>
            )}
            {currentCVE.ai_risk_score && (
              <span className="inline-flex items-center gap-1 px-2 py-1 text-sm bg-purple-100 text-purple-800 rounded-full">
                <Database className="h-3 w-3" />
                AI Risk: {currentCVE.ai_risk_score.toFixed(1)}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={refreshCVEData}
              disabled={refreshing}
              className="p-2 text-gray-400 hover:text-gray-600 transition-colors disabled:opacity-50"
              title="Refresh CVE data"
            >
              <Monitor className={`h-5 w-5 ${refreshing ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 transition-colors"
            >
              <X className="h-6 w-6" />
            </button>
          </div>
        </div>

        <div className="flex">
          {/* Left side - CVE Details */}
          <div className="flex-1 p-6 space-y-6">
            {/* Basic Information */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="text-sm font-medium text-gray-500 mb-1">CVSS Score</h3>
                <p className="text-2xl font-bold text-gray-900">{currentCVE.cvss_score || 'N/A'}</p>
              </div>
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="text-sm font-medium text-gray-500 mb-1">AI Risk Score</h3>
                <p className="text-2xl font-bold text-orange-600">
                  {currentCVE.ai_risk_score ? currentCVE.ai_risk_score.toFixed(1) : 'Not analyzed'}
                </p>
              </div>
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="text-sm font-medium text-gray-500 mb-1">Published</h3>
                <p className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                  <Calendar className="h-4 w-4" />
                  {formatDate(currentCVE.published_date)}
                </p>
              </div>
            </div>

            {/* Analysis Status and Actions */}
            <div className="bg-blue-50 border border-blue-200 p-4 rounded-lg">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
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
                </div>
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
                                  // Handle structured upgrade path objects
                                  <div>
                                    {path.version_requirements && (
                                      <div className="mb-2">
                                        <strong>Version Requirements:</strong> {path.version_requirements}
                                      </div>
                                    )}
                                    {path.patching_steps && (
                                      <div>
                                        <strong>Patching Steps:</strong>
                                        <ul className="list-disc list-inside mt-1 space-y-1">
                                          {Array.isArray(path.patching_steps) ? 
                                            path.patching_steps.map((step, stepIndex) => (
                                              <li key={stepIndex}>{step}</li>
                                            )) :
                                            <li>{path.patching_steps}</li>
                                          }
                                        </ul>
                                      </div>
                                    )}
                                  </div>
                                ) : (
                                  // Handle simple string upgrade paths
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
          </div>
        </div>
      </div>
    </div>
  );
};

// Main CVE Management Component
const CVEManagement = () => {
  const [cves, setCVEs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
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
      console.log('CVEs loaded:', data.length);
    } catch (error) {
      console.error('Failed to load CVEs:', error);
      setCVEs([]);
      setError('Failed to load CVEs');
    } finally {
      setLoading(false);
    }
  };

  // Enhanced handleAnalyzeCVE with real-time table updates
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
                // Map from the new API response structure
                ai_risk_score: result.ai_analysis?.risk_score || result.risk_assessment?.base_risk_score,
                ai_summary: result.ai_analysis?.summary,
                mitigation_suggestions: JSON.stringify(result.ai_analysis?.mitigations || []),
                detection_methods: JSON.stringify(result.ai_analysis?.detection_methods || []),
                upgrade_paths: JSON.stringify(result.ai_analysis?.upgrade_paths || []),
                correlation_confidence: result.asset_correlation?.correlation_confidence,
                processed: true,
                last_analyzed: new Date().toISOString()
              }
            : cve
        )
      );

      console.log('CVE table updated for:', cveId);

    } catch (error) {
      console.error('Failed to analyze CVE:', error);
      setError(`Analysis failed for ${cveId}: ${error.message}`);
    } finally {
      setAnalyzingCVEs(prev => {
        const newSet = new Set(prev);
        newSet.delete(cveId);
        return newSet;
      });
    }
  };

  // Handle analysis completion from modal
  const handleAnalysisComplete = (cveId, updatedCVE) => {
    console.log('Analysis completed in modal for:', cveId);
    setCVEs(prevCVEs =>
      prevCVEs.map(cve =>
        cve.cve_id === cveId ? { ...cve, ...updatedCVE } : cve
      )
    );
  };

  const handleCVEClick = async (cve) => {
    try {
      // Always fetch fresh data when opening modal
      console.log('Fetching fresh CVE data for modal:', cve.cve_id);
      const response = await api.getCVE(cve.cve_id);
      
      // Handle the nested response structure
      const fullCVE = response.cve || response; // Extract CVE from nested structure if present
      setSelectedCVE(fullCVE);
      console.log('Fresh CVE data loaded:', fullCVE);
      console.log('API response structure:', response);
    } catch (error) {
      console.error('Failed to fetch CVE details:', error);
      setSelectedCVE(cve); // Fallback to existing data
    }
    setIsModalOpen(true);
  };

  const handleCollectCVEs = async () => {
    setCollecting(true);
    setError('');
    setMessage('');

    try {
      const response = await api.request('/cves/enhance-collection', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          days_back: 7,
          use_files: true
        })
      });

      setMessage('CVE collection started in background! Check back in a few minutes.');
      
      // Refresh CVE list after a delay
      setTimeout(() => {
        loadCVEs();
      }, 30000);

    } catch (error) {
      console.error('CVE collection failed:', error);
      setError(`CVE collection failed: ${error.message}`);
    } finally {
      setCollecting(false);
    }
  };

  // Clear messages after some time
  useEffect(() => {
    if (message) {
      const timer = setTimeout(() => setMessage(''), 5000);
      return () => clearTimeout(timer);
    }
  }, [message]);

  useEffect(() => {
    if (error) {
      const timer = setTimeout(() => setError(''), 5000);
      return () => clearTimeout(timer);
    }
  }, [error]);

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
    <div className="space-y-6">
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

      {/* Messages */}
      {message && (
        <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded">
          {message}
        </div>
      )}
      
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
          {error}
        </div>
      )}

      {/* Filters */}
      <div className="bg-white p-4 rounded-lg shadow space-y-4">
        <div className="flex gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="h-5 w-5 absolute left-3 top-3 text-gray-400" />
              <input
                type="text"
                placeholder="Search CVEs by ID or description..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
        
        <div className="flex items-center justify-between text-sm text-gray-600">
          <div className="flex items-center gap-4">
            <span>Total CVEs: {cves.length}</span>
            <span>Filtered: {filteredCVEs.length}</span>
            <span>Analyzed: {cves.filter(cve => cve.ai_risk_score || cve.processed).length}</span>
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
                    {cve.processed || cve.ai_risk_score ? (
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
                      className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
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
                          {cve.ai_risk_score ? 'Re-analyze' : 'Analyze'}
                        </div>
                      )}
                    </button>
                    <button
                      onClick={() => handleCVEClick(cve)}
                      className="text-blue-600 hover:text-blue-900 hover:bg-blue-50 px-3 py-1 rounded text-sm transition-colors"
                    >
                      View
                    </button>
                    <button className="text-green-600 hover:text-green-900 hover:bg-green-50 px-3 py-1 rounded text-sm transition-colors">
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
                disabled={collecting}
                className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {collecting ? 'Collecting...' : 'Collect CVEs'}
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
        onAnalysisComplete={handleAnalysisComplete}
      />
    </div>
  );
};

export default CVEManagement;
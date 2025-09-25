// Complete Restructured API Service - frontend/src/services/api.js
// Includes rate limiting, proper error handling, and organized structure

export const api = {
  baseURL: 'http://localhost:8000/api/v1',
  
  // Rate limiting to prevent spam requests (especially for CPE endpoints)
  _requestCounts: new Map(),
  _maxRequestsPerMinute: 30,
  _cpeMaxRequestsPerMinute: 10, // More restrictive for CPE endpoints
  
  // Check rate limit
  _checkRateLimit: function(endpoint) {
    const now = Date.now();
    const minute = Math.floor(now / 60000);
    
    // Use different limits for CPE endpoints
    const isCPEEndpoint = endpoint.includes('cpe-lookup') || endpoint.includes('cpe');
    const maxRequests = isCPEEndpoint ? this._cpeMaxRequestsPerMinute : this._maxRequestsPerMinute;
    const key = `${endpoint}_${minute}`;
    
    const count = this._requestCounts.get(key) || 0;
    if (count >= maxRequests) {
      throw new Error(`Rate limit exceeded for ${endpoint}. Please wait a moment.`);
    }
    
    this._requestCounts.set(key, count + 1);
    
    // Clean old entries
    for (const [k, v] of this._requestCounts.entries()) {
      const keyMinute = parseInt(k.split('_').pop());
      if (keyMinute < minute - 1) {
        this._requestCounts.delete(k);
      }
    }
  },

  // Core request method with enhanced error handling
  request: async function(endpoint, options = {}) {
    // Apply rate limiting
    try {
      this._checkRateLimit(endpoint);
    } catch (rateLimitError) {
      throw rateLimitError;
    }

    const token = localStorage.getItem('token');
    const url = `${this.baseURL}${endpoint}`;

    // Build headers safely
    const defaultHeaders = {};
    // Only set JSON content-type if the body is not FormData
    const isFormData = options?.body instanceof FormData;
    if (!isFormData) {
      defaultHeaders['Content-Type'] = 'application/json';
    }
    if (token) {
      defaultHeaders['Authorization'] = `Bearer ${token}`;
    }

    const config = {
      method: options.method || 'GET',
      ...options,
      // headers: default + user headers, with user headers taking precedence
      headers: {
        ...defaultHeaders,
        ...(options.headers || {}),
      },
    };

    try {
      console.log(`Making request to: ${url}`);
      const response = await fetch(url, config);

      if (!response.ok) {
        let errorData;
        try {
          errorData = await response.json();
        } catch (parseError) {
          errorData = { detail: `HTTP ${response.status}: ${response.statusText}` };
        }

        const errorMessage = errorData.detail || errorData.message || `HTTP ${response.status}: ${response.statusText}`;
        console.error(`API Error (${endpoint}):`, {
          status: response.status,
          statusText: response.statusText,
          errorData,
          url
        });

        throw new Error(errorMessage);
      }

      const data = await response.json();
      console.log(`API Success (${endpoint}):`, data);
      return data;

    } catch (error) {
      // Enhanced error handling to avoid [object Object] issues
      if (error instanceof TypeError && error.message.includes('fetch')) {
        const networkError = `Network error: Unable to connect to ${url}`;
        console.error(`API Network Error (${endpoint}):`, networkError);
        throw new Error(networkError);
      }

      if (error instanceof Error && error.message) {
        console.error(`API Error (${endpoint}):`, error.message);
        throw error;
      }

      const fallbackError = `Request failed: ${String(error)}`;
      console.error(`API Unexpected Error (${endpoint}):`, fallbackError);
      throw new Error(fallbackError);
    }
  },

  // ===== AUTHENTICATION ENDPOINTS =====
  
  login: async function(username, password) {
    const requestBody = { username, password };
    console.log('About to send request body:', requestBody);
    return this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify(requestBody),
    });
  },

  logout: async function() {
    return this.request('/auth/logout', { method: 'POST' });
  },

  getProfile: async function() {
    return this.request('/auth/profile');
  },

  updateProfile: async function(data) {
    return this.request('/auth/profile', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  register: async function(userData) {
    return this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData),
    });
  },

  // User Management
  getUsers: async function() {
    return this.request('/auth/users');
  },

  createUser: async function(userData) {
    return this.request('/auth/users', {
      method: 'POST',
      body: JSON.stringify(userData),
    });
  },

  updateUser: async function(userId, userData) {
    return this.request(`/auth/users/${userId}`, {
      method: 'PUT',
      body: JSON.stringify(userData),
    });
  },

  deleteUser: async function(userId) {
    return this.request(`/auth/users/${userId}`, {
      method: 'DELETE',
    });
  },

  getUserById: async function(userId) {
    return this.request(`/auth/users/${userId}`);
  },

  changeUserPassword: async function(userId, passwordData) {
    return this.request(`/auth/users/${userId}/password`, {
      method: 'PUT',
      body: JSON.stringify(passwordData),
    });
  },

  resetUserPassword: async function(userId) {
    return this.request(`/auth/users/${userId}/reset-password`, {
      method: 'POST',
    });
  },

  activateUser: async function(userId) {
    return this.request(`/auth/users/${userId}/activate`, {
      method: 'POST',
    });
  },

  deactivateUser: async function(userId) {
    return this.request(`/auth/users/${userId}/deactivate`, {
      method: 'POST',
    });
  },

  // ===== ASSET ENDPOINTS =====

  getAssets: async function(params = {}) {
    const cleanParams = {};
    for (const [key, value] of Object.entries(params)) {
      if (value !== '' && value !== null && value !== undefined) {
        cleanParams[key] = value;
      }
    }
    const query = new URLSearchParams(cleanParams).toString();
    return this.request(`/assets/?${query}`);
  },

  getAsset: async function(assetId) {
    return this.request(`/assets/${assetId}`);
  },

  createAsset: async function(assetData) {
    return this.request('/assets/', {
      method: 'POST',
      body: JSON.stringify(assetData),
    });
  },

  updateAsset: async function(assetId, assetData) {
    return this.request(`/assets/${assetId}`, {
      method: 'PUT',
      body: JSON.stringify(assetData),
    });
  },

  deleteAsset: async function(assetId) {
    return this.request(`/assets/${assetId}`, {
      method: 'DELETE',
    });
  },

  bulkUpdateAssets: async function(assetUpdates) {
    return this.request('/assets/bulk-update', {
      method: 'PUT',
      body: JSON.stringify(assetUpdates),
    });
  },

  importAssets: async function(assetData) {
    return this.request('/assets/import', {
      method: 'POST',
      body: JSON.stringify(assetData),
    });
  },

  exportAssets: async function(format = 'json') {
    return this.request(`/assets/export?format=${format}`);
  },

  getAssetTypes: async function() {
    return this.request('/assets/types');
  },

  getAssetEnvironments: async function() {
    return this.request('/assets/environments');
  },

  searchAssets: async function(query) {
    return this.request(`/assets/search?q=${encodeURIComponent(query)}`);
  },

  // ===== CPE LOOKUP ENDPOINTS (Enhanced with proper error handling) =====

  // Enhanced CPE methods (add to your existing api object)
smartCPESearch: async function(query, options = {}) {
  try {
    // Try enhanced search first
    const params = new URLSearchParams({
      q: query,
      limit: options.limit?.toString() || '20',
      ...(options.vendor && { vendor: options.vendor }),
      ...(options.category && { category: options.category }),
      ...(options.include_deprecated && { include_deprecated: 'true' })
    });
    
    return await this.request(`/cpe-lookup/search?${params.toString()}`);
  } catch (error) {
    console.warn('Enhanced CPE search failed, falling back:', error.message);
    // Fallback to your existing method
    return await this.searchCPE(query, options.limit || 20);
  }
},

// Enhanced CPE lookup for your asset modals (replaces cpeLookup)
enhancedCPELookup: async function(query, limit = 12) {
  if (!query || !query.trim()) {
    throw new Error('Query cannot be empty');
  }
  
  if (query.length < 2) {
    throw new Error('Query must be at least 2 characters long');
  }
  
  try {
    // Try enhanced search via /cpe-lookup/search
    const result = await this.request(`/cpe-lookup/search?q=${encodeURIComponent(query)}&limit=${limit}`);
    return result.products || [];
  } catch (error) {
    console.warn('Enhanced CPE lookup failed, trying fallback:', error.message);
    
    // Fallback to your existing /assets/cpe-lookup endpoint
    try {
      return await this.request('/assets/cpe-lookup', {
        method: 'POST',
        body: JSON.stringify({ 
          query: query.trim(), 
          limit: Math.max(1, Math.min(limit, 50))
        }),
      });
    } catch (fallbackError) {
      throw new Error(`CPE lookup failed: ${fallbackError.message}`);
    }
  }
},

// Get search suggestions for autocomplete
getCPESearchSuggestions: async function(partialQuery, limit = 10) {
  if (!partialQuery || partialQuery.length < 2) {
    return { suggestions: [], query: partialQuery };
  }
  
  try {
    const result = await this.request(`/cpe-lookup/suggestions?q=${encodeURIComponent(partialQuery)}&limit=${limit}`);
    return result;
  } catch (error) {
    console.warn('CPE suggestions not available:', error.message);
    
    // Fallback: try enhanced search and extract suggestions
    try {
      const searchResult = await this.smartCPESearch(partialQuery, { limit: 5 });
      const suggestions = searchResult.products?.map(p => `${p.vendor} ${p.product}`) || [];
      return { suggestions: suggestions.slice(0, limit), query: partialQuery };
    } catch (fallbackError) {
      return { suggestions: [], query: partialQuery };
    }
  }
},

// Enhanced status check
smartCPEStatus: async function() {
  try {
    const status = await this.getCPEStatus();
    return {
      ...status,
      enhanced_features_available: true, // Will be true if enhanced backend is available
    };
  } catch (error) {
    console.warn('CPE status check failed:', error.message);
    return { has_data: false, enhanced_features_available: false };
  }
},

  // Enhanced CPE lookup with validation and error handling
  cpeLookup: async function(query, limit = 12) {
    if (!query || !query.trim()) {
      throw new Error('Query cannot be empty');
    }
    
    if (query.length < 2) {
      throw new Error('Query must be at least 2 characters long');
    }
    
    return this.request('/assets/cpe-lookup', {
      method: 'POST',
      body: JSON.stringify({ 
        query: query.trim(), 
        limit: Math.max(1, Math.min(limit, 50)) // Ensure reasonable limits
      }),
    });
  },

  // Alias for backward compatibility
  lookupCPEServices: async function(query, limit = 12) {
    return this.cpeLookup(query, limit);
  },

  // CPE Status and Management
  getCPEStatus: async function() {
    return this.request('/cpe-lookup/status');
  },

  triggerCPEIngestion: async function(forceRefresh = false) {
    const endpoint = forceRefresh ? '/cpe-lookup/ingest?force_refresh=true' : '/cpe-lookup/ingest';
    return this.request(endpoint, { method: 'POST' });
  },

  // Alias for consistency
  initializeCPE: async function(forceRefresh = false) {
    return this.triggerCPEIngestion(forceRefresh);
  },

  // Advanced CPE operations
  searchCPEProducts: async function(searchData) {
    return this.request('/cpe-lookup/search', {
      method: 'POST',
      body: JSON.stringify(searchData),
    });
  },

  searchCPE: async function(query, limit = 20) {
    const params = new URLSearchParams({ q: query, limit: limit.toString() });
    return this.request(`/cpe-lookup/search?${params.toString()}`);
  },

  getCPEProduct: async function(cpeNameId) {
    return this.request(`/cpe-lookup/product/${cpeNameId}`);
  },

  getCPEVendors: async function(query = null, limit = 50) {
    const params = new URLSearchParams();
    if (query) params.append('query', query);
    params.append('limit', limit.toString());
    return this.request(`/cpe-lookup/vendors?${params.toString()}`);
  },

  getCPEProductsByVendor: async function(vendor, limit = 50) {
    const params = new URLSearchParams({ vendor, limit: limit.toString() });
    return this.request(`/cpe-lookup/products?${params.toString()}`);
  },

  clearCPECache: async function() {
    return this.request('/cpe-lookup/cache', {
      method: 'DELETE',
    });
  },

  // ===== CVE ENDPOINTS =====

  getCVEs: async function(params = {}) {
    const cleanParams = {};
    for (const [key, value] of Object.entries(params)) {
      if (value !== '' && value !== null && value !== undefined) {
        cleanParams[key] = value;
      }
    }
    const query = new URLSearchParams(cleanParams).toString();
    return this.request(`/cves/?${query}`);
  },

  getCVE: async function(cveId) {
    return this.request(`/cves/${cveId}`);
  },

  collectCVEs: async function(daysBack = 7, useFiles = true) {
    return this.request('/cves/collect', {
      method: 'POST',
      body: JSON.stringify({
        days_back: daysBack,
        use_files: useFiles
      }),
    });
  },

  collectCVEsImmediate: async function(daysBack = 7, useFiles = true) {
    return this.request('/cves/collect-immediate', {
      method: 'POST',
      body: JSON.stringify({
        days_back: daysBack,
        use_files: useFiles
      }),
    });
  },

  analyzeCVE: async function(cveId, includeAssetCorrelation = true) {
    return this.request(`/cves/${cveId}/analyze?include_asset_correlation=${includeAssetCorrelation}`, {
      method: 'POST',
    });
  },

  getCVEStatistics: async function() {
    return this.request('/cves/stats');
  },

  testCVECollection: async function(daysBack = 1, useFiles = true) {
    return this.request(`/cves/test-collection?days_back=${daysBack}&use_files=${useFiles}`);
  },

  enhanceCollection: async function(daysBack = 7, useFiles = true) {
    return this.request('/cves/enhance-collection', {
      method: 'POST',
      body: JSON.stringify({
        days_back: daysBack,
        use_files: useFiles
      }),
    });
  },

  manualCollect: async function(daysBack = 1, useFiles = true) {
    return this.request('/cves/manual-collect', {
      method: 'POST',
      body: JSON.stringify({
        days_back: daysBack,
        use_files: useFiles
      }),
    });
  },

  getCollectionStats: async function() {
    return this.request('/cves/collection-stats');
  },

  testFileDownload: async function() {
    return this.request('/cves/test-file-download');
  },

  // ===== ASSIGNMENT ENDPOINTS =====

  getAssignments: async function(params = {}) {
    const cleanParams = {};
    for (const [key, value] of Object.entries(params)) {
      if (value !== '' && value !== null && value !== undefined) {
        cleanParams[key] = value;
      }
    }
    const query = new URLSearchParams(cleanParams).toString();
    const endpoint = `/assignments/?${query}`;

    try {
      return await this.request(endpoint);
    } catch (error) {
      console.error('getAssignments error:', error);
      throw error;
    }
  },

  getAssignment: async function(assignmentId) {
    return this.request(`/assignments/${assignmentId}`);
  },

  createAssignment: async function(assignmentData) {
    return this.request('/assignments/', {
      method: 'POST',
      body: JSON.stringify(assignmentData),
    });
  },

  updateAssignment: async function(id, data) {
    return this.request(`/assignments/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  deleteAssignment: async function(assignmentId) {
    return this.request(`/assignments/${assignmentId}`, {
      method: 'DELETE',
    });
  },

  getAssignmentStats: async function() {
    return this.request('/assignments/dashboard/stats');
  },

  getMyAssignments: async function(status = null) {
    const params = { my_assignments: true };
    if (status) params.status = status;
    return this.getAssignments(params);
  },

  bulkUpdateAssignments: async function(updates) {
    return this.request('/assignments/bulk-update', {
      method: 'PUT',
      body: JSON.stringify(updates),
    });
  },

  getAssignmentHistory: async function(assignmentId) {
    return this.request(`/assignments/${assignmentId}/history`);
  },

  addAssignmentComment: async function(assignmentId, comment) {
    return this.request(`/assignments/${assignmentId}/comments`, {
      method: 'POST',
      body: JSON.stringify({ comment }),
    });
  },

  batchCreateAssignments: async function(assignments) {
    return this.request('/assignments/batch-create', {
      method: 'POST',
      body: JSON.stringify(assignments),
    });
  },

  // ===== RECOMMENDATION ENDPOINTS =====

  getRecommendations: async function(params = {}) {
    const query = new URLSearchParams(params).toString();
    return this.request(`/recommendations/?${query}`);
  },

  getDashboardData: async function() {
    return this.request('/recommendations/dashboard');
  },

  createRecommendation: async function(recommendationData) {
    return this.request('/recommendations/', {
      method: 'POST',
      body: JSON.stringify(recommendationData),
    });
  },

  updateRecommendation: async function(recommendationId, data) {
    return this.request(`/recommendations/${recommendationId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  deleteRecommendation: async function(recommendationId) {
    return this.request(`/recommendations/${recommendationId}`, {
      method: 'DELETE',
    });
  },

  getRecommendationsByAsset: async function(assetId) {
    return this.request(`/recommendations/asset/${assetId}`);
  },

  getRecommendationsByCVE: async function(cveId) {
    return this.request(`/recommendations/cve/${cveId}`);
  },

  // ===== CPE-CVE CORRELATION ENDPOINTS =====

  correlateCPEToCVEs: async function(correlationData) {
    return this.request('/cpe-cve-correlation/correlate-cpe', {
      method: 'POST',
      body: JSON.stringify(correlationData),
    });
  },

  getCPEVulnerabilities: async function(cpeName) {
    if (!cpeName || !cpeName.trim()) {
      throw new Error('CPE name is required');
    }
    const encodedCPE = encodeURIComponent(cpeName);
    return this.request(`/cpe-cve-correlation/cpe/${encodedCPE}/vulnerabilities`);
  },

  assessAssetVulnerabilities: async function(assetId) {
    return this.request(`/cpe-cve-correlation/assets/${assetId}/vulnerabilities`);
  },

  getAssetVulnerabilities: async function(assetId) {
    return this.assessAssetVulnerabilities(assetId);
  },

  bulkAssessAssets: async function(assessmentData) {
    return this.request('/cpe-cve-correlation/assets/bulk-assess', {
      method: 'POST',
      body: JSON.stringify(assessmentData),
    });
  },

  searchVulnerabilities: async function(params = {}) {
    const cleanParams = {};
    for (const [key, value] of Object.entries(params)) {
      if (value !== '' && value !== null && value !== undefined) {
        cleanParams[key] = value;
      }
    }
    const query = new URLSearchParams(cleanParams).toString();
    return this.request(`/cpe-cve-correlation/vulnerabilities/search?${query}`);
  },

  getAssetCPEMappings: async function(assetId) {
    return this.request(`/cpe-cve-correlation/assets/${assetId}/cpe-mappings`);
  },

  triggerAssetAssessment: async function(assetId) {
    return this.request(`/cpe-cve-correlation/assets/${assetId}/trigger-assessment`, {
      method: 'POST',
    });
  },

  getEnhancedAffectedAssets: async function(cveId, confidenceThreshold = 0.7) {
    return this.request(`/cpe-cve-correlation/cves/${cveId}/affected-assets-enhanced?confidence_threshold=${confidenceThreshold}`);
  },

  getCVEAffectedAssets: async function(cveId) {
    return this.request(`/cpe-cve-correlation/cves/${cveId}/affected-assets`);
  },

  getVulnerabilityDashboard: async function(environment = null) {
    const params = environment ? `?environment=${encodeURIComponent(environment)}` : '';
    return this.request(`/cpe-cve-correlation/dashboard/vulnerability-overview${params}`);
  },

  // ===== DASHBOARD AND ANALYTICS =====

  getHealthCheck: async function() {
    return this.request('/health');
  },

  getSystemStats: async function() {
    return this.request('/dashboard/stats');
  },

  getAnalytics: async function(timeRange = '30d') {
    return this.request(`/analytics?range=${timeRange}`);
  },

  getVulnerabilityTrends: async function(timeRange = '30d') {
    return this.request(`/analytics/vulnerability-trends?range=${timeRange}`);
  },

  getAssetRiskDistribution: async function() {
    return this.request('/analytics/asset-risk-distribution');
  },

  getTopVulnerabilities: async function(limit = 10) {
    return this.request(`/analytics/top-vulnerabilities?limit=${limit}`);
  },

  getMostAffectedAssets: async function(limit = 10) {
    return this.request(`/analytics/most-affected-assets?limit=${limit}`);
  },

  getAssignmentMetrics: async function(timeRange = '30d') {
    return this.request(`/analytics/assignment-metrics?range=${timeRange}`);
  },

  // ===== SEARCH AND FILTERING =====

  globalSearch: async function(query, filters = {}) {
    const params = { q: query, ...filters };
    const queryString = new URLSearchParams(params).toString();
    return this.request(`/search?${queryString}`);
  },

  searchAll: async function(query) {
    const [cves, assets, assignments] = await Promise.allSettled([
      this.getCVEs({ search: query }),
      this.getAssets({ search: query }),
      this.getAssignments({ search: query })
    ]);

    return {
      cves: cves.status === 'fulfilled' ? cves.value : [],
      assets: assets.status === 'fulfilled' ? assets.value : [],
      assignments: assignments.status === 'fulfilled' ? assignments.value : []
    };
  },

  // ===== FILE OPERATIONS =====

  uploadFile: async function(endpoint, file, additionalData = {}) {
    const formData = new FormData();
    formData.append('file', file);

    Object.entries(additionalData).forEach(([key, value]) => {
      formData.append(key, value);
    });

    return this.request(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${localStorage.getItem('token')}`
      },
      body: formData
    });
  },

  downloadFile: async function(endpoint) {
    const token = localStorage.getItem('token');
    const url = `${this.baseURL}${endpoint}`;

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Download failed: ${response.status} ${response.statusText}`);
    }

    return response.blob();
  },

  // ===== BATCH OPERATIONS =====

  batchAnalyzeCVEs: async function(cveIds, onProgress = null) {
    const results = [];
    const total = cveIds.length;

    for (let i = 0; i < cveIds.length; i++) {
      const cveId = cveIds[i];
      try {
        const result = await this.analyzeCVE(cveId);
        results.push({ cveId, success: true, result });

        if (onProgress) {
          onProgress({
            completed: i + 1,
            total,
            currentCVE: cveId,
            success: true
          });
        }
      } catch (error) {
        results.push({ cveId, success: false, error: error.message });

        if (onProgress) {
          onProgress({
            completed: i + 1,
            total,
            currentCVE: cveId,
            success: false,
            error: error.message
          });
        }
      }
    }

    return {
      results,
      summary: {
        total,
        successful: results.filter(r => r.success).length,
        failed: results.filter(r => !r.success).length
      }
    };
  },

  batchUpdateAssets: async function(assetUpdates) {
    return this.request('/assets/batch-update', {
      method: 'PUT',
      body: JSON.stringify(assetUpdates),
    });
  },

  // ===== EXPORT/IMPORT OPERATIONS =====

  exportData: async function(type, format = 'json') {
    const endpoint = `/export/${type}?format=${format}`;
    return this.request(endpoint);
  },

  importData: async function(type, file) {
    return this.uploadFile(`/import/${type}`, file);
  },

  exportCVEs: async function(format = 'json') {
    return this.exportData('cves', format);
  },

  exportAssignments: async function(format = 'json') {
    return this.exportData('assignments', format);
  },

  // ===== UTILITY METHODS =====

  // Check if the API is available
  healthCheck: async function() {
    try {
      const response = await fetch(`${this.baseURL.replace('/api/v1', '')}/health`);
      return response.ok;
    } catch {
      return false;
    }
  },

  testConnection: async function() {
    try {
      await this.request('/health');
      return true;
    } catch (error) {
      console.error('Connection test failed:', error);
      return false;
    }
  },

  ping: async function() {
    return this.request('/ping');
  },

  getVersion: async function() {
    return this.request('/version');
  },

  formatError: function(error) {
    if (typeof error === 'string') return error;
    if (error?.message) return error.message;
    if (error?.detail) return error.detail;
    return 'An unexpected error occurred';
  },

  // ===== INTEGRATION HELPERS =====

  getAffectedServicesEnhanced: async function(cveId) {
    try {
      const enhancedResult = await this.getEnhancedAffectedAssets(cveId);
      return enhancedResult.affected_assets || [];
    } catch (error) {
      console.warn(`Enhanced affected services not available for ${cveId}, falling back to basic version`);
      return this.getCVEAffectedAssets(cveId);
    }
  },

  getAssetVulnerabilityStatus: async function(assetId) {
    try {
      const assessment = await this.assessAssetVulnerabilities(assetId);
      return {
        hasVulnerabilities: assessment.total_cves > 0,
        riskScore: assessment.risk_score,
        totalCVEs: assessment.total_cves,
        criticalCVEs: assessment.critical_cves,
        highCVEs: assessment.high_cves,
        mediumCVEs: assessment.medium_cves,
        lowCVEs: assessment.low_cves,
        lastAssessment: assessment.assessment_timestamp
      };
    } catch (error) {
      console.warn(`Vulnerability status not available for asset ${assetId}:`, error);
      return {
        hasVulnerabilities: false,
        riskScore: 0,
        totalCVEs: 0,
        criticalCVEs: 0,
        highCVEs: 0,
        mediumCVEs: 0,
        lowCVEs: 0,
        lastAssessment: null
      };
    }
  },

  // ===== LEGACY COMPATIBILITY =====

  // Legacy method names for backward compatibility
  getAffectedServices: async function(cveId) {
    return this.getCVEAffectedAssets(cveId);
  },

  getServiceVulnerabilities: async function(serviceId) {
    return this.getAssetVulnerabilities(serviceId);
  },

  // ===== ENHANCED CPE SEARCH ENDPOINTS =====

  // Enhanced CPE search with natural language processing
  enhancedCPESearch: async function(searchRequest) {
    return this.request('/cpe-lookup/enhanced-search', {
      method: 'POST',
      body: JSON.stringify(searchRequest),
    });
  },

  // Get autocomplete suggestions for CPE search
  getCPEAutocomplete: async function(query, limit = 10) {
    const params = new URLSearchParams({ query, limit: limit.toString() });
    return this.request(`/cpe-lookup/autocomplete?${params.toString()}`);
  },

  // Parse natural language query
  parseNaturalLanguageQuery: async function(query) {
    return this.request('/cpe-lookup/parse-query', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ query }),
    });
  },

  // Smart CPE lookup with different modes
  smartCPELookup: async function(query, options = {}) {
    const searchRequest = {
      query,
      search_mode: options.mode || 'smart',
      max_results: options.limit || 20,
      include_deprecated: options.includeDeprecated || false,
      include_suggestions: options.includeSuggestions !== false,
      confidence_threshold: options.confidenceThreshold || 0.3,
      ...options
    };
    
    return this.enhancedCPESearch(searchRequest);
  },

  // Get search suggestions for improving queries
  getCPESearchSuggestions: async function(query, includePopular = true) {
    try {
      // Get both autocomplete and query parsing
      const [autocomplete, parsed] = await Promise.all([
        this.getCPEAutocomplete(query),
        query.length > 2 ? this.parseNaturalLanguageQuery(query) : null
      ]);

      return {
        autocomplete: autocomplete.suggestions,
        popular_products: autocomplete.popular_products,
        query_hints: autocomplete.query_hints,
        parsed_query: parsed,
        confidence: parsed?.confidence || 0
      };
    } catch (error) {
      console.warn('Failed to get search suggestions:', error);
      return {
        autocomplete: [],
        popular_products: [],
        query_hints: [],
        parsed_query: null,
        confidence: 0
      };
    }
  },

  // Advanced CPE search with filters
  advancedCPESearch: async function(filters) {
    const searchRequest = {
      query: filters.query || '',
      search_mode: 'advanced',
      vendor_filter: filters.vendor,
      product_filter: filters.product,
      version_filter: filters.version,
      part_filter: filters.part,
      max_results: filters.limit || 50,
      include_deprecated: filters.includeDeprecated || false,
      confidence_threshold: filters.confidenceThreshold || 0.3
    };
    
    return this.enhancedCPESearch(searchRequest);
  },

  // Quick search for common software
  quickCPESearch: async function(softwareName) {
    const commonQueries = {
      'apache': 'Apache HTTP Server',
      'nginx': 'Nginx web server',
      'mysql': 'MySQL database',
      'postgresql': 'PostgreSQL database',
      'mongodb': 'MongoDB database',
      'redis': 'Redis server',
      'docker': 'Docker container',
      'windows': 'Microsoft Windows',
      'linux': 'Linux operating system'
    };

    const query = commonQueries[softwareName.toLowerCase()] || softwareName;
    return this.smartCPELookup(query, { mode: 'simple', limit: 10 });
  },

// ===== ENHANCED UI HELPER METHODS =====

  // Get formatted search results for UI display
  getFormattedCPEResults: async function(query, options = {}) {
    try {
      const results = await this.smartCPELookup(query, options);
      
      // Format results for easier UI consumption
      const formattedResults = {
        ...results,
        products: results.products.map(product => ({
          ...product,
          display_name: this.formatCPEDisplayName(product),
          risk_badge: this.getRiskBadgeInfo(product.security_risk_level),
          category_icon: this.getCategoryIcon(product.category),
          popularity_stars: Math.round(product.popularity_score * 5)
        }))
      };

      return formattedResults;
    } catch (error) {
      console.error('Failed to get formatted CPE results:', error);
      throw error;
    }
  },

  // Helper to format CPE display names
  formatCPEDisplayName: function(product) {
    if (product.title) {
      return product.title;
    }
    
    // Create a readable name from vendor and product
    const vendor = product.vendor.charAt(0).toUpperCase() + product.vendor.slice(1);
    const productName = product.product.replace(/_/g, ' ')
      .split(' ')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
    
    if (product.version && product.version !== '*') {
      return `${vendor} ${productName} ${product.version}`;
    }
    
    return `${vendor} ${productName}`;
  },

  // Helper to get risk badge information
  getRiskBadgeInfo: function(riskLevel) {
    const riskInfo = {
      'low': { color: 'green', text: 'Low Risk', icon: '🟢' },
      'medium': { color: 'yellow', text: 'Medium Risk', icon: '🟡' },
      'high': { color: 'red', text: 'High Risk', icon: '🔴' },
      'unknown': { color: 'gray', text: 'Unknown', icon: '⚫' }
    };
    
    return riskInfo[riskLevel] || riskInfo.unknown;
  },

  // Helper to get category icons
  getCategoryIcon: function(category) {
    const categoryIcons = {
      'Web Server': '🌐',
      'Database': '🗄️',
      'Operating System': '💻',
      'Browser': '🌍',
      'Development': '⚙️',
      'Container': '📦',
      'CMS': '📝',
      'Framework': '🏗️',
      'Other': '📋'
    };
    
    return categoryIcons[category] || categoryIcons.Other;
  },

  // Real-time search with debouncing support
  searchCPEWithDebounce: function(query, callback, delay = 300) {
    // Clear existing timeout
    if (this._searchTimeout) {
      clearTimeout(this._searchTimeout);
    }
    
    // Set new timeout
    this._searchTimeout = setTimeout(async () => {
      try {
        if (query.length > 1) {
          const results = await this.getFormattedCPEResults(query, {
            mode: 'smart',
            limit: 15,
            includeSuggestions: true
          });
          callback(null, results);
        } else {
          callback(null, { products: [], suggestions: [] });
        }
      } catch (error) {
        callback(error, null);
      }
    }, delay);
  },

  // Validate CPE search input
  validateCPESearchInput: function(query) {
    const validation = {
      isValid: true,
      warnings: [],
      suggestions: []
    };

    if (!query || query.trim().length === 0) {
      validation.isValid = false;
      validation.warnings.push('Search query cannot be empty');
      return validation;
    }

    if (query.trim().length < 2) {
      validation.isValid = false;
      validation.warnings.push('Search query must be at least 2 characters long');
      return validation;
    }

    // Check for potential issues
    if (query.length === 1) {
      validation.suggestions.push('Try using more specific terms');
    }

    if (/^\d+\.\d+/.test(query)) {
      validation.warnings.push('Searching by version only may yield limited results');
      validation.suggestions.push('Try including the software name with the version');
    }

    if (query.includes('cpe:2.3:')) {
      validation.suggestions.push('Use the regular CPE lookup for formatted CPE strings');
    }

    return validation;
  },

// ===== SEARCH ANALYTICS AND TRACKING =====

  // Track search queries for analytics (if needed)
  trackCPESearch: async function(query, results, searchMode = 'smart') {
    try {
      // Only track if analytics are enabled
      if (this.analyticsEnabled) {
        const searchData = {
          query,
          result_count: results.total_count,
          search_mode: searchMode,
          confidence: results.confidence_score,
          timestamp: new Date().toISOString()
        };
        
        // Store locally or send to analytics endpoint
        localStorage.setItem('last_cpe_search', JSON.stringify(searchData));
      }
    } catch (error) {
      console.warn('Failed to track search:', error);
    }
  },

  // Get search history (from local storage)
  getCPESearchHistory: function(limit = 10) {
    try {
      const history = JSON.parse(localStorage.getItem('cpe_search_history') || '[]');
      return history.slice(0, limit);
    } catch (error) {
      console.warn('Failed to get search history:', error);
      return [];
    }
  },

  // Add to search history
  addToCPESearchHistory: function(query, results) {
    try {
      const history = this.getCPESearchHistory();
      const newEntry = {
        query,
        timestamp: new Date().toISOString(),
        result_count: results.total_count,
        confidence: results.confidence_score
      };
      
      // Avoid duplicates
      const filtered = history.filter(item => item.query !== query);
      filtered.unshift(newEntry);
      
      // Keep only last 20 searches
      const updated = filtered.slice(0, 20);
      localStorage.setItem('cpe_search_history', JSON.stringify(updated));
    } catch (error) {
      console.warn('Failed to add to search history:', error);
    }
  },

  // Clear search history
  clearCPESearchHistory: function() {
    try {
      localStorage.removeItem('cpe_search_history');
    } catch (error) {
      console.warn('Failed to clear search history:', error);
    }
  }
};



// Default export
export default api;
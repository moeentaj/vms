// Complete API Service - Consolidated with ALL functions
// frontend/src/services/api.js

export const api = {
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
      // Better error handling to avoid [object Object] issues
      if (error instanceof TypeError && error.message.includes('fetch')) {
        // Network error
        const networkError = `Network error: Unable to connect to ${url}`;
        console.error(`API Network Error (${endpoint}):`, networkError);
        throw new Error(networkError);
      }
      
      // If it's already a proper Error with a message, re-throw it
      if (error instanceof Error && error.message) {
        console.error(`API Error (${endpoint}):`, error.message);
        throw error;
      }
      
      // Handle any other unexpected error types
      const fallbackError = `Unexpected error occurred while calling ${endpoint}`;
      console.error(`API Unexpected Error (${endpoint}):`, error);
      throw new Error(fallbackError);
    }
  },

  // ===== AUTHENTICATION ENDPOINTS =====
  login: async function(username, password) {
    const requestBody = { username, password };
    console.log('About to send request body:', requestBody);
    console.log('JSON stringified:', JSON.stringify(requestBody));
    return this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
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

  getUsers: async function() {
    return this.request('/auth/users');
  },

  register: async function(userData) {
    return this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData),
    });
  },

  logout: async function() {
    return this.request('/auth/logout', {
      method: 'POST',
    });
  },

  // ===== CVE ENDPOINTS =====
  getCVEs: async function(params = {}) {
    // Clean up empty parameters
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

  // Legacy CVE endpoints for compatibility
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

  // ===== ASSET ENDPOINTS =====
  getAssets: async function(params = {}) {
    // Clean up empty parameters
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

  // ===== ASSIGNMENT ENDPOINTS =====
  getAssignments: async function(params = {}) {
    // Clean up empty parameters to avoid sending empty strings
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

  // ===== DASHBOARD ENDPOINTS =====
  getDashboardData: async function() {
    return this.request('/recommendations/dashboard');
  },

  getVulnerabilityDashboard: async function(environment = null) {
    const params = environment ? 
      `?environment=${encodeURIComponent(environment)}` : '';
    return this.request(`/cpe-cve-correlation/dashboard/vulnerability-overview${params}`);
  },

  getHealthCheck: async function() {
    return this.request('/health');
  },

  getSystemStats: async function() {
    return this.request('/dashboard/stats');
  },

  // ===== CPE-CVE CORRELATION ENDPOINTS =====
  
  // Direct CPE to CVE correlation
  correlateCPEToCVEs: async function(correlationData) {
    return this.request('/cpe-cve-correlation/correlate-cpe', {
      method: 'POST',
      body: JSON.stringify(correlationData),
    });
  },

  // Get vulnerability summary for a specific CPE
  getCPEVulnerabilities: async function(cpeName) {
    const encodedCPE = encodeURIComponent(cpeName);
    return this.request(`/cpe-cve-correlation/cpe/${encodedCPE}/vulnerabilities`);
  },

  // Asset vulnerability assessment
  assessAssetVulnerabilities: async function(assetId) {
    return this.request(`/cpe-cve-correlation/assets/${assetId}/vulnerabilities`);
  },

  // Get asset vulnerabilities (alias for consistency)
  getAssetVulnerabilities: async function(assetId) {
    return this.assessAssetVulnerabilities(assetId);
  },

  // Bulk asset vulnerability assessment
  bulkAssessAssets: async function(assessmentData) {
    return this.request('/cpe-cve-correlation/assets/bulk-assess', {
      method: 'POST',
      body: JSON.stringify(assessmentData),
    });
  },

  // Search vulnerabilities by software criteria
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

  // Get CPE mappings for an asset
  getAssetCPEMappings: async function(assetId) {
    return this.request(`/cpe-cve-correlation/assets/${assetId}/cpe-mappings`);
  },

  // Trigger single asset assessment
  triggerAssetAssessment: async function(assetId) {
    return this.request(`/cpe-cve-correlation/assets/${assetId}/trigger-assessment`, {
      method: 'POST',
    });
  },

  // Enhanced CVE affected assets (integrates with existing CVE management)
  getEnhancedAffectedAssets: async function(cveId, confidenceThreshold = 0.7) {
    return this.request(`/cpe-cve-correlation/cves/${cveId}/affected-assets-enhanced?confidence_threshold=${confidenceThreshold}`);
  },

  // Get affected assets for a CVE
  getCVEAffectedAssets: async function(cveId) {
    return this.request(`/cpe-cve-correlation/cves/${cveId}/affected-assets`);
  },

  // ===== CPE LOOKUP ENDPOINTS =====
  
  // Search CPE products
  searchCPEProducts: async function(searchData) {
    return this.request('/cpe-lookup/search', {
      method: 'POST',
      body: JSON.stringify(searchData),
    });
  },

  // Simple CPE search by query string
  searchCPE: async function(query, limit = 20) {
    const params = new URLSearchParams({ q: query, limit: limit.toString() });
    return this.request(`/cpe-lookup/search?${params.toString()}`);
  },

  // Get specific CPE product details
  getCPEProduct: async function(cpeNameId) {
    return this.request(`/cpe-lookup/product/${cpeNameId}`);
  },

  // Get CPE vendors
  getCPEVendors: async function(query = null, limit = 50) {
    const params = new URLSearchParams();
    if (query) params.append('query', query);
    params.append('limit', limit.toString());
    return this.request(`/cpe-lookup/vendors?${params.toString()}`);
  },

  // Get CPE products for a vendor
  getCPEProductsByVendor: async function(vendor, limit = 50) {
    const params = new URLSearchParams({ vendor, limit: limit.toString() });
    return this.request(`/cpe-lookup/products?${params.toString()}`);
  },

  // Get CPE status and statistics
  getCPEStatus: async function() {
    return this.request('/cpe-lookup/status');
  },

  // Trigger CPE data ingestion
  triggerCPEIngestion: async function(forceRefresh = false) {
    return this.request(`/cpe-lookup/ingest?force_refresh=${forceRefresh}`, {
      method: 'POST',
    });
  },

  // Clear CPE cache
  clearCPECache: async function() {
    return this.request('/cpe-lookup/cache', {
      method: 'DELETE',
    });
  },

  // ===== INTEGRATION HELPERS =====
  
  // Enhanced version of existing CVE affected services
  getAffectedServicesEnhanced: async function(cveId) {
    try {
      // Try enhanced version first
      const enhancedResult = await this.getEnhancedAffectedAssets(cveId);
      return enhancedResult.affected_assets || [];
    } catch (error) {
      console.warn(`Enhanced affected services not available for ${cveId}, falling back to basic version`);
      // Fallback to existing method if available
      if (this.getAffectedServices) {
        return this.getAffectedServices(cveId);
      }
      return [];
    }
  },

  // Asset integration for existing asset management
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

  // ===== RECOMMENDATIONS ENDPOINTS =====
  
  getRecommendations: async function(params = {}) {
    const query = new URLSearchParams(params).toString();
    return this.request(`/recommendations/?${query}`);
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

  // ===== USER MANAGEMENT ENDPOINTS =====
  
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
        // Don't set Content-Type for FormData, let browser set it
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

  // ===== EXPORT/IMPORT HELPERS =====
  
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

  exportAssets: async function(format = 'json') {
    return this.exportData('assets', format);
  },

  exportAssignments: async function(format = 'json') {
    return this.exportData('assignments', format);
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

  batchCreateAssignments: async function(assignments) {
    return this.request('/assignments/batch-create', {
      method: 'POST',
      body: JSON.stringify(assignments),
    });
  },

  // ===== UTILITY METHODS =====
  
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

  // ===== LEGACY COMPATIBILITY =====
  
  // Legacy method names for backward compatibility
  getAffectedServices: async function(cveId) {
    return this.getCVEAffectedAssets(cveId);
  },

  getServiceVulnerabilities: async function(serviceId) {
    // This was likely asset-based, redirect to asset vulnerabilities
    return this.getAssetVulnerabilities(serviceId);
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

  // ===== ANALYTICS AND REPORTING =====
  
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
  }
};

// Default export
export default api;
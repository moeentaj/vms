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

  // Auth endpoints
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

  // CVE endpoints
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

  collectCVEs: async function(daysBack = 7) {
    return this.request('/cves/collect', {
      method: 'POST',
      body: JSON.stringify({ days_back: daysBack }),
    });
  },

  analyzeCVE: async function(cveId) {
    return this.request(`/cves/${cveId}/analyze`, {
      method: 'POST',
    });
  },

  // Asset endpoints
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

  createAsset: async function(assetData) {
    return this.request('/assets/', {
      method: 'POST',
      body: JSON.stringify(assetData),
    });
  },

  // Assignment endpoints
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

  getAssignmentStats: async function() {
    return this.request('/assignments/dashboard/stats');
  },

  // Dashboard
  getDashboardData: async function() {
    return this.request('/recommendations/dashboard');
  },

  // NEW: CPE to CVE Correlation endpoints
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

  // Get vulnerability dashboard overview
  getVulnerabilityDashboard: async function(environment = null) {
    const params = environment ? `?environment=${encodeURIComponent(environment)}` : '';
    return this.request(`/cpe-cve-correlation/dashboard/vulnerability-overview${params}`);
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

  // CPE Lookup endpoints (extends existing CPE functionality)
  searchCPEProducts: async function(searchData) {
    return this.request('/cpe-lookup/search', {
      method: 'POST',
      body: JSON.stringify(searchData),
    });
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

  getCPEStatus: async function() {
    return this.request('/cpe-lookup/status');
  },

  triggerCPEIngestion: async function(forceRefresh = false) {
    return this.request(`/cpe-lookup/ingest?force_refresh=${forceRefresh}`, {
      method: 'POST',
    });
  },

  clearCPECache: async function() {
    return this.request('/cpe-lookup/cache', {
      method: 'DELETE',
    });
  },

  // Integration helpers for existing components
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
        criticalCount: assessment.critical_cves,
        highCount: assessment.high_cves,
        lastAssessed: assessment.last_assessed,
        recommendations: assessment.recommendations
      };
    } catch (error) {
      console.warn(`Vulnerability assessment not available for asset ${assetId}:`, error);
      return {
        hasVulnerabilities: false,
        riskScore: 0,
        criticalCount: 0,
        highCount: 0,
        lastAssessed: null,
        recommendations: []
      };
    }
  },

  // Dashboard integration
  getDashboardDataEnhanced: async function() {
    try {
      // Get both existing dashboard data and vulnerability overview
      const [dashboardData, vulnOverview] = await Promise.allSettled([
        this.getDashboardData(),
        this.getVulnerabilityDashboard()
      ]);

      const result = {};
      
      if (dashboardData.status === 'fulfilled') {
        result.dashboard = dashboardData.value;
      }
      
      if (vulnOverview.status === 'fulfilled') {
        result.vulnerabilityOverview = vulnOverview.value;
      }

      return result;
    } catch (error) {
      console.warn('Enhanced dashboard data not fully available, falling back to basic dashboard');
      return { dashboard: await this.getDashboardData() };
    }
  }
};
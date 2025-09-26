/**
 * Enhanced API Service with CPE Dictionary 2.0 and CPE Match 2.0 Integration
 * frontend/src/services/api.js
 * 
 * Complete API service with enhanced CPE capabilities and improved error handling
 */

// Custom error class for API errors
class APIError extends Error {
  constructor(status, message, data = {}) {
    super(message);
    this.name = 'APIError';
    this.status = status;
    this.data = data;
  }
}

class APIService {
  constructor() {
    this.baseURL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
    this.timeout = 30000; // 30 seconds
    this.retryAttempts = 3;
    this.retryDelay = 1000; // 1 second
  }

  // ===== CORE HTTP METHODS =====

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const token = localStorage.getItem('token');

    const defaultOptions = {
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
      },
      timeout: this.timeout,
      ...options,
    };

    try {
      const response = await this.fetchWithRetry(url, defaultOptions);

      if (!response.ok) {
        const errorData = await this.extractErrorData(response);
        throw new APIError(response.status, errorData.detail || errorData.message || 'Request failed', errorData);
      }

      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return await response.json();
      }

      return await response.text();

    } catch (error) {
      if (error instanceof APIError) {
        throw error;
      }
      throw new APIError(0, error.message || 'Network error', { originalError: error });
    }
  }

  async fetchWithRetry(url, options, attempt = 1) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), options.timeout);

      const response = await fetch(url, {
        ...options,
        signal: controller.signal
      });

      clearTimeout(timeoutId);
      return response;

    } catch (error) {
      if (attempt < this.retryAttempts && this.shouldRetry(error)) {
        console.warn(`API request failed (attempt ${attempt}/${this.retryAttempts}):`, error.message);
        await this.delay(this.retryDelay * attempt);
        return this.fetchWithRetry(url, options, attempt + 1);
      }
      throw error;
    }
  }

  shouldRetry(error) {
    return error.name === 'AbortError' ||
      error.message.includes('fetch') ||
      error.message.includes('network');
  }

  async delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async extractErrorData(response) {
    try {
      const text = await response.text();
      return JSON.parse(text);
    } catch {
      return { message: `HTTP ${response.status}: ${response.statusText}` };
    }
  }

  // ===== ENHANCED CPE DICTIONARY 2.0 METHODS =====

  /**
   * Enhanced CPE search using CPE Dictionary 2.0
   */
  async enhancedCPESearch(searchRequest) {
    try {
      const response = await this.request('/enhanced-cpe/search', {
        method: 'POST',
        body: JSON.stringify(searchRequest),
      });
      return response;
    } catch (error) {
      console.error('Enhanced CPE search failed:', error);
      throw error;
    }
  }

  /**
   * Simple CPE search via GET (for basic queries)
   */
  async searchEnhancedCPE(query, options = {}) {
    const params = new URLSearchParams({
      q: query,
      limit: (options.limit || 20).toString(),
      ...(options.vendor && { vendor: options.vendor }),
      ...(options.product && { product: options.product }),
      ...(options.version && { version: options.version }),
      ...(options.category && { category: options.category }),
      ...(options.include_deprecated && { include_deprecated: 'true' }),
      ...(options.offset && { offset: options.offset.toString() })
    });

    try {
      return await this.request(`/enhanced-cpe/search?${params.toString()}`);
    } catch (error) {
      console.error('Enhanced CPE GET search failed:', error);
      throw error;
    }
  }

  /**
   * Get CPE product details by ID
   */
  async getCPEProduct(cpeNameId) {
    try {
      return await this.request(`/enhanced-cpe/product/${encodeURIComponent(cpeNameId)}`);
    } catch (error) {
      console.error(`Failed to get CPE product ${cpeNameId}:`, error);
      throw error;
    }
  }

  /**
   * Get enhanced CPE status
   */
  async getEnhancedCPEStatus() {
    try {
      return await this.request('/enhanced-cpe/status');
    } catch (error) {
      console.error('Failed to get enhanced CPE status:', error);
      throw error;
    }
  }

  /**
   * Trigger CPE data ingestion
   */
  async triggerEnhancedCPEIngestion(forceRefresh = false) {
    try {
      const params = forceRefresh ? '?force_refresh=true' : '';
      return await this.request(`/enhanced-cpe/ingest${params}`, {
        method: 'POST'
      });
    } catch (error) {
      console.error('Enhanced CPE ingestion failed:', error);
      throw error;
    }
  }

  /**
   * Get CPE categories
   */
  async getCPECategories(limit = 50) {
    try {
      return await this.request(`/enhanced-cpe/categories?limit=${limit}`);
    } catch (error) {
      console.error('Failed to get CPE categories:', error);
      return { categories: [], total_count: 0 };
    }
  }

  /**
   * Get CPE vendors
   */
  async getCPEVendors(limit = 100) {
    try {
      return await this.request(`/enhanced-cpe/vendors?limit=${limit}`);
    } catch (error) {
      console.error('Failed to get CPE vendors:', error);
      return { vendors: [], total_count: 0 };
    }
  }

  /**
   * Get search suggestions for autocomplete
   */
  async getCPESearchSuggestions(query, limit = 10) {
    if (!query || query.length < 2) {
      return { suggestions: [], query: query };
    }

    try {
      const params = new URLSearchParams({
        q: query,
        limit: limit.toString()
      });

      return await this.request(`/enhanced-cpe/suggestions?${params.toString()}`);
    } catch (error) {
      console.warn('CPE suggestions not available:', error.message);
      return { suggestions: [], query: query };
    }
  }

  /**
   * Find CPE matches for a product (vulnerability correlation)
   */
  async findCPEMatches(vendor, product, version = null) {
    try {
      const matchRequest = {
        vendor: vendor,
        product: product,
        ...(version && { version: version })
      };

      return await this.request('/enhanced-cpe/match', {
        method: 'POST',
        body: JSON.stringify(matchRequest)
      });
    } catch (error) {
      console.error('CPE match search failed:', error);
      throw error;
    }
  }

  /**
   * Bulk CPE search for multiple queries
   */
  async bulkCPESearch(queries, limitPerQuery = 10) {
    try {
      return await this.request('/enhanced-cpe/bulk-search', {
        method: 'POST',
        body: JSON.stringify({
          queries: queries,
          limit_per_query: limitPerQuery
        })
      });
    } catch (error) {
      console.error('Bulk CPE search failed:', error);
      throw error;
    }
  }

  /**
   * Clear CPE cache (admin only)
   */
  async clearCPECache() {
    try {
      return await this.request('/enhanced-cpe/cache', {
        method: 'DELETE'
      });
    } catch (error) {
      console.error('Failed to clear CPE cache:', error);
      throw error;
    }
  }

  /**
   * Initialize CPE database (trigger ingestion)
   */
  async initializeCPE(forceRefresh = false) {
    try {
      return await this.triggerEnhancedCPEIngestion(forceRefresh);
    } catch (error) {
      console.error('Failed to initialize CPE database:', error);
      throw error;
    }
  }

  /**
   * Get CPE initialization/ingestion status
   */
  async getCPEIngestionStatus() {
    try {
      return await this.request('/enhanced-cpe/ingestion/status');
    } catch (error) {
      console.error('Failed to get CPE ingestion status:', error);
      return { message: 'Status not available', current_status: { has_data: false } };
    }
  }

  // ===== ENHANCED ASSET METHODS WITH CPE INTEGRATION =====

  /**
   * Smart CPE lookup for asset creation/editing
   */
  async smartCPELookup(query, options = {}) {
    if (!query || query.trim().length < 2) {
      throw new Error('Query must be at least 2 characters long');
    }

    try {
      // Try enhanced search first
      const searchResult = await this.searchEnhancedCPE(query.trim(), {
        limit: options.limit || 12,
        include_deprecated: options.include_deprecated || false,
        ...options
      });

      return searchResult.products || [];

    } catch (error) {
      console.warn('Enhanced CPE lookup failed, trying legacy:', error.message);

      // Fallback to legacy CPE lookup
      try {
        return await this.request('/assets/cpe-lookup', {
          method: 'POST',
          body: JSON.stringify({
            query: query.trim(),
            limit: Math.max(1, Math.min(options.limit || 12, 50))
          }),
        });
      } catch (fallbackError) {
        throw new Error(`CPE lookup failed: ${fallbackError.message}`);
      }
    }
  }

  /**
   * Legacy CPE lookup (for backward compatibility)
   */
  async cpeLookup(query, limit = 12) {
    return this.smartCPELookup(query, { limit });
  }

  // ===== LEGACY CPE METHODS FOR BACKWARD COMPATIBILITY =====

  /**
   * Legacy CPE status check
   */
  async getCPEStatus() {
    try {
      // Try enhanced status first
      const enhancedStatus = await this.getEnhancedCPEStatus();
      return {
        has_data: enhancedStatus.has_data,
        total_products: enhancedStatus.total_products,
        last_updated: enhancedStatus.last_updated,
        cache_file_exists: enhancedStatus.cache_files?.enhanced_cache_exists || false,
        categories_available: enhancedStatus.categories_available,
        vendors_count: enhancedStatus.vendors_count
      };
    } catch (error) {
      console.warn('Enhanced CPE status not available, trying legacy endpoint');
      try {
        return await this.request('/cpe-lookup/status');
      } catch (fallbackError) {
        console.error('All CPE status endpoints failed:', fallbackError);
        return {
          has_data: false,
          total_products: 0,
          last_updated: null,
          cache_file_exists: false,
          categories_available: 0,
          vendors_count: 0
        };
      }
    }
  }

  /**
   * Legacy CPE ingestion trigger
   */
  async triggerCPEIngestion(forceRefresh = false) {
    try {
      // Try enhanced ingestion first
      return await this.triggerEnhancedCPEIngestion(forceRefresh);
    } catch (error) {
      console.warn('Enhanced CPE ingestion not available, trying legacy endpoint');
      try {
        const endpoint = forceRefresh ? '/cpe-lookup/ingest?force_refresh=true' : '/cpe-lookup/ingest';
        return await this.request(endpoint, { method: 'POST' });
      } catch (fallbackError) {
        console.error('All CPE ingestion endpoints failed:', fallbackError);
        throw fallbackError;
      }
    }
  }

  /**
   * Legacy search CPE method
   */
  async searchCPE(query, limit = 20) {
    try {
      // Try enhanced search first
      const result = await this.searchEnhancedCPE(query, { limit });
      return result.products || [];
    } catch (error) {
      console.warn('Enhanced CPE search not available, trying legacy endpoint');
      try {
        return await this.request('/cpe-lookup/search', {
          method: 'POST',
          body: JSON.stringify({ query, limit })
        });
      } catch (fallbackError) {
        console.error('All CPE search endpoints failed:', fallbackError);
        throw fallbackError;
      }
    }
  }

  /**
   * Alias for initializeCPE (different naming conventions)
   */
  async initCPE(forceRefresh = false) {
    return this.initializeCPE(forceRefresh);
  }

  /**
   * Check if CPE system is ready
   */
  async isCPEReady() {
    try {
      const status = await this.getCPEStatus();
      return status.has_data && status.total_products > 0;
    } catch (error) {
      console.error('Failed to check CPE readiness:', error);
      return false;
    }
  }

  // ===== ENHANCED CVE CORRELATION METHODS =====

  /**
   * Get CVEs potentially affecting an asset
   */
  async getAssetVulnerabilities(assetId, confidenceThreshold = 0.7) {
    try {
      const params = new URLSearchParams({ confidence_threshold: confidenceThreshold.toString() });
      return await this.request(`/cpe-cve-correlation/assets/${assetId}/vulnerabilities?${params.toString()}`);
    } catch (error) {
      console.error(`Failed to get vulnerabilities for asset ${assetId}:`, error);
      throw error;
    }
  }

  /**
   * Get assets potentially affected by a CVE
   */
  async getCVEAffectedAssets(cveId, confidenceThreshold = 0.7) {
    try {
      const params = new URLSearchParams({ confidence_threshold: confidenceThreshold.toString() });
      return await this.request(`/cpe-cve-correlation/cves/${cveId}/affected-assets?${params.toString()}`);
    } catch (error) {
      console.error(`Failed to get affected assets for CVE ${cveId}:`, error);
      throw error;
    }
  }

  /**
   * Enhanced affected assets with detailed correlation info
   */
  async getEnhancedAffectedAssets(cveId, confidenceThreshold = 0.7) {
    try {
      const params = new URLSearchParams({ confidence_threshold: confidenceThreshold.toString() });
      return await this.request(`/cpe-cve-correlation/cves/${cveId}/affected-assets-enhanced?${params.toString()}`);
    } catch (error) {
      console.warn(`Enhanced affected assets not available for ${cveId}, falling back:`, error);
      return this.getCVEAffectedAssets(cveId, confidenceThreshold);
    }
  }

  /**
   * Bulk assessment of multiple assets
   */
  async bulkAssessAssets(assessmentData) {
    try {
      return await this.request('/cpe-cve-correlation/assets/bulk-assess', {
        method: 'POST',
        body: JSON.stringify(assessmentData),
      });
    } catch (error) {
      console.error('Bulk asset assessment failed:', error);
      throw error;
    }
  }

  /**
   * Search vulnerabilities with enhanced filters
   */
  async searchVulnerabilities(params = {}) {
    try {
      const cleanParams = {};
      for (const [key, value] of Object.entries(params)) {
        if (value !== '' && value !== null && value !== undefined) {
          cleanParams[key] = value;
        }
      }
      const query = new URLSearchParams(cleanParams).toString();
      return await this.request(`/cpe-cve-correlation/vulnerabilities/search?${query}`);
    } catch (error) {
      console.error('Vulnerability search failed:', error);
      throw error;
    }
  }

  // ===== EXISTING CVE MANAGEMENT METHODS (ENHANCED) =====

  async getCVEs(params = {}) {
    const query = new URLSearchParams(params).toString();
    return this.request(`/cves?${query}`);
  }

  async getCVE(cveId) {
    return this.request(`/cves/${cveId}`);
  }

  async collectCVEs(params = {}) {
    return this.request('/cves/collect', {
      method: 'POST',
      body: JSON.stringify({
        days_back: 7,
        use_files: true,
        ...params
      })
    });
  }

  async analyzeCVE(cveId) {
    return this.request(`/cves/${cveId}/analyze`, {
      method: 'POST'
    });
  }

  async batchAnalyzeCVEs(cveIds, onProgress = null) {
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

      // Small delay to prevent overwhelming the API
      if (i < cveIds.length - 1) {
        await this.delay(100);
      }
    }

    return results;
  }

  // ===== ASSET MANAGEMENT METHODS (ENHANCED) =====

  async getAssets(params = {}) {
    const query = new URLSearchParams(params).toString();
    return this.request(`/assets?${query}`);
  }

  async getAsset(assetId) {
    return this.request(`/assets/${assetId}`);
  }

  async createAsset(assetData) {
    return this.request('/assets', {
      method: 'POST',
      body: JSON.stringify(assetData),
    });
  }

  async updateAsset(assetId, assetData) {
    return this.request(`/assets/${assetId}`, {
      method: 'PUT',
      body: JSON.stringify(assetData),
    });
  }

  async deleteAsset(assetId) {
    return this.request(`/assets/${assetId}`, {
      method: 'DELETE',
    });
  }

  async getAssetEnvironments() {
    return this.request('/assets/environments');
  }

  async searchAssets(query) {
    return this.request(`/assets/search?q=${encodeURIComponent(query)}`);
  }

  // ===== AUTHENTICATION METHODS =====

  async login(username, password) {
    try {
      const response = await this.request('/auth/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          username: username,
          password: password,
        }),
      });

      if (response.access_token) {
        localStorage.setItem('token', response.access_token);
        localStorage.setItem('tokenType', response.token_type || 'bearer');
      }

      return response;
    } catch (error) {
      console.error('Login failed:', error);
      throw error;
    }
  }

  async register(userData) {
    return this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData),
    });
  }

  async getProfile() {
    return this.request('/auth/profile');
  }

  logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('tokenType');
  }

  async getCurrentUser() {
    return this.request('/auth/me');
  }

  isAuthenticated() {
    return !!localStorage.getItem('token');
  }

  // ===== ASSIGNMENT METHODS =====

  async getAssignments(params = {}) {
    const query = new URLSearchParams(params).toString();
    return this.request(`/assignments?${query}`);
  }

  async createAssignment(assignmentData) {
    return this.request('/assignments', {
      method: 'POST',
      body: JSON.stringify(assignmentData),
    });
  }

  async updateAssignment(assignmentId, updateData) {
    return this.request(`/assignments/${assignmentId}`, {
      method: 'PUT',
      body: JSON.stringify(updateData),
    });
  }

  async deleteAssignment(assignmentId) {
    return this.request(`/assignments/${assignmentId}`, {
      method: 'DELETE',
    });
  }

  // ===== SYSTEM STATUS AND MONITORING =====

  async getSystemStatus() {
    return this.request('/status');
  }

  async getSystemHealth() {
    return this.request('/health');
  }

  async getSystemVersion() {
    return this.request('/version');
  }

  // ===== UTILITY METHODS =====

  formatError(error) {
    if (error instanceof APIError) {
      return error.message;
    }
    if (error?.message) return error.message;
    if (error?.detail) return error.detail;
    return 'An unexpected error occurred';
  }

  async getDashboardData() {
    try {
      const [cves, assets, assignments] = await Promise.allSettled([
        this.getCVEs({ limit: 10 }),
        this.getAssets({ limit: 10 }),
        this.getAssignments({ limit: 10 })
      ]);

      return {
        cves: cves.status === 'fulfilled' ? cves.value : [],
        assets: assets.status === 'fulfilled' ? assets.value : [],
        assignments: assignments.status === 'fulfilled' ? assignments.value : []
      };
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
      throw error;
    }
  }

  // ===== FILE OPERATIONS =====

  async uploadFile(endpoint, file, additionalData = {}) {
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
  }

  async downloadFile(endpoint) {
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
  }

}
// Create and export API instance
const api = new APIService();

export { api, APIError };
export default api;
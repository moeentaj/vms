import React, { useState, useEffect } from 'react';
import { Search, ExternalLink, Database, Clock, Tag } from 'lucide-react';

const CPELookup = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedProduct, setSelectedProduct] = useState(null);
  const [stats, setStats] = useState(null);

  // Load CPE status on component mount
  useEffect(() => {
    loadCPEStatus();
  }, []);

  // Debounced search
  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchQuery.length > 2) {
        searchCPE();
      } else {
        setResults([]);
      }
    }, 500);

    return () => clearTimeout(timer);
  }, [searchQuery]);

  const loadCPEStatus = async () => {
    try {
      const response = await fetch('/api/v1/cpe/status', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (error) {
      console.error('Failed to load CPE status:', error);
    }
  };

  const searchCPE = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/v1/cpe/search', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          query: searchQuery,
          limit: 20
        })
      });

      if (response.ok) {
        const data = await response.json();
        setResults(data.products || []);
      } else if (response.status === 404) {
        setResults([]);
        alert('CPE data not available. Please run CPE ingestion first.');
      }
    } catch (error) {
      console.error('CPE search failed:', error);
      setResults([]);
    } finally {
      setLoading(false);
    }
  };

  const refreshCPEData = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/v1/cpe/ingest', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          alert('CPE data refresh started in background');
          loadCPEStatus();
        }
      }
    } catch (error) {
      console.error('Failed to refresh CPE data:', error);
      alert('Failed to refresh CPE data');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">CPE Database Lookup</h2>
          <p className="text-gray-600">Search the NIST Common Platform Enumeration database</p>
        </div>
        <div className="flex space-x-3">
          {stats && (
            <div className="bg-white px-4 py-2 rounded-lg border text-sm">
              <div className="flex items-center space-x-2">
                <Database className="h-4 w-4 text-blue-600" />
                <span>{stats.total_products?.toLocaleString()} products</span>
              </div>
            </div>
          )}
          <button
            onClick={refreshCPEData}
            disabled={loading}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center space-x-2"
          >
            <Database className="h-4 w-4" />
            <span>{loading ? 'Refreshing...' : 'Refresh Data'}</span>
          </button>
        </div>
      </div>

      {/* Search Interface */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="relative">
          <Search className="h-5 w-5 text-gray-400 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Search for software products (e.g., 'apache', 'mysql', 'windows server')..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 text-lg"
          />
        </div>

        {loading && (
          <div className="mt-4 flex items-center justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <span className="ml-3 text-gray-600">Searching CPE database...</span>
          </div>
        )}

        {/* Search Results */}
        {results.length > 0 && (
          <div className="mt-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">
              Search Results ({results.length})
            </h3>
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {results.map((product, index) => (
                <div
                  key={index}
                  onClick={() => setSelectedProduct(product)}
                  className="p-4 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3">
                        <h4 className="font-medium text-gray-900">
                          {product.vendor} {product.product}
                        </h4>
                        {product.version !== '*' && (
                          <span className="bg-blue-100 text-blue-800 px-2 py-1 rounded text-sm">
                            v{product.version}
                          </span>
                        )}
                        {product.deprecated && (
                          <span className="bg-red-100 text-red-800 px-2 py-1 rounded text-sm">
                            Deprecated
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-gray-600 mt-1">
                        {product.title || product.description || 'No description available'}
                      </p>
                      <p className="text-xs text-gray-500 mt-2 font-mono">
                        {product.cpe_name}
                      </p>
                    </div>
                    <ExternalLink className="h-4 w-4 text-gray-400" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {searchQuery.length > 2 && results.length === 0 && !loading && (
          <div className="mt-6 text-center py-8">
            <div className="text-gray-500">
              <Database className="h-12 w-12 mx-auto mb-3 opacity-50" />
              <p>No products found for "{searchQuery}"</p>
              <p className="text-sm mt-1">Try different keywords or check spelling</p>
            </div>
          </div>
        )}
      </div>

      {/* Selected Product Details */}
      {selectedProduct && (
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex justify-between items-start mb-4">
            <h3 className="text-lg font-medium text-gray-900">Product Details</h3>
            <button
              onClick={() => setSelectedProduct(null)}
              className="text-gray-400 hover:text-gray-600"
            >
              ×
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <dl className="space-y-3">
                <div>
                  <dt className="text-sm font-medium text-gray-500">Product Name</dt>
                  <dd className="text-sm text-gray-900">{selectedProduct.product}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Vendor</dt>
                  <dd className="text-sm text-gray-900">{selectedProduct.vendor}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Version</dt>
                  <dd className="text-sm text-gray-900">
                    {selectedProduct.version === '*' ? 'All versions' : selectedProduct.version}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">CPE Name</dt>
                  <dd className="text-sm text-gray-900 font-mono break-all">{selectedProduct.cpe_name}</dd>
                </div>
              </dl>
            </div>

            <div>
              <dl className="space-y-3">
                <div>
                  <dt className="text-sm font-medium text-gray-500">CPE ID</dt>
                  <dd className="text-sm text-gray-900 font-mono">{selectedProduct.cpe_name_id}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Status</dt>
                  <dd className="text-sm">
                    {selectedProduct.deprecated ? (
                      <span className="bg-red-100 text-red-800 px-2 py-1 rounded text-xs">
                        Deprecated
                      </span>
                    ) : (
                      <span className="bg-green-100 text-green-800 px-2 py-1 rounded text-xs">
                        Active
                      </span>
                    )}
                  </dd>
                </div>
                {selectedProduct.last_modified && (
                  <div>
                    <dt className="text-sm font-medium text-gray-500">Last Modified</dt>
                    <dd className="text-sm text-gray-900">
                      {new Date(selectedProduct.last_modified).toLocaleDateString()}
                    </dd>
                  </div>
                )}
              </dl>
            </div>
          </div>

          {selectedProduct.title && (
            <div className="mt-4 pt-4 border-t border-gray-200">
              <dt className="text-sm font-medium text-gray-500 mb-2">Description</dt>
              <dd className="text-sm text-gray-900">{selectedProduct.title}</dd>
            </div>
          )}

          <div className="mt-6 pt-4 border-t border-gray-200">
            <button
              onClick={() => {
                // Logic to create asset with this CPE product
                alert('Use this CPE reference when creating assets to automatically populate service information.');
              }}
              className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center space-x-2"
            >
              <Tag className="h-4 w-4" />
              <span>Use in Asset Creation</span>
            </button>
          </div>
        </div>
      )}

      {/* CPE Status Information */}
      {stats && (
        <div className="bg-gray-50 rounded-lg p-4">
          <div className="flex items-center space-x-4 text-sm text-gray-600">
            <div className="flex items-center space-x-2">
              <Clock className="h-4 w-4" />
              <span>
                {stats.last_refresh 
                  ? `Last updated: ${new Date(stats.last_refresh).toLocaleDateString()}`
                  : 'Never updated'
                }
              </span>
            </div>
            <span>•</span>
            <span>{stats.total_products?.toLocaleString()} products available</span>
            {stats.needs_refresh && (
              <>
                <span>•</span>
                <span className="text-yellow-600">Refresh recommended</span>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default CPELookup;
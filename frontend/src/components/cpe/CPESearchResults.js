import React, { useState } from 'react';
import {
  Star,
  Shield,
  Clock,
  ExternalLink,
  Copy,
  Check,
  AlertTriangle,
  Info,
  ChevronDown,
  ChevronUp,
  Filter,
  TrendingUp,
  Search, // ✅ Missing import added
} from 'lucide-react';

const CPESearchResults = ({ results, onSelect, onViewVulnerabilities }) => {
  const [expandedProduct, setExpandedProduct] = useState(null);
  const [copiedCPE, setCopiedCPE] = useState(null);
  const [sortBy, setSortBy] = useState('relevance');
  const [filterBy, setFilterBy] = useState('all');

  if (!results || !results.products) return null;

  const handleCopyCPE = async (cpeProduct) => {
    try {
      await navigator.clipboard.writeText(cpeProduct.cpe_name);
      setCopiedCPE(cpeProduct.cpe_name);
      setTimeout(() => setCopiedCPE(null), 2000);
    } catch (error) {
      console.error('Failed to copy CPE name:', error);
    }
  };

  const handleProductSelect = (product) => onSelect?.(product);
  const handleViewVulnerabilities = (product) => onViewVulnerabilities?.(product);

  const getRiskBadgeClass = (riskLevel) => {
    const classes = {
      low: 'bg-green-100 text-green-800 border-green-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      high: 'bg-red-100 text-red-800 border-red-200',
      unknown: 'bg-gray-100 text-gray-800 border-gray-200',
    };
    return classes[riskLevel] || classes.unknown;
  };

  const getPopularityStars = (score) =>
    Array.from({ length: 5 }, (_, i) => (
      <Star
        key={i}
        className={`h-3 w-3 ${i < score ? 'text-yellow-400 fill-current' : 'text-gray-300'}`}
      />
    ));

  const sortProducts = (products) => {
    const sorted = [...products];
    switch (sortBy) {
      case 'relevance':
        return sorted.sort((a, b) => b.relevance_score - a.relevance_score);
      case 'popularity':
        return sorted.sort((a, b) => b.popularity_score - a.popularity_score);
      case 'vendor':
        return sorted.sort((a, b) => a.vendor.localeCompare(b.vendor));
      case 'risk': {
        const riskOrder = { high: 3, medium: 2, low: 1, unknown: 0 };
        return sorted.sort(
          (a, b) => riskOrder[b.security_risk_level] - riskOrder[a.security_risk_level]
        );
      }
      default:
        return sorted;
    }
  };

  const filterProducts = (products) => {
    if (filterBy === 'all') return products;
    if (filterBy === 'verified') return products.filter((p) => p.vendor_verified);
    if (filterBy === 'recent') return products.filter((p) => !p.deprecated);
    if (filterBy === 'high-risk') return products.filter((p) => p.security_risk_level === 'high');
    return products;
  };

  const processedProducts = sortProducts(filterProducts(results.products));

  return (
    <div className="space-y-6">
      {/* Results Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-gray-900">
            Search Results ({results.total_count})
          </h3>
          <p className="text-sm text-gray-600">
            Found {results.total_count} products in {results.execution_time_ms}ms
            {results.confidence_score ? (
              <span className="ml-2">• {Math.round(results.confidence_score * 100)}% confidence</span>
            ) : null}
          </p>
        </div>

        {/* Sort and Filter Controls */}
        <div className="flex items-center space-x-3">
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="text-sm border border-gray-300 rounded-md px-3 py-1"
          >
            <option value="relevance">Sort by Relevance</option>
            <option value="popularity">Sort by Popularity</option>
            <option value="vendor">Sort by Vendor</option>
            <option value="risk">Sort by Risk</option>
          </select>

          <select
            value={filterBy}
            onChange={(e) => setFilterBy(e.target.value)}
            className="text-sm border border-gray-300 rounded-md px-3 py-1"
          >
            <option value="all">All Products</option>
            <option value="verified">Verified Vendors</option>
            <option value="recent">Active Products</option>
            <option value="high-risk">High Risk</option>
          </select>
        </div>
      </div>

      {/* Query Understanding */}
      {results.query_understanding && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-start space-x-2">
            <Info className="h-4 w-4 text-blue-600 mt-0.5 flex-shrink-0" />
            <div className="flex-1">
              <h4 className="font-medium text-blue-900">Query Understanding</h4>
              <p className="text-sm text-blue-800 mt-1">
                {results.query_understanding.explanation}
              </p>
              {results.query_understanding.extracted_terms?.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-2">
                  {results.query_understanding.extracted_terms.map((term, index) => (
                    <span
                      key={index}
                      className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-blue-100 text-blue-800"
                    >
                      {term}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Suggestions */}
      {results.suggestions?.length > 0 && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <h4 className="font-medium text-yellow-900 mb-2">Suggestions to Improve Results</h4>
          <ul className="space-y-1">
            {results.suggestions.map((suggestion, index) => (
              <li key={index} className="text-sm text-yellow-800">
                • {suggestion.suggestion}
                <span className="text-yellow-600 ml-1">({suggestion.reason})</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Alternative Queries */}
      {results.alternative_queries?.length > 0 && (
        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
          <h4 className="font-medium text-gray-900 mb-2">Try These Alternative Searches</h4>
          <div className="flex flex-wrap gap-2">
            {results.alternative_queries.map((query, index) => (
              <button
                key={index}
                className="px-3 py-1 bg-white border border-gray-300 rounded-full text-sm hover:bg-gray-100 transition-colors"
                onClick={() => {
                  // Hook up to your search trigger
                  console.log('Alternative query clicked:', query);
                }}
              >
                {query}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Products List */}
      <div className="space-y-4">
        {processedProducts.map((product) => (
          <div
            key={product.cpe_name_id}
            className="bg-white border border-gray-200 rounded-lg hover:shadow-md transition-shadow"
          >
            <div className="p-6">
              {/* Product Header */}
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3">
                    <span className="text-2xl">{product.category_icon}</span>
                    <div>
                      <h4 className="text-lg font-semibold text-gray-900">
                        {product.display_name}
                      </h4>
                      <p className="text-sm text-gray-600">{product.description}</p>
                    </div>
                  </div>

                  {/* Product Metadata */}
                  <div className="mt-3 flex items-center space-x-6 text-sm text-gray-600">
                    <span>
                      <strong>Vendor:</strong> {product.vendor}
                      {product.vendor_verified && (
                        <Check className="h-3 w-3 text-green-600 inline ml-1" />
                      )}
                    </span>
                    <span><strong>Version:</strong> {product.version}</span>
                    <span><strong>Category:</strong> {product.category}</span>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleProductSelect(product)}
                    className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors text-sm"
                  >
                    Select
                  </button>
                  <button
                    onClick={() => handleViewVulnerabilities(product)}
                    className="bg-white border border-gray-300 px-3 py-2 rounded-md hover:bg-gray-50 transition-colors text-sm"
                  >
                    View CVEs
                  </button>
                  <button
                    onClick={() => handleCopyCPE(product)}
                    className="bg-white border border-gray-300 px-3 py-2 rounded-md hover:bg-gray-50 transition-colors text-sm inline-flex items-center"
                    title="Copy CPE"
                  >
                    <Copy className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() =>
                      setExpandedProduct((prev) =>
                        prev === product.cpe_name_id ? null : product.cpe_name_id
                      )
                    }
                    className="bg-white border border-gray-300 px-3 py-2 rounded-md hover:bg-gray-50 transition-colors text-sm inline-flex items-center"
                    title="Details"
                  >
                    {expandedProduct === product.cpe_name_id ? (
                      <ChevronUp className="h-4 w-4" />
                    ) : (
                      <ChevronDown className="h-4 w-4" />
                    )}
                  </button>
                </div>
              </div>

              {/* Copied toast-ish note */}
              {copiedCPE === product.cpe_name && (
                <div className="mt-2 text-xs text-green-700">CPE copied to clipboard.</div>
              )}

              {/* Expanded Details */}
              {expandedProduct === product.cpe_name_id && (
                <div className="mt-3 space-y-3 border-t pt-3">
                  {/* Last Modified */}
                  {product.last_modified && (
                    <div className="flex items-center space-x-2 text-sm">
                      <Clock className="h-4 w-4 text-gray-500" />
                      <span className="text-gray-600">
                        Last updated:{' '}
                        {new Date(product.last_modified).toLocaleDateString()}
                      </span>
                    </div>
                  )}

                  {/* References */}
                  {product.references?.length > 0 && (
                    <div>
                      <h5 className="text-sm font-medium text-gray-900 mb-2">References</h5>
                      <div className="space-y-1">
                        {product.references.slice(0, 3).map((ref, refIndex) => (
                          <a
                            key={refIndex}
                            href={ref.href}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center space-x-1 text-sm text-blue-600 hover:text-blue-800"
                          >
                            <ExternalLink className="h-3 w-3" />
                            <span>{ref.href}</span>
                          </a>
                        ))}
                        {product.references.length > 3 && (
                          <span className="text-sm text-gray-500">
                            +{product.references.length - 3} more references
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Technical Details */}
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-gray-600">CPE Name ID:</span>
                      <div className="font-mono text-xs text-gray-900">
                        {product.cpe_name_id}
                      </div>
                    </div>
                    <div>
                      <span className="text-gray-600">Product ID:</span>
                      <div className="font-mono text-xs text-gray-900">{product.product}</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Load More */}
      {results.total_count > processedProducts.length && (
        <div className="text-center">
          <button className="bg-gray-600 text-white px-6 py-2 rounded-md hover:bg-gray-700 transition-colors">
            Load More Results
          </button>
        </div>
      )}

      {/* No Results */}
      {processedProducts.length === 0 && (
        <div className="text-center py-12">
          <div className="text-gray-400 mb-4">
            <Search className="h-12 w-12 mx-auto" />
          </div>
          <h3 className="text-lg font-medium text-gray-900 mb-2">No Results Found</h3>
          <p className="text-gray-600 mb-4">
            Try adjusting your search terms or filters to find what you're looking for.
          </p>
          {results.suggestions?.length > 0 && (
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 text-left max-w-md mx-auto">
              <h4 className="font-medium text-blue-900 mb-2">Try these suggestions:</h4>
              <ul className="space-y-1">
                {results.suggestions.map((suggestion, index) => (
                  <li key={index} className="text-sm text-blue-800">
                    • {suggestion.suggestion}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default CPESearchResults;

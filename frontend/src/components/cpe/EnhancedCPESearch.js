import React, { useState, useEffect, useRef, useCallback } from 'react';
import { 
  Search, 
  AlertCircle, 
  CheckCircle, 
  Lightbulb, 
  Zap, 
  BookOpen, 
  ArrowRight,
  Star,
  Shield,
  Clock,
  TrendingUp,
  Filter,
  X,
  HelpCircle
} from 'lucide-react';
import api from '../../services/api';

const EnhancedCPESearch = ({ onSelect, onResults, mode = 'smart' }) => {
  // State management
  const [input, setInput] = useState('');
  const [suggestions, setSuggestions] = useState([]);
  const [guidance, setGuidance] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [confidence, setConfidence] = useState(0);
  const [showTutorial, setShowTutorial] = useState(false);
  const [searchMode, setSearchMode] = useState(mode);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [searchHistory, setSearchHistory] = useState([]);
  const [selectedCPE, setSelectedCPE] = useState(null);
  
  // Advanced filter state
  const [advancedFilters, setAdvancedFilters] = useState({
    vendor: '',
    product: '',
    version: '',
    includeDeprecated: false,
    confidenceThreshold: 0.3
  });

  const inputRef = useRef(null);
  const searchTimeoutRef = useRef(null);

  // Load search history on mount
  useEffect(() => {
    const history = api.getCPESearchHistory(5);
    setSearchHistory(history);
  }, []);

  // Real-time input analysis and suggestions
  useEffect(() => {
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current);
    }

    if (input.length === 0) {
      setGuidance(null);
      setSuggestions([]);
      setConfidence(0);
      return;
    }

    searchTimeoutRef.current = setTimeout(async () => {
      await analyzeAndSuggest(input);
    }, 300);

    return () => {
      if (searchTimeoutRef.current) {
        clearTimeout(searchTimeoutRef.current);
      }
    };
  }, [input]);

  const analyzeAndSuggest = async (query) => {
    try {
      setIsLoading(true);
      
      // Validate input
      const validation = api.validateCPESearchInput(query);
      if (!validation.isValid) {
        setGuidance({
          type: 'error',
          message: validation.warnings[0],
          suggestions: validation.suggestions
        });
        setConfidence(0);
        return;
      }

      // Get suggestions and parse query
      const searchData = await api.getCPESearchSuggestions(query);
      
      setConfidence(searchData.confidence);
      setSuggestions(searchData.autocomplete.slice(0, 6));
      
      // Generate guidance based on parsed query
      if (searchData.parsed_query) {
        const parsed = searchData.parsed_query;
        if (parsed.confidence < 0.3) {
          setGuidance({
            type: 'warning',
            message: 'Try being more specific about the software',
            suggestions: parsed.suggestions
          });
        } else if (parsed.confidence < 0.6) {
          setGuidance({
            type: 'info',
            message: 'Good start! You can make this more specific',
            suggestions: parsed.suggestions
          });
        } else {
          setGuidance({
            type: 'success',
            message: 'Great! This should find relevant results',
            suggestions: []
          });
        }
      }

    } catch (error) {
      console.error('Analysis failed:', error);
      setGuidance({
        type: 'warning',
        message: 'Unable to analyze query',
        suggestions: ['Try using more specific terms']
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleSearch = async () => {
    if (!input.trim()) return;

    try {
      setIsLoading(true);
      
      let results;
      if (searchMode === 'advanced') {
        results = await api.advancedCPESearch({
          query: input,
          ...advancedFilters,
          limit: 20
        });
      } else {
        results = await api.getFormattedCPEResults(input, {
          mode: searchMode,
          limit: 20,
          includeSuggestions: true
        });
      }

      // Add to search history
      api.addToCPESearchHistory(input, results);
      setSearchHistory(api.getCPESearchHistory(5));

      // Track search
      api.trackCPESearch(input, results, searchMode);

      // Pass results to parent
      if (onResults) {
        onResults(results);
      }

    } catch (error) {
      console.error('Search failed:', error);
      setGuidance({
        type: 'error',
        message: `Search failed: ${error.message}`,
        suggestions: ['Please try again with different terms']
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleSuggestionClick = (suggestion) => {
    setInput(suggestion);
    setSuggestions([]);
    // Trigger search automatically
    setTimeout(() => handleSearch(), 100);
  };

  const handleHistoryClick = (historyItem) => {
    setInput(historyItem.query);
    setTimeout(() => handleSearch(), 100);
  };

  const getConfidenceColor = () => {
    if (confidence >= 0.7) return 'bg-green-500';
    if (confidence >= 0.4) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  const getGuidanceIcon = () => {
    switch (guidance?.type) {
      case 'success': return <CheckCircle className="h-4 w-4 text-green-600" />;
      case 'warning': return <AlertCircle className="h-4 w-4 text-yellow-600" />;
      case 'error': return <AlertCircle className="h-4 w-4 text-red-600" />;
      default: return <Lightbulb className="h-4 w-4 text-blue-600" />;
    }
  };

  const examples = [
    { text: "Apache HTTP Server 2.4", category: "Web Server", icon: "🌐" },
    { text: "MySQL 8.0.25", category: "Database", icon: "🗄️" },
    { text: "nginx 1.18", category: "Web Server", icon: "⚡" },
    { text: "PostgreSQL 13", category: "Database", icon: "🐘" },
    { text: "Microsoft Windows Server 2019", category: "Operating System", icon: "💻" },
    { text: "Docker 20.10", category: "Container Platform", icon: "📦" }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h3 className="text-xl font-semibold text-gray-900">Smart Software Search</h3>
          <p className="text-gray-600">Find software vulnerabilities using natural language</p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={() => setShowTutorial(!showTutorial)}
            className="flex items-center space-x-1 text-sm text-blue-600 hover:text-blue-800"
          >
            <BookOpen className="h-4 w-4" />
            <span>{showTutorial ? 'Hide' : 'Show'} Help</span>
          </button>
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center space-x-1 text-sm text-gray-600 hover:text-gray-800"
          >
            <Filter className="h-4 w-4" />
            <span>Advanced</span>
          </button>
        </div>
      </div>

      {/* Search Mode Toggle */}
      <div className="flex justify-center">
        <div className="bg-gray-100 rounded-lg p-1 flex">
          {['smart', 'simple', 'advanced'].map((mode) => (
            <button
              key={mode}
              onClick={() => setSearchMode(mode)}
              className={`px-4 py-2 rounded-md capitalize transition-colors ${
                searchMode === mode 
                  ? 'bg-white text-blue-600 shadow-sm' 
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              {mode}
            </button>
          ))}
        </div>
      </div>

      {/* Tutorial Section */}
      {showTutorial && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
          <h4 className="font-medium text-blue-900 mb-3">How to Search Effectively</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-blue-800">
            <div>
              <p className="font-medium mb-2">✅ Good Examples:</p>
              <ul className="space-y-1">
                <li>• "Apache HTTP Server 2.4"</li>
                <li>• "MySQL database 8.0"</li>
                <li>• "nginx web server"</li>
                <li>• "Windows Server 2019"</li>
              </ul>
            </div>
            <div>
              <p className="font-medium mb-2">❌ Avoid:</p>
              <ul className="space-y-1">
                <li>• Too vague: "server software"</li>
                <li>• Just versions: "2.4.1"</li>
                <li>• Abbreviations: "IIS"</li>
                <li>• Internal names: "prod-web-01"</li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Advanced Filters */}
      {showAdvanced && (
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <h4 className="font-medium text-gray-900 mb-4">Advanced Search Filters</h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Vendor</label>
              <input
                type="text"
                value={advancedFilters.vendor}
                onChange={(e) => setAdvancedFilters(prev => ({ ...prev, vendor: e.target.value }))}
                placeholder="e.g., apache, microsoft"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Product</label>
              <input
                type="text"
                value={advancedFilters.product}
                onChange={(e) => setAdvancedFilters(prev => ({ ...prev, product: e.target.value }))}
                placeholder="e.g., http_server, windows"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Version</label>
              <input
                type="text"
                value={advancedFilters.version}
                onChange={(e) => setAdvancedFilters(prev => ({ ...prev, version: e.target.value }))}
                placeholder="e.g., 2.4.41"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>
          <div className="mt-4 flex items-center justify-between">
            <div className="flex items-center">
              <input
                type="checkbox"
                id="includeDeprecated"
                checked={advancedFilters.includeDeprecated}
                onChange={(e) => setAdvancedFilters(prev => ({ ...prev, includeDeprecated: e.target.checked }))}
                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              <label htmlFor="includeDeprecated" className="ml-2 text-sm text-gray-700">
                Include deprecated products
              </label>
            </div>
            <div className="flex items-center space-x-2">
              <label className="text-sm text-gray-700">Confidence:</label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.1"
                value={advancedFilters.confidenceThreshold}
                onChange={(e) => setAdvancedFilters(prev => ({ ...prev, confidenceThreshold: parseFloat(e.target.value) }))}
                className="w-20"
              />
              <span className="text-sm text-gray-600">{Math.round(advancedFilters.confidenceThreshold * 100)}%</span>
            </div>
          </div>
        </div>
      )}

      {/* Main Search Interface */}
      <div className="relative">
        <div className="relative">
          <Search className="absolute left-4 top-4 h-5 w-5 text-gray-400" />
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder="Search for software (e.g., 'apache web server', 'mysql 8.0', 'windows server')..."
            className="w-full pl-12 pr-24 py-4 text-lg border-2 border-gray-200 rounded-xl focus:border-blue-500 focus:ring-0 transition-colors"
          />
          
          {/* Confidence Indicator */}
          {input && (
            <div className="absolute right-4 top-4 flex items-center space-x-3">
              {isLoading && (
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600"></div>
              )}
              <div className="flex items-center space-x-2">
                <div className="w-16 bg-gray-200 rounded-full h-2">
                  <div 
                    className={`h-2 rounded-full transition-all duration-300 ${getConfidenceColor()}`}
                    style={{ width: `${confidence * 100}%` }}
                  ></div>
                </div>
                <span className="text-xs text-gray-500">{Math.round(confidence * 100)}%</span>
              </div>
              <button
                onClick={handleSearch}
                disabled={!input.trim() || isLoading}
                className="bg-blue-600 text-white px-4 py-1 rounded-lg hover:bg-blue-700 disabled:opacity-50 text-sm"
              >
                Search
              </button>
            </div>
          )}
        </div>

        {/* Live Suggestions */}
        {suggestions.length > 0 && (
          <div className="absolute z-10 w-full mt-2 bg-white border border-gray-200 rounded-lg shadow-lg max-h-64 overflow-y-auto">
            <div className="p-2 text-xs text-gray-500 border-b">Suggestions</div>
            {suggestions.map((suggestion, index) => (
              <div
                key={index}
                onClick={() => handleSuggestionClick(suggestion)}
                className="p-3 hover:bg-gray-50 cursor-pointer border-b border-gray-100 last:border-b-0 flex items-center justify-between"
              >
                <span className="font-medium text-gray-900">{suggestion}</span>
                <ArrowRight className="h-4 w-4 text-gray-400" />
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Real-time Guidance */}
      {guidance && (
        <div className={`p-4 rounded-lg border ${
          guidance.type === 'success' ? 'bg-green-50 border-green-200' :
          guidance.type === 'warning' ? 'bg-yellow-50 border-yellow-200' :
          guidance.type === 'error' ? 'bg-red-50 border-red-200' :
          'bg-blue-50 border-blue-200'
        }`}>
          <div className="flex items-start space-x-2">
            {getGuidanceIcon()}
            <div className="flex-1">
              <p className={`text-sm font-medium ${
                guidance.type === 'success' ? 'text-green-800' :
                guidance.type === 'warning' ? 'text-yellow-800' :
                guidance.type === 'error' ? 'text-red-800' :
                'text-blue-800'
              }`}>
                {guidance.message}
              </p>
              {guidance.suggestions && guidance.suggestions.length > 0 && (
                <ul className={`mt-2 text-xs space-y-1 ${
                  guidance.type === 'success' ? 'text-green-700' :
                  guidance.type === 'warning' ? 'text-yellow-700' :
                  guidance.type === 'error' ? 'text-red-700' :
                  'text-blue-700'
                }`}>
                  {guidance.suggestions.map((suggestion, index) => (
                    <li key={index}>• {suggestion}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Search History */}
      {!input && searchHistory.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h4 className="font-medium text-gray-900 mb-3 flex items-center">
            <Clock className="h-4 w-4 mr-2" />
            Recent Searches
          </h4>
          <div className="space-y-2">
            {searchHistory.map((item, index) => (
              <button
                key={index}
                onClick={() => handleHistoryClick(item)}
                className="w-full text-left p-2 bg-white rounded border hover:border-blue-300 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-gray-900">{item.query}</span>
                  <div className="flex items-center space-x-2 text-xs text-gray-500">
                    <span>{item.result_count} results</span>
                    <span>{Math.round(item.confidence * 100)}% confidence</span>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Quick Examples */}
      {!input && searchHistory.length === 0 && (
        <div className="bg-gray-50 rounded-lg p-6">
          <h4 className="font-medium text-gray-900 mb-4 flex items-center">
            <TrendingUp className="h-4 w-4 mr-2" />
            Popular Software
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {examples.map((example, index) => (
              <button
                key={index}
                onClick={() => setInput(example.text)}
                className="flex items-center justify-between p-3 bg-white rounded-lg border border-gray-200 hover:border-blue-300 hover:bg-blue-50 transition-colors text-left"
              >
                <div className="flex items-center space-x-3">
                  <span className="text-lg">{example.icon}</span>
                  <div>
                    <div className="font-medium text-gray-900">{example.text}</div>
                    <div className="text-sm text-gray-600">{example.category}</div>
                  </div>
                </div>
                <ArrowRight className="h-4 w-4 text-gray-400" />
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Smart Analysis Display */}
      {input && confidence > 0.4 && (
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <h4 className="font-medium text-gray-900 mb-3 flex items-center">
            <Zap className="h-4 w-4 text-blue-600 mr-2" />
            Smart Analysis
          </h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-gray-600">Vendor:</span>
              <div className="font-medium text-gray-900">
                {extractVendor(input) || <span className="text-gray-400">Not detected</span>}
              </div>
            </div>
            <div>
              <span className="text-gray-600">Product:</span>
              <div className="font-medium text-gray-900">
                {extractProduct(input) || <span className="text-gray-400">Not detected</span>}
              </div>
            </div>
            <div>
              <span className="text-gray-600">Version:</span>
              <div className="font-medium text-gray-900">
                {extractVersion(input) || <span className="text-gray-400">Not detected</span>}
              </div>
            </div>
            <div>
              <span className="text-gray-600">Type:</span>
              <div className="font-medium text-gray-900">
                {classifyType(input) || <span className="text-gray-400">Application</span>}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Selected CPE Display */}
      {selectedCPE && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-6">
          <div className="flex items-start justify-between">
            <div className="flex items-start">
              <CheckCircle className="h-5 w-5 text-green-600 mt-0.5 mr-3 flex-shrink-0" />
              <div>
                <h3 className="font-medium text-green-900">Selected: {selectedCPE.display_name}</h3>
                <p className="text-sm text-green-800 mt-1">{selectedCPE.description}</p>
                <div className="mt-2 text-xs text-green-700 font-mono bg-green-100 p-2 rounded">
                  {selectedCPE.cpe_name}
                </div>
                <div className="mt-2 flex items-center space-x-4 text-xs text-green-700">
                  <span className="flex items-center">
                    <Star className="h-3 w-3 mr-1" />
                    {selectedCPE.popularity_stars}/5 popularity
                  </span>
                  <span className="flex items-center">
                    <Shield className="h-3 w-3 mr-1" />
                    {selectedCPE.risk_badge.text}
                  </span>
                </div>
              </div>
            </div>
            <button
              onClick={() => setSelectedCPE(null)}
              className="text-green-600 hover:text-green-800"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

// Helper functions for parsing (simplified versions)
const extractVendor = (query) => {
  const vendors = ['apache', 'microsoft', 'oracle', 'nginx', 'mysql', 'postgresql', 'mongodb', 'redis', 'google', 'amazon'];
  const found = vendors.find(vendor => query.toLowerCase().includes(vendor));
  return found ? found.charAt(0).toUpperCase() + found.slice(1) : null;
};

const extractProduct = (query) => {
  const products = {
    'http server': 'HTTP Server',
    'web server': 'Web Server',
    'database': 'Database',
    'nginx': 'Nginx',
    'mysql': 'MySQL',
    'postgresql': 'PostgreSQL',
    'mongodb': 'MongoDB',
    'redis': 'Redis',
    'windows': 'Windows',
    'linux': 'Linux'
  };
  
  const lowerQuery = query.toLowerCase();
  for (const [key, value] of Object.entries(products)) {
    if (lowerQuery.includes(key)) {
      return value;
    }
  }
  return null;
};

const extractVersion = (query) => {
  const versionMatch = query.match(/\d+\.\d+(?:\.\d+)?(?:\.\d+)?/);
  return versionMatch ? versionMatch[0] : null;
};

const classifyType = (query) => {
  const lowerQuery = query.toLowerCase();
  if (lowerQuery.includes('server') || lowerQuery.includes('database')) return 'Application';
  if (lowerQuery.includes('windows') || lowerQuery.includes('linux') || lowerQuery.includes('os')) return 'Operating System';
  if (lowerQuery.includes('router') || lowerQuery.includes('switch')) return 'Hardware';
  return 'Application';
};

export default EnhancedCPESearch;
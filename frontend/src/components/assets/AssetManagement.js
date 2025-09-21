// Enhanced AssetManagement.js with clean separation of concerns
import React, { useState, useEffect, useCallback } from 'react';
import { 
  Plus, 
  Edit, 
  Trash2, 
  Search, 
  RefreshCw, 
  AlertTriangle, 
  X,
  Eye,
  Server,
  Shield,
  Monitor
} from 'lucide-react';
import { api } from '../../services/api';
import CreateAssetModal from './CreateAssetModal';
import EditAssetModal from './EditAssetModal';

// Enhanced Error Boundary
const ErrorBoundary = ({ children, fallback }) => {
  const [hasError, setHasError] = useState(false);

  useEffect(() => {
    const handleError = (error) => {
      setHasError(true);
      console.error('Component Error:', error);
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

// Toast Notification Component
const Toast = ({ message, type = 'info', onClose }) => {
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

// Delete Confirmation Modal
const DeleteConfirmationModal = ({ asset, isOpen, onClose, onConfirm }) => {
  const [loading, setLoading] = useState(false);

  const handleDelete = async () => {
    setLoading(true);
    try {
      await onConfirm();
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg max-w-md w-full">
        <div className="px-6 py-4">
          <div className="flex items-center mb-4">
            <AlertTriangle className="h-6 w-6 text-red-600 mr-3" />
            <h3 className="text-lg font-medium text-gray-900">Delete Asset</h3>
          </div>
          
          <p className="text-gray-600 mb-6">
            Are you sure you want to delete <strong>{asset?.name}</strong>? This action cannot be undone.
          </p>
          
          <div className="flex justify-end space-x-3">
            <button
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
              disabled={loading}
            >
              Cancel
            </button>
            <button
              onClick={handleDelete}
              disabled={loading}
              className="px-4 py-2 text-sm font-medium text-white bg-red-600 border border-transparent rounded-md hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
            >
              {loading && <RefreshCw className="animate-spin h-4 w-4 mr-2" />}
              Delete Asset
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Asset Detail Modal
const AssetDetailModal = ({ asset, isOpen, onClose }) => {
  if (!isOpen || !asset) return null;

  const getAssetTypeIcon = (type) => {
    switch (type) {
      case 'server': return <Server className="h-5 w-5" />;
      case 'database': return <Monitor className="h-5 w-5" />;
      default: return <Shield className="h-5 w-5" />;
    }
  };

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg w-full max-w-3xl max-h-[90vh] overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              {getAssetTypeIcon(asset.asset_type)}
              <h3 className="text-lg font-medium text-gray-900 ml-2">{asset.name}</h3>
            </div>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
              <X className="h-6 w-6" />
            </button>
          </div>
        </div>

        <div className="px-6 py-4 overflow-y-auto max-h-[calc(90vh-120px)]">
          <div className="grid grid-cols-2 gap-6">
            {/* Basic Information */}
            <div>
              <h4 className="text-sm font-medium text-gray-900 mb-3">Basic Information</h4>
              <dl className="space-y-2">
                <div>
                  <dt className="text-xs font-medium text-gray-500">Asset Type</dt>
                  <dd className="text-sm text-gray-900 capitalize">{asset.asset_type?.replace('_', ' ')}</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-gray-500">Environment</dt>
                  <dd className="text-sm text-gray-900 capitalize">{asset.environment}</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-gray-500">Criticality</dt>
                  <dd className="text-sm text-gray-900 capitalize">{asset.criticality}</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-gray-500">Location</dt>
                  <dd className="text-sm text-gray-900">{asset.location || 'Not specified'}</dd>
                </div>
              </dl>
            </div>

            {/* Network Information */}
            <div>
              <h4 className="text-sm font-medium text-gray-900 mb-3">Network Information</h4>
              <dl className="space-y-2">
                <div>
                  <dt className="text-xs font-medium text-gray-500">IP Address</dt>
                  <dd className="text-sm text-gray-900">{asset.ip_address || 'Not specified'}</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-gray-500">Hostname</dt>
                  <dd className="text-sm text-gray-900">{asset.hostname || 'Not specified'}</dd>
                </div>
              </dl>
            </div>

            {/* Service Information */}
            <div>
              <h4 className="text-sm font-medium text-gray-900 mb-3">Service Information</h4>
              <dl className="space-y-2">
                <div>
                  <dt className="text-xs font-medium text-gray-500">Primary Service</dt>
                  <dd className="text-sm text-gray-900">{asset.primary_service || 'Not specified'}</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-gray-500">Service Vendor</dt>
                  <dd className="text-sm text-gray-900">{asset.service_vendor || 'Not specified'}</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-gray-500">Service Version</dt>
                  <dd className="text-sm text-gray-900">{asset.service_version || 'Not specified'}</dd>
                </div>
              </dl>
            </div>

            {/* Operating System */}
            <div>
              <h4 className="text-sm font-medium text-gray-900 mb-3">Operating System</h4>
              <dl className="space-y-2">
                <div>
                  <dt className="text-xs font-medium text-gray-500">Operating System</dt>
                  <dd className="text-sm text-gray-900">{asset.operating_system || 'Not specified'}</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-gray-500">OS Version</dt>
                  <dd className="text-sm text-gray-900">{asset.os_version || 'Not specified'}</dd>
                </div>
              </dl>
            </div>
          </div>

          {/* Tags */}
          {asset.tags && asset.tags.length > 0 && (
            <div className="mt-6">
              <h4 className="text-sm font-medium text-gray-900 mb-3">Tags</h4>
              <div className="flex flex-wrap gap-2">
                {asset.tags.map((tag, index) => (
                  <span
                    key={index}
                    className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Metadata */}
          {asset.created_at && (
            <div className="mt-6 pt-6 border-t border-gray-200">
              <h4 className="text-sm font-medium text-gray-900 mb-3">Metadata</h4>
              <dl className="grid grid-cols-2 gap-4">
                <div>
                  <dt className="text-xs font-medium text-gray-500">Created</dt>
                  <dd className="text-sm text-gray-900">
                    {new Date(asset.created_at).toLocaleDateString()}
                  </dd>
                </div>
                {asset.updated_at && (
                  <div>
                    <dt className="text-xs font-medium text-gray-500">Last Updated</dt>
                    <dd className="text-sm text-gray-900">
                      {new Date(asset.updated_at).toLocaleDateString()}
                    </dd>
                  </div>
                )}
              </dl>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Main AssetManagement Component
const AssetManagement = () => {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('');
  const [filterEnvironment, setFilterEnvironment] = useState('');
  const [filterCriticality, setFilterCriticality] = useState('');
  
  // Modal states
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [selectedAsset, setSelectedAsset] = useState(null);
  
  // Toast state
  const [toast, setToast] = useState(null);

  const addToast = useCallback((message, type = 'info') => {
    setToast({ message, type });
  }, []);

  const removeToast = useCallback(() => {
    setToast(null);
  }, []);

  // Load assets
  const loadAssets = useCallback(async (showRefreshIndicator = false) => {
    if (showRefreshIndicator) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    try {
      const params = {};
      if (searchTerm) params.search = searchTerm;
      if (filterType) params.asset_type = filterType;
      if (filterEnvironment) params.environment = filterEnvironment;
      if (filterCriticality) params.criticality = filterCriticality;

      const data = await api.getAssets(params);
      setAssets(Array.isArray(data) ? data : data.data || []);
    } catch (error) {
      console.error('Failed to load assets:', error);
      addToast(`Failed to load assets: ${error.message}`, 'error');
      
      // Fallback to mock data for development
      setAssets([
        { 
          id: 1, 
          name: 'Web Server 01', 
          asset_type: 'server', 
          environment: 'production', 
          criticality: 'critical', 
          ip_address: '10.0.1.10',
          hostname: 'web-01.company.com',
          primary_service: 'Apache HTTP Server',
          service_version: '2.4.41',
          operating_system: 'Ubuntu Linux',
          os_version: '20.04 LTS',
          location: 'Data Center A',
          tags: ['web', 'frontend', 'critical']
        },
        { 
          id: 2, 
          name: 'Database Server', 
          asset_type: 'database', 
          environment: 'production', 
          criticality: 'high', 
          ip_address: '10.0.1.20',
          hostname: 'db-01.company.com',
          primary_service: 'PostgreSQL',
          service_version: '13.7',
          operating_system: 'CentOS Linux',
          os_version: '8',
          location: 'Data Center A',
          tags: ['database', 'postgresql', 'backend']
        }
      ]);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [searchTerm, filterType, filterEnvironment, filterCriticality, addToast]);

  // Load assets on component mount and when filters change
  useEffect(() => {
    loadAssets();
  }, [loadAssets]);

  // Handle asset operations
  const handleEditAsset = (asset) => {
    setSelectedAsset(asset);
    setShowEditModal(true);
  };

  const handleDeleteAsset = (asset) => {
    setSelectedAsset(asset);
    setShowDeleteModal(true);
  };

  const handleViewAsset = (asset) => {
    setSelectedAsset(asset);
    setShowDetailModal(true);
  };

  const handleDeleteConfirm = async () => {
    try {
      await api.deleteAsset(selectedAsset.id);
      setAssets(prev => prev.filter(asset => asset.id !== selectedAsset.id));
      addToast(`Asset "${selectedAsset.name}" deleted successfully`, 'success');
      setShowDeleteModal(false);
      setSelectedAsset(null);
    } catch (error) {
      console.error('Failed to delete asset:', error);
      addToast(`Failed to delete asset: ${error.message}`, 'error');
    }
  };

  const handleAssetUpdated = () => {
    addToast('Asset updated successfully', 'success');
    loadAssets(true);
    setShowEditModal(false);
    setSelectedAsset(null);
  };

  const handleAssetCreated = () => {
    addToast('Asset created successfully', 'success');
    loadAssets(true);
    setShowCreateModal(false);
  };

  // Color mappings
  const ENVIRONMENT_COLORS = {
    production: 'bg-red-100 text-red-800 border-red-200',
    staging: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    development: 'bg-green-100 text-green-800 border-green-200',
    testing: 'bg-blue-100 text-blue-800 border-blue-200'
  };

  const CRITICALITY_COLORS = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-green-100 text-green-800 border-green-200'
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center min-h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        {/* Toast Notification */}
        {toast && (
          <Toast
            message={toast.message}
            type={toast.type}
            onClose={removeToast}
          />
        )}

        {/* Header */}
        <div className="flex justify-between items-center">
          <h2 className="text-2xl font-bold text-gray-900">Asset Management</h2>
          <div className="flex space-x-3">
            <button
              onClick={() => loadAssets(true)}
              disabled={refreshing}
              className="bg-gray-100 text-gray-700 px-4 py-2 rounded-lg hover:bg-gray-200 flex items-center gap-2 disabled:opacity-50"
            >
              <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <button 
              onClick={() => setShowCreateModal(true)}
              className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center gap-2"
            >
              <Plus className="h-4 w-4" />
              Add Asset
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search assets..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>

            {/* Asset Type Filter */}
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="">All Types</option>
              <option value="server">Server</option>
              <option value="workstation">Workstation</option>
              <option value="network_device">Network Device</option>
              <option value="database">Database</option>
              <option value="application">Application</option>
              <option value="container">Container</option>
              <option value="iot_device">IoT Device</option>
              <option value="other">Other</option>
            </select>

            {/* Environment Filter */}
            <select
              value={filterEnvironment}
              onChange={(e) => setFilterEnvironment(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="">All Environments</option>
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="development">Development</option>
              <option value="testing">Testing</option>
            </select>

            {/* Criticality Filter */}
            <select
              value={filterCriticality}
              onChange={(e) => setFilterCriticality(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="">All Criticality Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>

        {/* Assets Table */}
        <div className="bg-white rounded-lg shadow overflow-hidden">
          {assets.length === 0 ? (
            <div className="text-center py-12">
              <Shield className="mx-auto h-12 w-12 text-gray-400" />
              <h3 className="mt-2 text-sm font-medium text-gray-900">No assets found</h3>
              <p className="mt-1 text-sm text-gray-500">
                Get started by creating a new asset.
              </p>
              <div className="mt-6">
                <button
                  onClick={() => setShowCreateModal(true)}
                  className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
                >
                  <Plus className="h-4 w-4 mr-2" />
                  Add Asset
                </button>
              </div>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP Address</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Environment</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Criticality</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {assets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="flex-shrink-0 h-8 w-8">
                          {asset.asset_type === 'server' && <Server className="h-5 w-5 text-gray-400" />}
                          {asset.asset_type === 'database' && <Monitor className="h-5 w-5 text-gray-400" />}
                          {!['server', 'database'].includes(asset.asset_type) && <Shield className="h-5 w-5 text-gray-400" />}
                        </div>
                        <div className="ml-3">
                          <div className="text-sm font-medium text-gray-900">{asset.name}</div>
                          {asset.hostname && (
                            <div className="text-sm text-gray-500">{asset.hostname}</div>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      <span className="capitalize">{asset.asset_type?.replace('_', ' ')}</span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {asset.ip_address || 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full border ${
                        ENVIRONMENT_COLORS[asset.environment] || 'bg-gray-100 text-gray-800 border-gray-200'
                      }`}>
                        {asset.environment}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full border ${
                        CRITICALITY_COLORS[asset.criticality] || 'bg-gray-100 text-gray-800 border-gray-200'
                      }`}>
                        {asset.criticality}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => handleViewAsset(asset)}
                          className="text-blue-600 hover:text-blue-900 flex items-center"
                          title="View Details"
                        >
                          <Eye className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleEditAsset(asset)}
                          className="text-indigo-600 hover:text-indigo-900 flex items-center"
                          title="Edit Asset"
                        >
                          <Edit className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteAsset(asset)}
                          className="text-red-600 hover:text-red-900 flex items-center"
                          title="Delete Asset"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Modals */}
        {showCreateModal && (
          <CreateAssetModal
            onClose={() => setShowCreateModal(false)}
            onSuccess={handleAssetCreated}
          />
        )}

        {showEditModal && selectedAsset && (
          <EditAssetModal
            asset={selectedAsset}
            onClose={() => {
              setShowEditModal(false);
              setSelectedAsset(null);
            }}
            onSuccess={handleAssetUpdated}
          />
        )}

        {showDeleteModal && selectedAsset && (
          <DeleteConfirmationModal
            asset={selectedAsset}
            isOpen={showDeleteModal}
            onClose={() => {
              setShowDeleteModal(false);
              setSelectedAsset(null);
            }}
            onConfirm={handleDeleteConfirm}
          />
        )}

        {showDetailModal && selectedAsset && (
          <AssetDetailModal
            asset={selectedAsset}
            isOpen={showDetailModal}
            onClose={() => {
              setShowDetailModal(false);
              setSelectedAsset(null);
            }}
          />
        )}
      </div>
    </ErrorBoundary>
  );
};

export default AssetManagement;
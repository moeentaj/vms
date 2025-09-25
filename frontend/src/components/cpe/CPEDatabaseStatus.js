import React from 'react';
import { 
  Database, 
  CheckCircle, 
  XCircle, 
  AlertTriangle, 
  Loader, 
  RefreshCw, 
  Download 
} from 'lucide-react';

const CPEDatabaseStatus = ({ status, onRefresh, onInitialize, loading }) => {
  const getStatusColor = () => {
    if (!status) return 'gray';
    if (status.has_data && status.total_products > 0) return 'green';
    if (status.has_data && status.needs_refresh) return 'yellow';
    return 'red';
  };

  const getStatusIcon = () => {
    const color = getStatusColor();
    if (loading) return <Loader className="h-5 w-5 animate-spin" />;
    if (color === 'green') return <CheckCircle className="h-5 w-5 text-green-600" />;
    if (color === 'yellow') return <AlertTriangle className="h-5 w-5 text-yellow-600" />;
    return <XCircle className="h-5 w-5 text-red-600" />;
  };

  const getStatusMessage = () => {
    if (loading) return 'Checking CPE database status...';
    if (!status) return 'Unable to check CPE status';

    if (status.has_data && status.total_products > 0) {
      return `CPE database ready with ${status.total_products?.toLocaleString()} products`;
    }

    if (status.has_data && status.needs_refresh) {
      return 'CPE database needs refresh';
    }

    return 'CPE database not initialized - required for lookups';
  };

  const canInitialize = () => {
    return !loading && (!status?.has_data || status?.needs_refresh);
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-3">
          <Database className="h-6 w-6 text-blue-600" />
          <h3 className="text-lg font-medium text-gray-900">CPE Database Status</h3>
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="text-gray-400 hover:text-gray-600 disabled:opacity-50"
        >
          <RefreshCw className={`h-5 w-5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          {getStatusIcon()}
          <div>
            <div className="font-medium text-gray-900">Database Status</div>
            <div className="text-sm text-gray-600">{getStatusMessage()}</div>
          </div>
        </div>

        {canInitialize() && (
          <button
            onClick={onInitialize}
            disabled={loading}
            className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 flex items-center space-x-2"
          >
            <Download className="h-4 w-4" />
            <span>
              {status?.has_data ? 'Refresh Database' : 'Initialize Database'}
            </span>
          </button>
        )}
      </div>

      {/* Database Details */}
      {status && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4 pt-4 border-t border-gray-200">
          <div className="text-center">
            <div className="text-sm text-gray-500">Total Products</div>
            <div className="text-lg font-semibold text-gray-900">
              {status.total_products?.toLocaleString() || '0'}
            </div>
          </div>

          <div className="text-center">
            <div className="text-sm text-gray-500">Cache Age</div>
            <div className="text-lg font-semibold text-gray-900">
              {status.cache_age_hours ? `${Math.round(status.cache_age_hours)}h` : 'N/A'}
            </div>
          </div>

          <div className="text-center">
            <div className="text-sm text-gray-500">Last Updated</div>
            <div className="text-sm font-medium text-gray-900">
              {status.last_refresh ? new Date(status.last_refresh).toLocaleDateString() : 'Never'}
            </div>
          </div>
        </div>
      )}

      {/* Status Details */}
      {status && status.reason && (
        <div className="mt-4 pt-4 border-t border-gray-200">
          <div className="text-sm text-gray-600">
            <strong>Status:</strong> {status.reason}
          </div>
        </div>
      )}
    </div>
  );
};

export default CPEDatabaseStatus;
import React, { useState, useEffect } from 'react';
import { Plus } from 'lucide-react';
import { api } from '../../services/api';
import { ENVIRONMENT_COLORS, CRITICALITY_COLORS } from '../../utils/constants';
import CreateAssetModal from './CreateAssetModal';

const AssetManagement = () => {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);

  useEffect(() => {
    loadAssets();
  }, []);

  const loadAssets = async () => {
    try {
      const data = await api.getAssets();
      setAssets(data);
    } catch (error) {
      console.error('Failed to load assets:', error);
      // Mock data for development
      setAssets([
        { 
          id: 1, 
          name: 'Web Server 01', 
          asset_type: 'server', 
          environment: 'production', 
          criticality: 'critical', 
          ip_address: '10.0.1.10' 
        },
        { 
          id: 2, 
          name: 'Database Server', 
          asset_type: 'database', 
          environment: 'production', 
          criticality: 'high', 
          ip_address: '10.0.1.20' 
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="flex justify-center p-8"><div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div></div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">Asset Management</h2>
        <button 
          onClick={() => setShowCreateModal(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center gap-2"
        >
          <Plus className="h-4 w-4" />
          Add Asset
        </button>
      </div>

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP Address</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Environment</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Criticality</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {assets.map((asset) => (
              <tr key={asset.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                  {asset.name}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  {asset.asset_type}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  {asset.ip_address}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${ENVIRONMENT_COLORS[asset.environment] || 'bg-gray-100 text-gray-800'}`}>
                    {asset.environment}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${CRITICALITY_COLORS[asset.criticality] || 'bg-gray-100 text-gray-800'}`}>
                    {asset.criticality}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  <button className="text-blue-600 hover:text-blue-900 mr-3">
                    Edit
                  </button>
                  <button className="text-red-600 hover:text-red-900">
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Create Asset Modal */}
      {showCreateModal && (
        <CreateAssetModal
          onClose={() => setShowCreateModal(false)}
          onSuccess={() => {
            setShowCreateModal(false);
            loadAssets();
          }}
        />
      )}
    </div>
  );
};

export default AssetManagement;
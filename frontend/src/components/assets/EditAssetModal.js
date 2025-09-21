// EditAssetModal.js - Consistent with CreateAssetModal structure
import React, { useState, useEffect } from 'react';
import { X, Search, Loader, Plus, Trash2, Loader2 } from 'lucide-react';
import { api } from '../../services/api';

// Loading Modal Component
const LoadingModal = ({ open, title, subtitle }) => {
  if (!open) return null;
  return (
    <div className="fixed inset-0 bg-gray-800 bg-opacity-75 flex items-center justify-center z-[60]">
      <div className="bg-white rounded-lg p-6 max-w-sm w-full mx-4">
        <div className="flex items-center space-x-3">
          <Loader className="animate-spin h-5 w-5 text-blue-600" />
          <div>
            <div className="font-medium">{title}</div>
            <div className="text-sm text-gray-600">{subtitle}</div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Toast Stack Component
const ToastStack = ({ toasts, remove }) => (
  <div className="fixed top-4 right-4 z-[55] space-y-2">
    {toasts.map(toast => (
      <div
        key={toast.id}
        className={`p-4 rounded-md shadow-md max-w-sm ${
          toast.type === 'error' ? 'bg-red-100 text-red-800' :
          toast.type === 'success' ? 'bg-green-100 text-green-800' :
          'bg-blue-100 text-blue-800'
        }`}
      >
        <div className="flex justify-between">
          <span className="text-sm">{toast.message}</span>
          <button onClick={() => remove(toast.id)} className="ml-2 text-current">
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>
    ))}
  </div>
);

// CPE Lookup Inline Component - Exactly like CreateAssetModal
const CpeLookupInline = ({ onSelect, buttonLabel = 'CPE Lookup', placeholder = "Search CPE (e.g., 'nginx', 'postgres', 'tomcat')" }) => {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    const t = setTimeout(async () => {
      if (!open) return;
      if (!query.trim()) {
        setResults([]);
        return;
      }
      setLoading(true);
      setError('');
      try {
        const resp = await fetch('/api/v1/assets/cpe-lookup', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          },
          body: JSON.stringify({ query, limit: 12 })
        });
        if (!resp.ok) throw new Error('Lookup failed');
        const data = await resp.json();
        setResults(Array.isArray(data) ? data : []);
      } catch (e) {
        setResults([]);
        setError('Search failed. Try again.');
      } finally {
        setLoading(false);
      }
    }, 300);
    return () => clearTimeout(t);
  }, [query, open]);

  return (
    <div className="mt-2">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className="inline-flex items-center gap-2 bg-blue-100 text-blue-700 px-3 py-1.5 rounded-md hover:bg-blue-200"
      >
        <Search className="h-4 w-4" />
        {open ? 'Close Lookup' : buttonLabel}
      </button>

      {open && (
        <div className="mt-2 p-3 bg-gray-50 rounded-md border border-gray-200">
          <div className="relative">
            <input
              type="text"
              placeholder={placeholder}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 pr-10"
            />
            <Search className="h-5 w-5 text-gray-400 absolute right-3 top-2.5" />
          </div>

          {loading && (
            <div className="mt-2 text-sm text-gray-600 flex items-center gap-2">
              <Loader2 className="h-4 w-4 animate-spin" />
              Searching CPE database...
            </div>
          )}

          {error && !loading && (
            <div className="mt-2 text-sm text-red-600">{error}</div>
          )}

          {results.length > 0 && !loading && (
            <div className="mt-2 max-h-52 overflow-y-auto border border-gray-200 rounded-md divide-y">
              {results.map((r, i) => (
                <button
                  type="button"
                  key={`${r.cpe_name_id}-${i}`}
                  onClick={() => { onSelect(r); setOpen(false); setQuery(''); setResults([]); }}
                  className="w-full text-left p-3 hover:bg-gray-100"
                >
                  <div className="font-medium text-sm">
                    {(r.vendor || '').trim()} {(r.product || '').trim()} {(r.version || '').trim()}
                  </div>
                  <div className="text-xs text-gray-600 truncate">
                    {r.title || r.description || r.cpe_name}
                  </div>
                </button>
              ))}
            </div>
          )}

          {query && results.length === 0 && !loading && !error && (
            <div className="mt-2 text-sm text-gray-600">No results found. Try broader search terms.</div>
          )}
        </div>
      )}
    </div>
  );
};

/**
 * Edit Asset Modal - Consistent with CreateAssetModal structure
 * - Loads existing asset data and allows editing
 * - Unified services array with primary flag
 * - Per-service CPE lookup
 * - Optional OS CPE lookup
 * - Loading modal while updating the asset
 * - Toast notifications
 */
const EditAssetModal = ({ asset, onClose, onSuccess }) => {
  // Base form - initialize with existing asset data
  const [formData, setFormData] = useState({
    name: '',
    asset_type: 'server',
    ip_address: '',
    hostname: '',

    // OS
    operating_system: '',
    os_version: '',
    os_cpe_name: '',

    // Asset context
    environment: 'production',
    criticality: 'medium',
    location: '',
  });

  // Services (unified) - initialize with existing data
  const [services, setServices] = useState([]);

  // Tags - initialize with existing data
  const [tags, setTags] = useState([]);
  const [tagInput, setTagInput] = useState('');

  // Loading and toasts
  const [submitting, setSubmitting] = useState(false);
  const [toasts, setToasts] = useState([]);

  // Initialize form data when asset prop changes
  useEffect(() => {
    if (asset) {
      setFormData({
        name: asset.name || '',
        asset_type: asset.asset_type || 'server',
        ip_address: asset.ip_address || '',
        hostname: asset.hostname || '',
        operating_system: asset.operating_system || '',
        os_version: asset.os_version || '',
        os_cpe_name: asset.os_cpe_name || '',
        environment: asset.environment || 'production',
        criticality: asset.criticality || 'medium',
        location: asset.location || '',
      });

      // Initialize services array
      const initialServices = [];
      
      // Add primary service if exists
      if (asset.primary_service || asset.service_vendor || asset.service_version) {
        initialServices.push({
          name: asset.primary_service || '',
          vendor: asset.service_vendor || '',
          version: asset.service_version || '',
          ports: [],
          detection_method: 'manual',
          cpe_name: asset.cpe_name || '',
          cpe_name_id: asset.cpe_name_id || '',
          is_primary: true,
        });
      }

      // Add additional services if they exist
      if (asset.additional_services && Array.isArray(asset.additional_services)) {
        asset.additional_services.forEach(service => {
          initialServices.push({
            name: service.name || '',
            vendor: service.vendor || '',
            version: service.version || '',
            ports: service.ports || [],
            detection_method: service.detection_method || 'manual',
            cpe_name: service.cpe_name || '',
            cpe_name_id: service.cpe_name_id || '',
            is_primary: false,
          });
        });
      }

      // Ensure at least one service entry
      if (initialServices.length === 0) {
        initialServices.push({
          name: '',
          vendor: '',
          version: '',
          ports: [],
          detection_method: 'manual',
          cpe_name: '',
          cpe_name_id: '',
          is_primary: true,
        });
      }

      setServices(initialServices);

      // Initialize tags
      setTags(asset.tags || []);
    }
  }, [asset]);

  // Toast helpers
  const removeToast = (id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  };
  
  const addToast = (message, type = 'info', ttlMs = 4000) => {
    const id = `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    setToasts(prev => [...prev, { id, message, type }]);
    window.setTimeout(() => removeToast(id), ttlMs);
  };

  // Form helpers
  const updateField = (field, value) => setFormData(prev => ({ ...prev, [field]: value }));

  const addService = () => {
    setServices(prev => [
      ...prev,
      {
        name: '',
        vendor: '',
        version: '',
        ports: [],
        detection_method: 'manual',
        cpe_name: '',
        cpe_name_id: '',
        is_primary: prev.length === 0,
      }
    ]);
  };

  const removeService = (index) => {
    setServices(prev => {
      const next = [...prev];
      next.splice(index, 1);
      // Ensure at least one primary remains
      if (!next.some(s => s.is_primary) && next.length > 0) {
        next[0].is_primary = true;
      }
      return next;
    });
  };

  const updateService = (index, field, value) => {
    setServices(prev => prev.map((s, i) => i === index ? { ...s, [field]: value } : s));
  };

  const setPrimary = (index) => {
    setServices(prev => prev.map((s, i) => ({ ...s, is_primary: i === index })));
  };

  const addTag = () => {
    const t = tagInput.trim();
    if (!t) return;
    if (!tags.includes(t)) setTags(prev => [...prev, t]);
    setTagInput('');
  };

  const removeTag = (t) => setTags(prev => prev.filter(x => x !== t));

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (submitting) return;

    // Validation
    if (!formData.name.trim()) {
      addToast('Please provide an asset name.', 'error');
      return;
    }

    if (services.length === 0) {
      addToast('Please add at least one service.', 'error');
      return;
    }

    setSubmitting(true);

    try {
      const primary = services.find(s => s.is_primary) || services[0];
      const additional_services = services
        .filter(s => s !== primary)
        .map(({ is_primary, ...rest }) => rest);

      const payload = {
        // Basic info
        name: formData.name,
        asset_type: formData.asset_type,
        ip_address: formData.ip_address || null,
        hostname: formData.hostname || null,

        // Primary service mapped to top-level
        primary_service: primary.name || null,
        service_vendor: primary.vendor || null,
        service_version: primary.version || null,
        cpe_name_id: primary.cpe_name_id || null,
        cpe_name: primary.cpe_name || null,

        // Additional services
        additional_services: additional_services.length ? additional_services : null,

        // OS
        operating_system: formData.operating_system || null,
        os_version: formData.os_version || null,
        os_cpe_name: formData.os_cpe_name || null,

        // Context
        environment: formData.environment || 'production',
        criticality: formData.criticality || 'medium',
        location: formData.location || null,

        // Tags
        tags: tags.length ? tags : null,
      };

      const response = await api.updateAsset(asset.id, payload);
      
      addToast('Asset updated successfully!', 'success');
      
      if (onSuccess) onSuccess();
      onClose();
      
    } catch (err) {
      console.error('Update asset failed:', err);
      const msg = typeof err?.message === 'string' && err.message.trim()
        ? err.message.trim().slice(0, 400)
        : 'Failed to update asset. Please try again.';
      addToast(msg, 'error');
    } finally {
      setSubmitting(false);
    }
  };

  if (!asset) {
    return null;
  }

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50">
      <LoadingModal open={submitting} title="Updating asset..." subtitle="Saving your changes to the asset." />
      <ToastStack toasts={toasts} remove={removeToast} />

      <div className="bg-white rounded-lg p-6 w-full max-w-5xl max-h-[90vh] overflow-y-auto relative">
        <button
          type="button"
          className="absolute top-4 right-4 text-gray-500 hover:text-gray-700"
          onClick={onClose}
        >
          <X className="h-5 w-5" />
        </button>

        <h2 className="text-xl font-semibold mb-4">Edit Asset: {asset.name}</h2>

        <form onSubmit={handleSubmit} className="space-y-8">
          {/* Basic Info */}
          <section>
            <h3 className="text-sm font-semibold text-gray-900 mb-3">Basic Info</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Asset Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => updateField('name', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Type</label>
                <select
                  value={formData.asset_type}
                  onChange={(e) => updateField('asset_type', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                >
                  <option value="server">Server</option>
                  <option value="workstation">Workstation</option>
                  <option value="network_device">Network Device</option>
                  <option value="database">Database</option>
                  <option value="application">Application</option>
                  <option value="container">Container</option>
                  <option value="iot_device">IoT Device</option>
                  <option value="other">Other</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">IP Address</label>
                <input
                  type="text"
                  value={formData.ip_address}
                  onChange={(e) => updateField('ip_address', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g., 192.168.1.100"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Hostname</label>
                <input
                  type="text"
                  value={formData.hostname}
                  onChange={(e) => updateField('hostname', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g., web-server-01"
                />
              </div>
            </div>
          </section>

          {/* Services */}
          <section>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-gray-900">Services</h3>
              <button
                type="button"
                onClick={addService}
                className="flex items-center gap-1 text-sm text-blue-600 hover:text-blue-700"
              >
                <Plus className="h-4 w-4" />
                Add Service
              </button>
            </div>

            {services.map((service, index) => (
              <div key={index} className="border border-gray-200 rounded-md p-4 mb-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <input
                      type="radio"
                      name="primaryService"
                      checked={service.is_primary}
                      onChange={() => setPrimary(index)}
                      className="h-4 w-4 text-blue-600"
                    />
                    <span className="text-sm font-medium">
                      {service.is_primary ? 'Primary Service' : 'Additional Service'}
                    </span>
                  </div>
                  {services.length > 1 && (
                    <button
                      type="button"
                      onClick={() => removeService(index)}
                      className="text-red-600 hover:text-red-700"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-3">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Service Name</label>
                    <input
                      type="text"
                      value={service.name}
                      onChange={(e) => updateService(index, 'name', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                      placeholder="e.g., Apache HTTP Server"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Vendor</label>
                    <input
                      type="text"
                      value={service.vendor}
                      onChange={(e) => updateService(index, 'vendor', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                      placeholder="e.g., Apache Software Foundation"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Version</label>
                    <input
                      type="text"
                      value={service.version}
                      onChange={(e) => updateService(index, 'version', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                      placeholder="e.g., 2.4.41"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Detection Method</label>
                    <select
                      value={service.detection_method}
                      onChange={(e) => updateService(index, 'detection_method', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="manual">Manual</option>
                      <option value="scan">Network Scan</option>
                      <option value="agent">Agent</option>
                      <option value="config">Configuration</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Ports (comma-separated)</label>
                    <input
                      type="text"
                      value={(service.ports || []).join(',')}
                      onChange={(e) => {
                        const raw = e.target.value;
                        const ports = raw.split(',').map(p => p.trim()).filter(Boolean);
                        updateService(index, 'ports', ports);
                      }}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                      placeholder="e.g., 80, 443"
                    />
                  </div>
                </div>

                {/* CPE Lookup for this service - EXACTLY like CreateAssetModal */}
                <div className="mt-2">
                  <CpeLookupInline
                    onSelect={(cpe) => {
                      updateService(index, 'cpe_name_id', cpe.cpe_name_id);
                      updateService(index, 'cpe_name', cpe.cpe_name);
                      if (!service.name) updateService(index, 'name', cpe.product || '');
                      if (!service.vendor) updateService(index, 'vendor', cpe.vendor || '');
                      if (!service.version && cpe.version) updateService(index, 'version', cpe.version || '');
                    }}
                    buttonLabel={`CPE Lookup for ${service.name || 'Service'}`}
                    placeholder={`Search CPE for ${service.name || 'service'}...`}
                  />
                  {service.cpe_name && (
                    <div className="mt-2">
                      <div className="text-xs text-green-700 bg-green-50 p-2 rounded border border-green-200">
                        <strong>Linked CPE:</strong> {service.cpe_name}
                      </div>
                      <button
                        type="button"
                        onClick={() => { 
                          updateService(index, 'cpe_name', ''); 
                          updateService(index, 'cpe_name_id', ''); 
                        }}
                        className="mt-1 text-xs text-red-600 hover:underline"
                      >
                        Clear CPE link
                      </button>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </section>

          {/* Operating System */}
          <section>
            <h3 className="text-sm font-semibold text-gray-900 mb-3">Operating System</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Operating System</label>
                <input
                  type="text"
                  value={formData.operating_system}
                  onChange={(e) => updateField('operating_system', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g., Ubuntu Linux"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">OS Version</label>
                <input
                  type="text"
                  value={formData.os_version}
                  onChange={(e) => updateField('os_version', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g., 20.04 LTS"
                />
              </div>
            </div>

            {/* OS CPE Lookup */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                OS CPE Lookup {formData.os_cpe_name && <span className="text-green-600">✓ Matched</span>}
              </label>
              <CpeLookupInline

                onSelect={(cpe) => {
                  updateField('os_cpe_name', cpe.cpe_name);
                  if (!formData.operating_system && cpe.product) {
                    updateField('operating_system', `${cpe.vendor} ${cpe.product}`.trim());
                  }
                  if (!formData.os_version && cpe.version) {
                    updateField('os_version', cpe.version);
                  }
                }}
                placeholder="Search for operating system CPE..."
              />
              {formData.os_cpe_name && (
                <div className="mt-1 text-xs text-gray-600 bg-gray-50 p-2 rounded">
                  <strong>Matched OS CPE:</strong> {formData.os_cpe_name}
                </div>
              )}
            </div>
          </section>

          {/* Tags */}
          <section>
            <h3 className="text-sm font-semibold text-gray-900 mb-2">Tags</h3>
            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="Add a tag and press Enter"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addTag(); } }}
                className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
              />
              <button type="button" onClick={addTag} className="px-3 py-2 bg-gray-100 rounded hover:bg-gray-200">Add</button>
            </div>
            {tags.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-2">
                {tags.map(t => (
                  <span key={t} className="inline-flex items-center gap-2 text-sm bg-gray-100 px-2 py-1 rounded">
                    {t}
                    <button type="button" className="text-gray-500 hover:text-gray-700" onClick={() => removeTag(t)}>
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </section>

          {/* Environment */}
          <section>
            <h3 className="text-sm font-semibold text-gray-900 mb-2">Environment</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Environment</label>
                <select
                  value={formData.environment}
                  onChange={(e) => updateField('environment', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                >
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                  <option value="testing">Testing</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Criticality</label>
                <select
                  value={formData.criticality}
                  onChange={(e) => updateField('criticality', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Location</label>
                <input
                  type="text"
                  value={formData.location}
                  onChange={(e) => updateField('location', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g., Data Center A, Rack 15"
                />
              </div>
            </div>
          </section>

          {/* Footer actions */}
          <div className="flex items-center gap-3 pt-2">
            <button
              type="submit"
              disabled={submitting}
              className="flex-1 bg-blue-600 text-white py-3 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 font-medium"
            >
              {submitting ? 'Updating Asset...' : 'Update Asset'}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="flex-1 bg-gray-300 text-gray-700 py-3 px-4 rounded-md hover:bg-gray-400 font-medium"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default EditAssetModal;
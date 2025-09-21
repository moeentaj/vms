// Complete Fixed EditAssetModal.js - Properly structured with all sections
import React, { useState, useEffect } from 'react';
import { X, Search, Loader, Plus, Trash2, Loader2, AlertTriangle, Database } from 'lucide-react';
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
        className={`p-4 rounded-md shadow-md max-w-sm ${toast.type === 'error' ? 'bg-red-100 text-red-800' :
          toast.type === 'success' ? 'bg-green-100 text-green-800' :
            toast.type === 'warning' ? 'bg-yellow-100 text-yellow-800' :
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

// CPE Data Status Component
const CPEDataStatus = ({ onInitialize }) => (
  <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
    <div className="flex items-center space-x-2">
      <AlertTriangle className="h-5 w-5 text-yellow-600" />
      <div className="flex-1">
        <div className="text-sm font-medium text-yellow-800">CPE Database Not Available</div>
        <div className="text-sm text-yellow-700">
          CPE lookup requires database initialization. Asset editing will work without CPE lookup.
        </div>
      </div>
      <button
        onClick={onInitialize}
        className="bg-yellow-600 text-white px-3 py-1 rounded text-sm hover:bg-yellow-700"
      >
        Initialize
      </button>
    </div>
  </div>
);

// Fixed CPE Lookup Component with proper error handling and debouncing
const CpeLookupInline = ({ 
  onSelect, 
  buttonLabel = 'CPE Lookup', 
  placeholder = "Search CPE (e.g., 'nginx', 'postgres', 'tomcat')", 
  onCPEError 
}) => {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [cpeAvailable, setCpeAvailable] = useState(true);
  const [retryCount, setRetryCount] = useState(0);

  useEffect(() => {
    // Debounce the search to prevent too many requests
    const timeoutId = setTimeout(async () => {
      if (!open || !query.trim()) {
        setResults([]);
        return;
      }

      // Limit retry attempts to prevent infinite loops
      if (retryCount > 3) {
        setError('Too many failed attempts. Please try again later.');
        return;
      }

      setLoading(true);
      setError('');

      try {
        const data = await api.request('/assets/cpe-lookup', {
          method: 'POST',
          body: JSON.stringify({ query: query.trim(), limit: 12 })
        });
        
        setResults(Array.isArray(data) ? data : []);
        setCpeAvailable(true);
        setRetryCount(0); // Reset retry count on success
        if (onCPEError) onCPEError(null);
        
      } catch (error) {
        console.error('CPE lookup error:', error);
        setResults([]);
        
        if (error.message.includes('CPE data not available') || 
            error.message.includes('404') || 
            error.message.includes('CPE lookup failed')) {
          setCpeAvailable(false);
          setError('CPE database not initialized');
          if (onCPEError) onCPEError('CPE database not initialized');
        } else if (error.message.includes('500')) {
          setRetryCount(prev => prev + 1);
          setError('CPE service temporarily unavailable. Please try again.');
          if (onCPEError) onCPEError('CPE service temporarily unavailable');
        } else {
          setError('Search failed. Try again.');
          if (onCPEError) onCPEError('Search failed');
        }
      } finally {
        setLoading(false);
      }
    }, 500); // Increased debounce delay to reduce API calls

    return () => clearTimeout(timeoutId);
  }, [query, open, onCPEError, retryCount]);

  const handleLocalInitialize = async () => {
    try {
      await api.triggerCPEIngestion(true);
      alert('CPE database initialization started. This may take a few minutes.');
      setError('');
      setCpeAvailable(true);
      setRetryCount(0);
      if (onCPEError) onCPEError(null);
    } catch (err) {
      console.error('CPE initialization error:', err);
      setError('Failed to initialize CPE database');
      if (onCPEError) onCPEError('Failed to initialize CPE database');
    }
  };

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className={`w-full px-3 py-2 border rounded-md text-left text-sm ${cpeAvailable
          ? 'border-gray-300 hover:border-blue-500 focus:ring-2 focus:ring-blue-500'
          : 'border-yellow-300 bg-yellow-50'
          }`}
      >
        <div className="flex items-center justify-between">
          <span className={cpeAvailable ? 'text-gray-700' : 'text-yellow-700'}>
            {buttonLabel}
          </span>
          <div className="flex items-center space-x-1">
            {!cpeAvailable && <AlertTriangle className="h-4 w-4 text-yellow-600" />}
            <Search className="h-4 w-4 text-gray-400" />
          </div>
        </div>
      </button>

      {open && (
        <div className="absolute top-full left-0 right-0 mt-1 bg-white border border-gray-300 rounded-md shadow-lg z-50 max-h-64 overflow-y-auto">
          {!cpeAvailable ? (
            <div className="p-4 text-center">
              <AlertTriangle className="h-8 w-8 text-yellow-600 mx-auto mb-2" />
              <div className="text-sm text-gray-600 mb-3">CPE database not available</div>
              <button
                onClick={handleLocalInitialize}
                className="bg-blue-600 text-white px-3 py-1 rounded text-sm hover:bg-blue-700"
              >
                Initialize CPE Database
              </button>
            </div>
          ) : (
            <>
              <div className="p-2 border-b">
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={placeholder}
                  className="w-full px-2 py-1 text-sm border border-gray-300 rounded"
                  autoFocus
                />
              </div>
              <div className="max-h-48 overflow-y-auto">
                {loading && (
                  <div className="p-3 text-center">
                    <Loader className="animate-spin h-4 w-4 mx-auto" />
                  </div>
                )}
                {error && (
                  <div className="p-3 text-center text-red-600 text-sm">{error}</div>
                )}
                {!loading && !error && results.length === 0 && query && (
                  <div className="p-3 text-center text-gray-500 text-sm">
                    No results found. Try broader search terms.
                  </div>
                )}
                {results.map((r, i) => (
                  <button
                    key={i}
                    type="button"
                    onClick={() => {
                      onSelect(r);
                      setOpen(false);
                      setQuery('');
                    }}
                    className="w-full px-3 py-2 text-left hover:bg-gray-100 border-b border-gray-100"
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
            </>
          )}
        </div>
      )}
    </div>
  );
};

/**
 * Edit Asset Modal - Complete version with proper structure
 */
const EditAssetModal = ({ asset, onClose, onSuccess }) => {
  // Form state
  const [formData, setFormData] = useState({
    name: '',
    asset_type: 'server',
    ip_address: '',
    hostname: '',
    operating_system: '',
    os_version: '',
    os_cpe_name: '',
    environment: 'production',
    criticality: 'medium',
    location: '',
  });

  // Services and tags
  const [services, setServices] = useState([]);
  const [tags, setTags] = useState([]);
  const [tagInput, setTagInput] = useState('');

  // UI state
  const [submitting, setSubmitting] = useState(false);
  const [toasts, setToasts] = useState([]);
  const [showCPEStatus, setShowCPEStatus] = useState(false);
  const [cpeError, setCpeError] = useState(null);

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
      const servicesArray = [];

      // Add primary service if exists
      if (asset.primary_service) {
        servicesArray.push({
          name: asset.primary_service,
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
          servicesArray.push({
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

      // Ensure at least one service exists
      if (servicesArray.length === 0) {
        servicesArray.push({
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

      setServices(servicesArray);

      // Initialize tags
      if (asset.tags && Array.isArray(asset.tags)) {
        setTags(asset.tags);
      }
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

  // Handle CPE errors from child components
  const handleCPEError = (error) => {
    setCpeError(error);
    if (error) {
      setShowCPEStatus(true);
    }
  };

  // SINGLE CPE initialization handler
  const initializeCPE = async () => {
    try {
      await api.triggerCPEIngestion(true);
      addToast('CPE database initialization started. This may take a few minutes.', 'info');
      setCpeError(null);
      setShowCPEStatus(false);
    } catch (err) {
      console.error('CPE initialization error:', err);
      addToast('Failed to initialize CPE database', 'error');
      setCpeError('Failed to initialize CPE database');
    }
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
        name: formData.name,
        asset_type: formData.asset_type,
        ip_address: formData.ip_address || null,
        hostname: formData.hostname || null,
        primary_service: primary.name || null,
        service_vendor: primary.vendor || null,
        service_version: primary.version || null,
        cpe_name_id: primary.cpe_name_id || null,
        cpe_name: primary.cpe_name || null,
        additional_services: additional_services.length ? additional_services : null,
        operating_system: formData.operating_system || null,
        os_version: formData.os_version || null,
        os_cpe_name: formData.os_cpe_name || null,
        environment: formData.environment || 'production',
        criticality: formData.criticality || 'medium',
        location: formData.location || null,
        tags: tags.length ? tags : null,
      };

      await api.updateAsset(asset.id, payload);

      addToast('Asset updated successfully!', 'success');
      if (onSuccess) onSuccess();
      setTimeout(onClose, 1000);
    } catch (err) {
      console.error('Update asset failed:', err);
      const msg = typeof err?.message === 'string' && err.message.trim()
        ? err.message
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
    <div className="fixed inset-0 bg-gray-800 bg-opacity-75 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg max-w-4xl w-full m-4 max-h-[90vh] overflow-y-auto">
        <div className="sticky top-0 bg-white border-b px-6 py-4 flex justify-between items-center">
          <h2 className="text-xl font-semibold">Edit Asset: {asset?.name}</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
            <X className="h-6 w-6" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-6">
          {/* CPE Status Warning */}
          {(showCPEStatus || cpeError) && (
            <CPEDataStatus onInitialize={initializeCPE} />
          )}

          {/* Basic Information */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Asset Name *</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => updateField('name', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Asset Type</label>
              <select
                value={formData.asset_type}
                onChange={(e) => updateField('asset_type', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
              >
                <option value="server">Server</option>
                <option value="workstation">Workstation</option>
                <option value="laptop">Laptop</option>
                <option value="network_device">Network Device</option>
                <option value="mobile_device">Mobile Device</option>
                <option value="iot_device">IoT Device</option>
                <option value="virtual_machine">Virtual Machine</option>
                <option value="container">Container</option>
                <option value="other">Other</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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

          {/* Services Section */}
          <div className="border-t pt-6">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-medium">Services</h3>
              <button
                type="button"
                onClick={addService}
                className="bg-blue-600 text-white px-3 py-1 rounded text-sm hover:bg-blue-700 flex items-center space-x-1"
              >
                <Plus className="h-4 w-4" />
                <span>Add Service</span>
              </button>
            </div>

            {services.map((service, index) => (
              <div key={index} className="border border-gray-200 rounded-lg p-4 mb-4">
                <div className="flex justify-between items-start mb-3">
                  <div className="flex items-center space-x-2">
                    <input
                      type="radio"
                      name="primary_service"
                      checked={service.is_primary}
                      onChange={() => setPrimary(index)}
                      className="text-blue-600"
                    />
                    <label className="text-sm font-medium text-gray-700">
                      {service.is_primary ? 'Primary Service' : 'Additional Service'}
                    </label>
                  </div>
                  {services.length > 1 && (
                    <button
                      type="button"
                      onClick={() => removeService(index)}
                      className="text-red-600 hover:text-red-800"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Service Name</label>
                    <input
                      type="text"
                      value={service.name}
                      onChange={(e) => updateService(index, 'name', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                      placeholder="e.g., nginx, mysql, ssh"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Vendor</label>
                    <input
                      type="text"
                      value={service.vendor}
                      onChange={(e) => updateService(index, 'vendor', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                      placeholder="e.g., nginx, oracle"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Version</label>
                    <input
                      type="text"
                      value={service.version}
                      onChange={(e) => updateService(index, 'version', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                      placeholder="e.g., 1.20.2, 8.0.33"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-3">
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

                {/* CPE Lookup for this service */}
                <div className="mt-3">
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
                    onCPEError={handleCPEError}
                  />
                  {service.cpe_name && (
                    <div className="mt-2 text-xs text-gray-600 bg-gray-50 px-2 py-1 rounded">
                      Selected CPE: {service.cpe_name}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* Operating System */}
          <div className="border-t pt-6">
            <h3 className="text-lg font-medium mb-4">Operating System</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Operating System</label>
                <input
                  type="text"
                  value={formData.operating_system}
                  onChange={(e) => updateField('operating_system', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g., Ubuntu, Windows Server, CentOS"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">OS Version</label>
                <input
                  type="text"
                  value={formData.os_version}
                  onChange={(e) => updateField('os_version', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g., 20.04, 2019, 7.9"
                />
              </div>
            </div>

            {/* OS CPE Lookup */}
            <div className="mb-4">
              <CpeLookupInline
                onSelect={(cpe) => {
                  updateField('os_cpe_name', cpe.cpe_name);
                  if (!formData.operating_system) updateField('operating_system', cpe.product || '');
                  if (!formData.os_version && cpe.version) updateField('os_version', cpe.version || '');
                }}
                buttonLabel="CPE Lookup for Operating System"
                placeholder="Search OS CPE (e.g., 'ubuntu', 'windows', 'centos')..."
                onCPEError={handleCPEError}
              />
              {formData.os_cpe_name && (
                <div className="mt-2 text-xs text-gray-600 bg-gray-50 px-2 py-1 rounded">
                  Selected OS CPE: {formData.os_cpe_name}
                </div>
              )}
            </div>
          </div>

          {/* Environment and Context */}
          <div className="border-t pt-6">
            <h3 className="text-lg font-medium mb-4">Environment & Context</h3>
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
                  <option value="qa">QA</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Criticality</label>
                <select
                  value={formData.criticality}
                  onChange={(e) => updateField('criticality', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Location</label>
                <input
                  type="text"
                  value={formData.location}
                  onChange={(e) => updateField('location', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g., Data Center 1, AWS us-east-1"
                />
              </div>
            </div>
          </div>

          {/* Tags */}
          <div className="border-t pt-6">
            <h3 className="text-lg font-medium mb-4">Tags</h3>
            <div className="flex flex-wrap gap-2 mb-3">
              {tags.map((tag) => (
                <span
                  key={tag}
                  className="bg-blue-100 text-blue-800 px-3 py-1 rounded-full text-sm flex items-center space-x-1"
                >
                  <span>{tag}</span>
                  <button
                    type="button"
                    onClick={() => removeTag(tag)}
                    className="text-blue-600 hover:text-blue-800"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </span>
              ))}
            </div>
            <div className="flex space-x-2">
              <input
                type="text"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addTag())}
                className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                placeholder="Add a tag..."
              />
              <button
                type="button"
                onClick={addTag}
                className="bg-gray-600 text-white px-4 py-2 rounded-md hover:bg-gray-700"
              >
                Add
              </button>
            </div>
          </div>

          {/* Form Actions */}
          <div className="border-t pt-6 flex justify-end space-x-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 flex items-center space-x-2"
            >
              {submitting && <Loader2 className="animate-spin h-4 w-4" />}
              <span>{submitting ? 'Updating...' : 'Update Asset'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Loading Modal */}
      <LoadingModal
        open={submitting}
        title="Updating Asset"
        subtitle="Please wait while we update the asset..."
      />

      {/* Toast Notifications */}
      <ToastStack toasts={toasts} remove={removeToast} />
    </div>
  );
};

export default EditAssetModal;
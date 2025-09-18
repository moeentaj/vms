import React, { useState, useEffect } from 'react';
import { Search, Plus, X, Loader2, Star } from 'lucide-react';

/* -----------------------------------------------------------
 * Toasts (lightweight, no external lib)
 * ---------------------------------------------------------*/
const Toast = ({ id, type = 'info', message, onClose }) => {
  const base =
    'pointer-events-auto flex items-start gap-3 w-full max-w-sm rounded-md shadow-lg border p-3 bg-white';
  const ring =
    type === 'error'
      ? 'border-red-200'
      : type === 'success'
      ? 'border-green-200'
      : 'border-gray-200';
  const accent =
    type === 'error'
      ? 'text-red-700'
      : type === 'success'
      ? 'text-green-700'
      : 'text-gray-700';

  return (
    <div className={`${base} ${ring}`}>
      <div className={`text-sm ${accent} leading-5 flex-1 whitespace-pre-wrap`}>
        {message}
      </div>
      <button
        type="button"
        onClick={() => onClose(id)}
        className="text-gray-400 hover:text-gray-600"
        aria-label="Dismiss"
        title="Dismiss"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
};

const ToastStack = ({ toasts, remove }) => {
  return (
    <div className="fixed z-[110] top-4 right-4 flex flex-col gap-2 pointer-events-none">
      {toasts.map(t => (
        <Toast key={t.id} {...t} onClose={remove} />
      ))}
    </div>
  );
};

/**
 * Loading modal (blocking overlay) used during long-running API calls
 */
const LoadingModal = ({ open, title = 'Working...', subtitle = 'Please wait while we process your request.' }) => {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center">
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" />
      <div className="relative bg-white rounded-lg shadow-xl w-full max-w-md p-6">
        <div className="flex items-center gap-3">
          <Loader2 className="h-6 w-6 animate-spin text-blue-600" />
          <div>
            <div className="font-semibold text-gray-900">{title}</div>
            <div className="text-sm text-gray-600">{subtitle}</div>
          </div>
        </div>
      </div>
    </div>
  );
};

/**
 * Reusable inline CPE Lookup widget.
 * Props:
 *  - onSelect: (cpe) => void
 *  - buttonLabel?: string
 *  - placeholder?: string
 */
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
        </div>
      )}
    </div>
  );
};

/**
 * Main Create Asset Modal (refactored)
 * - Single unified `services` array with a "primary" flag
 * - Per-service CPE lookup
 * - Optional OS CPE lookup
 * - Loading modal while creating the asset
 * - Toasts instead of alert()
 */
const CreateAssetModal = ({ onClose, onSuccess }) => {
  // Base form
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

  // Services (unified)
  const [services, setServices] = useState([
    {
      name: '',
      vendor: '',
      version: '',
      ports: [],
      detection_method: 'manual',
      cpe_name: '',
      cpe_name_id: '',
      is_primary: true,
    }
  ]);

  // Tags
  const [tags, setTags] = useState([]);
  const [tagInput, setTagInput] = useState('');

  // Loading and toasts
  const [submitting, setSubmitting] = useState(false);
  const [toasts, setToasts] = useState([]);

  // Toast helpers
  const removeToast = (id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  };
  const addToast = (message, type = 'info', ttlMs = 4000) => {
    const id = `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    setToasts(prev => [...prev, { id, message, type }]);
    window.setTimeout(() => removeToast(id), ttlMs);
  };

  // --- helpers
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
        is_primary: prev.length === 0, // first service primary if none
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

    // Validate name + at least one service entry (even if manual)
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
        // base
        name: formData.name,
        asset_type: formData.asset_type,
        ip_address: formData.ip_address || null,
        hostname: formData.hostname || null,

        // primary service mapped to top-level
        primary_service: primary.name || null,
        service_vendor: primary.vendor || null,
        service_version: primary.version || null,
        cpe_name_id: primary.cpe_name_id || null,
        cpe_name: primary.cpe_name || null,

        // additional services
        additional_services: additional_services.length ? additional_services : null,

        // OS
        operating_system: formData.operating_system || null,
        os_version: formData.os_version || null,
        os_cpe_name: formData.os_cpe_name || null,

        // context
        environment: formData.environment || 'production',
        criticality: formData.criticality || 'medium',
        location: formData.location || null,

        // tags
        tags: tags.length ? tags : null,

        // keep UI parity with backend defaults
        status: 'active',
        is_monitored: true
      };

      const resp = await fetch('/api/v1/assets', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify(payload)
      });

      if (!resp.ok) {
        const text = await resp.text();
        // Bubble up API-provided error if available
        throw new Error(text || `Failed to create asset (HTTP ${resp.status})`);
      }

      // success
      if (onSuccess) onSuccess();
      onClose();
    } catch (err) {
      console.error('Create asset failed:', err);
      const msg =
        typeof err?.message === 'string' && err.message.trim()
          ? err.message.trim().slice(0, 400)
          : 'Failed to create asset. Please try again.';
      addToast(msg, 'error');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50">
      <LoadingModal open={submitting} title="Creating asset..." subtitle="Calling the API and saving your asset." />
      <ToastStack toasts={toasts} remove={removeToast} />

      <div className="bg-white rounded-lg p-6 w-full max-w-5xl max-h-[90vh] overflow-y-auto relative">
        <button
          type="button"
          className="absolute top-4 right-4 text-gray-500 hover:text-gray-700"
          onClick={onClose}
        >
          <X className="h-5 w-5" />
        </button>

        <h2 className="text-xl font-semibold mb-4">Create Asset</h2>

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
                  <option value="service">Service</option>
                  <option value="application">Application</option>
                  <option value="network_device">Network Device</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">IP Address</label>
                <input
                  type="text"
                  value={formData.ip_address}
                  onChange={(e) => updateField('ip_address', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Hostname</label>
                <input
                  type="text"
                  value={formData.hostname}
                  onChange={(e) => updateField('hostname', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>
          </section>

          {/* Operating System */}
          <section>
            <h3 className="text-sm font-semibold text-gray-900 mb-3">Operating System</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">OS Name</label>
                <input
                  type="text"
                  value={formData.operating_system}
                  onChange={(e) => updateField('operating_system', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">OS Version</label>
                <input
                  type="text"
                  value={formData.os_version}
                  onChange={(e) => updateField('os_version', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">OS CPE (optional)</label>
                <div className="space-y-1">
                  {formData.os_cpe_name && (
                    <div className="text-xs text-green-700 bg-green-50 border border-green-200 rounded px-2 py-1 flex items-center justify-between">
                      <span className="truncate"><span className="font-medium">CPE:</span> {formData.os_cpe_name}</span>
                      <button
                        type="button"
                        onClick={() => updateField('os_cpe_name', '')}
                        className="ml-2 text-green-700 hover:underline"
                      >
                        Clear
                      </button>
                    </div>
                  )}
                  <CpeLookupInline
                    buttonLabel="OS CPE Lookup"
                    placeholder="Search OS CPE (e.g., 'windows 10', 'ubuntu 22.04')"
                    onSelect={(cpe) => {
                      updateField('os_cpe_name', cpe.cpe_name);
                      if (!formData.operating_system) updateField('operating_system', cpe.product || '');
                      if (!formData.os_version && cpe.version) updateField('os_version', cpe.version || '');
                    }}
                  />
                </div>
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
                className="inline-flex items-center gap-2 bg-gray-100 text-gray-700 px-3 py-1.5 rounded-md hover:bg-gray-200"
              >
                <Plus className="h-4 w-4" /> Add Service
              </button>
            </div>

            <div className="space-y-4">
              {services.map((s, idx) => (
                <div key={idx} className="p-4 bg-gray-50 rounded-lg border border-gray-200 relative">
                  <button
                    type="button"
                    onClick={() => removeService(idx)}
                    className="absolute top-2 right-2 text-red-500 hover:text-red-700"
                    aria-label="Remove service"
                    title="Remove service"
                  >
                    <X className="h-4 w-4" />
                  </button>

                  <div className="flex items-center gap-2 mb-3">
                    <button
                      type="button"
                      onClick={() => setPrimary(idx)}
                      className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs border ${s.is_primary ? 'bg-yellow-50 border-yellow-300 text-yellow-700' : 'bg-white border-gray-300 text-gray-600 hover:bg-gray-50'}`}
                      title="Set as primary"
                    >
                      <Star className={`h-3.5 w-3.5 ${s.is_primary ? 'fill-yellow-400 text-yellow-400' : ''}`} />
                      {s.is_primary ? 'Primary Service' : 'Set Primary'}
                    </button>

                    {s.cpe_name && (
                      <div className="ml-2 text-xs text-green-700 bg-green-50 border border-green-200 rounded px-2 py-1">
                        <span className="font-medium">CPE:</span> {s.cpe_name}
                      </div>
                    )}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Service Name</label>
                      <input
                        type="text"
                        value={s.name}
                        onChange={(e) => updateService(idx, 'name', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Vendor</label>
                      <input
                        type="text"
                        value={s.vendor}
                        onChange={(e) => updateService(idx, 'vendor', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Version</label>
                      <input
                        type="text"
                        value={s.version}
                        onChange={(e) => updateService(idx, 'version', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Ports (comma-separated)</label>
                      <input
                        type="text"
                        value={(s.ports || []).join(',')}
                        onChange={(e) => {
                          const raw = e.target.value;
                          const ports = raw.split(',').map(p => p.trim()).filter(Boolean);
                          updateService(idx, 'ports', ports);
                        }}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                  </div>

                  <div className="mt-2">
                    <CpeLookupInline
                      onSelect={(cpe) => {
                        updateService(idx, 'cpe_name_id', cpe.cpe_name_id);
                        updateService(idx, 'cpe_name', cpe.cpe_name);
                        if (!s.name) updateService(idx, 'name', cpe.product || '');
                        if (!s.vendor) updateService(idx, 'vendor', cpe.vendor || '');
                        if (!s.version && cpe.version) updateService(idx, 'version', cpe.version || '');
                      }}
                    />
                    {s.cpe_name && (
                      <button
                        type="button"
                        onClick={() => { updateService(idx, 'cpe_name', ''); updateService(idx, 'cpe_name_id', ''); }}
                        className="mt-2 text-xs text-green-700 hover:underline"
                      >
                        Clear CPE link
                      </button>
                    )}
                  </div>
                </div>
              ))}
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
                  <option value="test">Test</option>
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
              {submitting ? 'Creating Asset...' : 'Create Asset'}
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

export default CreateAssetModal;

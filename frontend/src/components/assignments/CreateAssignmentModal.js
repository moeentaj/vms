// Fixed CreateAssignmentModal.js with proper form handling and error management
import React, { useState, useEffect } from 'react';
import { X, AlertCircle, CheckCircle, User, Calendar, Flag } from 'lucide-react';
import { api } from '../../services/api';

const CreateAssignmentModal = ({ users = [], cves = [], onClose, onSuccess }) => {
  const [formData, setFormData] = useState({
    cve_id: '',
    assignee_id: '',
    title: '',
    description: '',
    priority: 'medium',
    due_date: ''
  });
  
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});
  const [toast, setToast] = useState(null);

  // Auto-generate title when CVE is selected
  useEffect(() => {
    if (formData.cve_id && !formData.title) {
      const selectedCVE = cves.find(cve => cve.cve_id === formData.cve_id);
      if (selectedCVE) {
        setFormData(prev => ({
          ...prev,
          title: `Investigate ${selectedCVE.cve_id} - ${selectedCVE.severity || 'Unknown'} Severity`,
          description: `Analyze and remediate vulnerability: ${selectedCVE.description?.substring(0, 200)}...`
        }));
      }
    }
  }, [formData.cve_id, cves, formData.title]);

  const validateForm = () => {
    const newErrors = {};

    if (!formData.cve_id) {
      newErrors.cve_id = 'CVE selection is required';
    }

    if (!formData.assignee_id) {
      newErrors.assignee_id = 'Assignee selection is required';
    }

    if (!formData.title.trim()) {
      newErrors.title = 'Title is required';
    }

    if (!formData.description.trim()) {
      newErrors.description = 'Description is required';
    }

    if (formData.due_date) {
      const dueDate = new Date(formData.due_date);
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      
      if (dueDate < today) {
        newErrors.due_date = 'Due date cannot be in the past';
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      setToast({
        message: 'Please fix the errors below',
        type: 'error'
      });
      return;
    }

    setLoading(true);
    setErrors({});

    try {
      const submissionData = {
        ...formData,
        assignee_id: parseInt(formData.assignee_id),
        due_date: formData.due_date || null
      };

      console.log('Submitting assignment data:', submissionData);
      
      const result = await api.createAssignment(submissionData);
      
      console.log('Assignment created successfully:', result);
      
      setToast({
        message: 'Assignment created successfully!',
        type: 'success'
      });

      // Close modal after short delay to show success message
      setTimeout(() => {
        onSuccess();
      }, 1000);

    } catch (error) {
      console.error('Failed to create assignment:', error);
      
      setToast({
        message: `Failed to create assignment: ${error.message}`,
        type: 'error'
      });

      // Handle specific validation errors from API
      if (error.message.includes('validation') || error.message.includes('required')) {
        setErrors({
          general: error.message
        });
      }
    } finally {
      setLoading(false);
    }
  };

  const handleFieldChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    
    // Clear field-specific error when user starts typing
    if (errors[field]) {
      setErrors(prev => {
        const newErrors = { ...prev };
        delete newErrors[field];
        return newErrors;
      });
    }
  };

  // Generate default due date (7 days from now)
  const getDefaultDueDate = () => {
    const date = new Date();
    date.setDate(date.getDate() + 7);
    return date.toISOString().split('T')[0];
  };

  const getPriorityColor = (priority) => {
    const colors = {
      low: 'bg-green-100 text-green-800 border-green-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      high: 'bg-orange-100 text-orange-800 border-orange-200',
      critical: 'bg-red-100 text-red-800 border-red-200'
    };
    return colors[priority] || colors.medium;
  };

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg w-full max-w-2xl max-h-[90vh] overflow-hidden">
        {/* Toast Notification */}
        {toast && (
          <div className={`absolute top-4 right-4 z-10 border-l-4 p-4 rounded shadow-lg ${
            toast.type === 'success' ? 'bg-green-100 border-green-400 text-green-700' :
            toast.type === 'error' ? 'bg-red-100 border-red-400 text-red-700' :
            'bg-blue-100 border-blue-400 text-blue-700'
          }`}>
            <div className="flex items-center">
              {toast.type === 'success' ? (
                <CheckCircle className="h-5 w-5 mr-2" />
              ) : (
                <AlertCircle className="h-5 w-5 mr-2" />
              )}
              <span>{toast.message}</span>
              <button 
                onClick={() => setToast(null)}
                className="ml-2 text-gray-500 hover:text-gray-700"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        {/* Modal Header */}
        <div className="px-6 py-4 border-b bg-gray-50">
          <div className="flex justify-between items-center">
            <div>
              <h3 className="text-lg font-semibold text-gray-900">Create Vulnerability Assignment</h3>
              <p className="text-sm text-gray-600">Assign a CVE for investigation and remediation</p>
            </div>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600"
              disabled={loading}
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="overflow-y-auto max-h-[calc(90vh-140px)]">
          <form onSubmit={handleSubmit} className="p-6 space-y-6">
            {/* General Error */}
            {errors.general && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <div className="flex items-center">
                  <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
                  <span className="text-red-800">{errors.general}</span>
                </div>
              </div>
            )}

            {/* CVE Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                <Flag className="inline h-4 w-4 mr-1" />
                CVE *
              </label>
              <select
                value={formData.cve_id}
                onChange={(e) => handleFieldChange('cve_id', e.target.value)}
                className={`w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                  errors.cve_id ? 'border-red-300' : 'border-gray-300'
                }`}
                disabled={loading}
              >
                <option value="">Select a CVE...</option>
                {cves.map((cve) => (
                  <option key={cve.cve_id} value={cve.cve_id}>
                    {cve.cve_id} - {cve.severity || 'Unknown'} - {cve.description?.substring(0, 60)}...
                  </option>
                ))}
              </select>
              {errors.cve_id && (
                <p className="mt-1 text-sm text-red-600">{errors.cve_id}</p>
              )}
            </div>

            {/* Assignee Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                <User className="inline h-4 w-4 mr-1" />
                Assignee *
              </label>
              <select
                value={formData.assignee_id}
                onChange={(e) => handleFieldChange('assignee_id', e.target.value)}
                className={`w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                  errors.assignee_id ? 'border-red-300' : 'border-gray-300'
                }`}
                disabled={loading}
              >
                <option value="">Select an assignee...</option>
                {users.map((user) => (
                  <option key={user.id} value={user.id}>
                    {user.first_name && user.last_name 
                      ? `${user.first_name} ${user.last_name} (${user.username})`
                      : user.username
                    } - {user.role}
                  </option>
                ))}
              </select>
              {errors.assignee_id && (
                <p className="mt-1 text-sm text-red-600">{errors.assignee_id}</p>
              )}
            </div>

            {/* Title */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Assignment Title *
              </label>
              <input
                type="text"
                value={formData.title}
                onChange={(e) => handleFieldChange('title', e.target.value)}
                placeholder="Enter assignment title..."
                className={`w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                  errors.title ? 'border-red-300' : 'border-gray-300'
                }`}
                disabled={loading}
              />
              {errors.title && (
                <p className="mt-1 text-sm text-red-600">{errors.title}</p>
              )}
            </div>

            {/* Description */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Description *
              </label>
              <textarea
                value={formData.description}
                onChange={(e) => handleFieldChange('description', e.target.value)}
                placeholder="Describe the assignment details and expected outcomes..."
                rows={4}
                className={`w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                  errors.description ? 'border-red-300' : 'border-gray-300'
                }`}
                disabled={loading}
              />
              {errors.description && (
                <p className="mt-1 text-sm text-red-600">{errors.description}</p>
              )}
            </div>

            {/* Priority and Due Date Row */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Priority */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Priority
                </label>
                <select
                  value={formData.priority}
                  onChange={(e) => handleFieldChange('priority', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  disabled={loading}
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
                <div className="mt-1">
                  <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getPriorityColor(formData.priority)}`}>
                    {formData.priority.charAt(0).toUpperCase() + formData.priority.slice(1)} Priority
                  </span>
                </div>
              </div>

              {/* Due Date */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  <Calendar className="inline h-4 w-4 mr-1" />
                  Due Date
                </label>
                <input
                  type="date"
                  value={formData.due_date}
                  onChange={(e) => handleFieldChange('due_date', e.target.value)}
                  min={new Date().toISOString().split('T')[0]}
                  className={`w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                    errors.due_date ? 'border-red-300' : 'border-gray-300'
                  }`}
                  disabled={loading}
                />
                {errors.due_date && (
                  <p className="mt-1 text-sm text-red-600">{errors.due_date}</p>
                )}
                <button
                  type="button"
                  onClick={() => handleFieldChange('due_date', getDefaultDueDate())}
                  className="mt-1 text-xs text-blue-600 hover:text-blue-800"
                  disabled={loading}
                >
                  Set default (7 days)
                </button>
              </div>
            </div>

            {/* Assignment Preview */}
            {formData.cve_id && formData.assignee_id && (
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <h4 className="text-sm font-medium text-blue-900 mb-2">Assignment Preview</h4>
                <div className="text-sm text-blue-800 space-y-1">
                  <p><strong>CVE:</strong> {formData.cve_id}</p>
                  <p><strong>Assignee:</strong> {users.find(u => u.id.toString() === formData.assignee_id)?.username}</p>
                  <p><strong>Priority:</strong> {formData.priority}</p>
                  {formData.due_date && (
                    <p><strong>Due:</strong> {new Date(formData.due_date).toLocaleDateString()}</p>
                  )}
                </div>
              </div>
            )}
          </form>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t bg-gray-50 flex justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            disabled={loading}
            className="px-4 py-2 text-gray-700 bg-gray-200 rounded-lg hover:bg-gray-300 disabled:opacity-50 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={loading || !formData.cve_id || !formData.assignee_id}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 transition-colors"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                Creating...
              </>
            ) : (
              'Create Assignment'
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default CreateAssignmentModal;
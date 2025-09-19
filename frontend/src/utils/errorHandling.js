// Enhanced Error Handling System
// frontend/src/utils/errorHandling.js

import React, { Component } from 'react';
import { AlertTriangle, RefreshCw, Home, Bug } from 'lucide-react';
import { useState, useEffect } from 'react';

// Centralized Error Handler Class
export class ErrorHandler {
  static instance = null;

  static getInstance() {
    if (!ErrorHandler.instance) {
      ErrorHandler.instance = new ErrorHandler();
    }
    return ErrorHandler.instance;
  }

  constructor() {
    this.errorListeners = [];
    this.setupGlobalErrorHandling();
  }

  setupGlobalErrorHandling() {
    // Handle uncaught JavaScript errors
    window.addEventListener('error', (event) => {
      this.handleError({
        message: event.error?.message || 'An unexpected error occurred',
        stack: event.error?.stack,
        type: 'javascript_error',
        fatal: true
      });
    });

    // Handle unhandled promise rejections
    window.addEventListener('unhandledrejection', (event) => {
      this.handleError({
        message: event.reason?.message || 'An unexpected promise rejection occurred',
        stack: event.reason?.stack,
        type: 'promise_rejection',
        fatal: false
      });
    });
  }

  handleError(error) {
    console.error('Error handled by ErrorHandler:', error);

    // Notify all error listeners
    this.errorListeners.forEach(listener => {
      try {
        listener(error);
      } catch (e) {
        console.error('Error in error listener:', e);
      }
    });
  }

  addErrorListener(listener) {
    this.errorListeners.push(listener);
  }

  removeErrorListener(listener) {
    this.errorListeners = this.errorListeners.filter(l => l !== listener);
  }

  // API Error handling with user-friendly messages
  static formatApiError(error) {
    if (!error) return 'An unknown error occurred';

    // Handle different types of errors
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      return 'Network connection error. Please check your internet connection.';
    }

    if (error.status) {
      switch (error.status) {
        case 400:
          return `Bad request: ${error.message || 'Invalid data provided'}`;
        case 401:
          return 'Authentication required. Please log in again.';
        case 403:
          return 'Access denied. You don\'t have permission for this action.';
        case 404:
          return 'Resource not found. It may have been deleted or moved.';
        case 429:
          return 'Too many requests. Please wait a moment and try again.';
        case 500:
          return 'Server error. Please try again later or contact support.';
        case 502:
        case 503:
        case 504:
          return 'Service temporarily unavailable. Please try again later.';
        default:
          return `Server error (${error.status}): ${error.message || 'Unknown error'}`;
      }
    }

    return error.message || 'An unexpected error occurred';
  }

  // Retry mechanism for failed requests
  static async retryRequest(requestFn, maxRetries = 3, delay = 1000) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await requestFn();
      } catch (error) {
        if (attempt === maxRetries) {
          throw error;
        }

        // Exponential backoff
        await new Promise(resolve => setTimeout(resolve, delay * Math.pow(2, attempt - 1)));
      }
    }
  }
}

// Enhanced Error Boundary Component
export class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: null
    };
  }

  static getDerivedStateFromError(error) {
    return {
      hasError: true,
      errorId: Date.now().toString(36) + Math.random().toString(36).substr(2)
    };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({
      error,
      errorInfo
    });

    // Log error to console in development
    if (process.env.NODE_ENV === 'development') {
      console.error('ErrorBoundary caught an error:', error, errorInfo);
    }

    // Report error to error handling service
    ErrorHandler.getInstance().handleError({
      message: error.message,
      stack: error.stack,
      componentStack: errorInfo.componentStack,
      type: 'react_error',
      fatal: true,
      errorId: this.state.errorId
    });
  }

  handleRetry = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: null
    });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback(this.state.error, this.handleRetry);
      }

      return (
        <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
          <div className="sm:mx-auto sm:w-full sm:max-w-md">
            <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
              <div className="text-center">
                <AlertTriangle className="mx-auto h-12 w-12 text-red-500" />
                <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
                  Something went wrong
                </h2>
                <p className="mt-2 text-center text-sm text-gray-600">
                  We're sorry, but something unexpected happened.
                </p>

                {process.env.NODE_ENV === 'development' && this.state.error && (
                  <details className="mt-4 text-left">
                    <summary className="cursor-pointer text-sm text-gray-500 hover:text-gray-700">
                      <Bug className="inline h-4 w-4 mr-1" />
                      Error Details (Development)
                    </summary>
                    <div className="mt-2 p-3 bg-gray-100 rounded text-xs font-mono text-gray-800 overflow-auto max-h-32">
                      <div className="mb-2">
                        <strong>Error:</strong> {this.state.error.message}
                      </div>
                      <div className="mb-2">
                        <strong>Stack:</strong>
                        <pre className="whitespace-pre-wrap">{this.state.error.stack}</pre>
                      </div>
                      {this.state.errorInfo && (
                        <div>
                          <strong>Component Stack:</strong>
                          <pre className="whitespace-pre-wrap">{this.state.errorInfo.componentStack}</pre>
                        </div>
                      )}
                    </div>
                  </details>
                )}

                <div className="mt-6 flex flex-col sm:flex-row gap-3">
                  <button
                    onClick={this.handleRetry}
                    className="flex-1 flex justify-center items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                  >
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Try Again
                  </button>
                  <button
                    onClick={() => window.location.href = '/'}
                    className="flex-1 flex justify-center items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                  >
                    <Home className="h-4 w-4 mr-2" />
                    Go Home
                  </button>
                </div>

                {this.state.errorId && (
                  <p className="mt-4 text-xs text-gray-400">
                    Error ID: {this.state.errorId}
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Toast Notification System
export class ToastManager {
  static instance = null;

  static getInstance() {
    if (!ToastManager.instance) {
      ToastManager.instance = new ToastManager();
    }
    return ToastManager.instance;
  }

  constructor() {
    this.toasts = [];
    this.listeners = [];
  }

  addToast(message, type = 'info', duration = 5000, actions = null) {
    const toast = {
      id: Date.now() + Math.random(),
      message,
      type,
      duration,
      actions,
      timestamp: Date.now()
    };

    this.toasts.push(toast);
    this.notifyListeners();

    // Auto remove toast after duration
    if (duration > 0) {
      setTimeout(() => {
        this.removeToast(toast.id);
      }, duration);
    }

    return toast.id;
  }

  removeToast(id) {
    this.toasts = this.toasts.filter(toast => toast.id !== id);
    this.notifyListeners();
  }

  clearAll() {
    this.toasts = [];
    this.notifyListeners();
  }

  addListener(listener) {
    this.listeners.push(listener);
  }

  removeListener(listener) {
    this.listeners = this.listeners.filter(l => l !== listener);
  }

  notifyListeners() {
    this.listeners.forEach(listener => {
      try {
        listener(this.toasts);
      } catch (e) {
        console.error('Error in toast listener:', e);
      }
    });
  }

  // Convenience methods
  success(message, duration, actions) {
    return this.addToast(message, 'success', duration, actions);
  }

  error(message, duration, actions) {
    return this.addToast(message, 'error', duration, actions);
  }

  warning(message, duration, actions) {
    return this.addToast(message, 'warning', duration, actions);
  }

  info(message, duration, actions) {
    return this.addToast(message, 'info', duration, actions);
  }
}

export const useToasts = () => {
  const [toasts, setToasts] = useState([]);
  const toastManager = ToastManager.getInstance();

  useEffect(() => {
    const updateToasts = (newToasts) => {
      setToasts([...newToasts]);
    };

    toastManager.addListener(updateToasts);

    return () => {
      toastManager.removeListener(updateToasts);
    };
  }, [toastManager]);

  return {
    toasts,
    addToast: toastManager.addToast.bind(toastManager),
    removeToast: toastManager.removeToast.bind(toastManager),
    clearAll: toastManager.clearAll.bind(toastManager),
    success: toastManager.success.bind(toastManager),
    error: toastManager.error.bind(toastManager),
    warning: toastManager.warning.bind(toastManager),
    info: toastManager.info.bind(toastManager)
  };
};

// Enhanced API Error Handler
export const handleApiError = (error, showToast = true) => {
  const formattedError = ErrorHandler.formatApiError(error);

  if (showToast) {
    ToastManager.getInstance().error(formattedError);
  }

  // Handle specific error types
  if (error.status === 401) {
    // Redirect to login
    localStorage.removeItem('token');
    window.location.href = '/login';
  }

  return formattedError;
};

// Loading State Manager
export class LoadingManager {
  static instance = null;

  static getInstance() {
    if (!LoadingManager.instance) {
      LoadingManager.instance = new LoadingManager();
    }
    return LoadingManager.instance;
  }

  constructor() {
    this.loadingStates = new Map();
    this.listeners = [];
  }

  setLoading(key, isLoading, message = null) {
    if (isLoading) {
      this.loadingStates.set(key, { isLoading: true, message, startTime: Date.now() });
    } else {
      this.loadingStates.delete(key);
    }
    this.notifyListeners();
  }

  isLoading(key) {
    return this.loadingStates.has(key);
  }

  getLoadingState(key) {
    return this.loadingStates.get(key);
  }

  getAllLoadingStates() {
    return Array.from(this.loadingStates.entries()).map(([key, state]) => ({
      key,
      ...state
    }));
  }

  addListener(listener) {
    this.listeners.push(listener);
  }

  removeListener(listener) {
    this.listeners = this.listeners.filter(l => l !== listener);
  }

  notifyListeners() {
    const loadingStates = this.getAllLoadingStates();
    this.listeners.forEach(listener => {
      try {
        listener(loadingStates);
      } catch (e) {
        console.error('Error in loading listener:', e);
      }
    });
  }
}

// React Hook for Loading States
export const useLoading = () => {
  const [loadingStates, setLoadingStates] = useState([]);
  const loadingManager = LoadingManager.getInstance();

  useEffect(() => {
    const updateLoadingStates = (states) => {
      setLoadingStates(states);
    };

    loadingManager.addListener(updateLoadingStates);

    return () => {
      loadingManager.removeListener(updateLoadingStates);
    };
  }, [loadingManager]);

  return {
    loadingStates,
    setLoading: loadingManager.setLoading.bind(loadingManager),
    isLoading: loadingManager.isLoading.bind(loadingManager),
    getLoadingState: loadingManager.getLoadingState.bind(loadingManager)
  };
};

// Enhanced API wrapper with error handling and retry logic
export const apiWithErrorHandling = {
  async request(url, options = {}) {
    const loadingKey = `api_${url}_${Date.now()}`;
    const loadingManager = LoadingManager.getInstance();

    try {
      loadingManager.setLoading(loadingKey, true, `Loading ${url}...`);

      const result = await ErrorHandler.retryRequest(async () => {
        return await fetch(url, options);
      });

      if (!result.ok) {
        const error = new Error(`HTTP ${result.status}: ${result.statusText}`);
        error.status = result.status;
        throw error;
      }

      return await result.json();
    } catch (error) {
      handleApiError(error);
      throw error;
    } finally {
      loadingManager.setLoading(loadingKey, false);
    }
  }
};

// Form Validation Helper
export const FormValidator = {
  email: (value) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!value) return 'Email is required';
    if (!emailRegex.test(value)) return 'Please enter a valid email address';
    return null;
  },

  required: (value, fieldName = 'Field') => {
    if (!value || (typeof value === 'string' && !value.trim())) {
      return `${fieldName} is required`;
    }
    return null;
  },

  minLength: (value, min, fieldName = 'Field') => {
    if (value && value.length < min) {
      return `${fieldName} must be at least ${min} characters long`;
    }
    return null;
  },

  maxLength: (value, max, fieldName = 'Field') => {
    if (value && value.length > max) {
      return `${fieldName} must not exceed ${max} characters`;
    }
    return null;
  },

  pattern: (value, pattern, message) => {
    if (value && !pattern.test(value)) {
      return message;
    }
    return null;
  },

  custom: (value, validator, message) => {
    if (!validator(value)) {
      return message;
    }
    return null;
  }
};

// Utility to validate entire form
export const validateForm = (formData, validationRules) => {
  const errors = {};

  for (const [field, rules] of Object.entries(validationRules)) {
    const value = formData[field];

    for (const rule of rules) {
      const error = rule(value);
      if (error) {
        errors[field] = error;
        break; // Stop at first error for this field
      }
    }
  }

  return errors;
};
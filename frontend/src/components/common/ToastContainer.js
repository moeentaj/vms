// Toast Container Component
// frontend/src/components/common/ToastContainer.js

import React from 'react';
import { X, CheckCircle, AlertTriangle, AlertCircle, Info } from 'lucide-react';
import { useToasts } from '../../utils/errorHandling';

const ToastContainer = () => {
  const { toasts, removeToast } = useToasts();

  const getToastIcon = (type) => {
    switch (type) {
      case 'success':
        return <CheckCircle className="h-5 w-5" />;
      case 'warning':
        return <AlertTriangle className="h-5 w-5" />;
      case 'error':
        return <AlertCircle className="h-5 w-5" />;
      default:
        return <Info className="h-5 w-5" />;
    }
  };

  const getToastStyles = (type) => {
    switch (type) {
      case 'success':
        return 'bg-green-100 border-green-400 text-green-700';
      case 'warning':
        return 'bg-yellow-100 border-yellow-400 text-yellow-700';
      case 'error':
        return 'bg-red-100 border-red-400 text-red-700';
      default:
        return 'bg-blue-100 border-blue-400 text-blue-700';
    }
  };

  const Toast = ({ toast }) => {
    const handleClose = () => {
      removeToast(toast.id);
    };

    return (
      <div
        className={`
          max-w-sm w-full shadow-lg rounded-lg pointer-events-auto border-l-4 p-4 mb-3
          transform transition-all duration-300 ease-in-out
          ${getToastStyles(toast.type)}
          animate-slide-in-right
        `}
      >
        <div className="flex items-start">
          <div className="flex-shrink-0">
            {getToastIcon(toast.type)}
          </div>
          <div className="ml-3 w-0 flex-1">
            <p className="text-sm font-medium">
              {toast.message}
            </p>
            {toast.actions && (
              <div className="mt-2 flex space-x-2">
                {toast.actions.map((action, index) => (
                  <button
                    key={index}
                    onClick={() => {
                      action.onClick();
                      if (action.closeOnClick !== false) {
                        handleClose();
                      }
                    }}
                    className="text-xs font-medium underline hover:no-underline"
                  >
                    {action.label}
                  </button>
                ))}
              </div>
            )}
          </div>
          <div className="ml-4 flex-shrink-0 flex">
            <button
              onClick={handleClose}
              className="inline-flex text-gray-400 hover:text-gray-600 focus:outline-none"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
    );
  };

  if (toasts.length === 0) {
    return null;
  }

  return (
    <div className="fixed top-4 right-4 z-50 space-y-2">
      {toasts.map((toast) => (
        <Toast key={toast.id} toast={toast} />
      ))}
    </div>
  );
};

export default ToastContainer;

// Loading Overlay Component
// frontend/src/components/common/LoadingOverlay.js

export const LoadingOverlay = ({ isLoading, message = 'Loading...', children }) => {
  if (!isLoading) {
    return children;
  }

  return (
    <div className="relative">
      {children}
      <div className="absolute inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-40">
        <div className="bg-white rounded-lg p-6 shadow-lg">
          <div className="flex items-center space-x-3">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
            <span className="text-gray-700">{message}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

// Global Loading States Display
export const GlobalLoadingIndicator = () => {
  const { loadingStates } = useLoading();

  if (loadingStates.length === 0) {
    return null;
  }

  return (
    <div className="fixed bottom-4 left-4 z-50">
      <div className="bg-white rounded-lg shadow-lg border p-3 max-w-xs">
        <div className="space-y-2">
          {loadingStates.map((state) => (
            <div key={state.key} className="flex items-center space-x-2">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
              <span className="text-sm text-gray-700 truncate">
                {state.message || 'Loading...'}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// Enhanced App Component with Error Handling
// frontend/src/App.js (modification)

import ToastContainer from './components/common/ToastContainer';
import { GlobalLoadingIndicator } from './components/common/LoadingOverlay';
import { ErrorBoundary } from './utils/errorHandling';

// Add these to your main App component
const App = () => {
  return (
    <ErrorBoundary>
      <div className="App">
        {/* Your existing app content */}
        
        {/* Add these components */}
        <ToastContainer />
        <GlobalLoadingIndicator />
      </div>
    </ErrorBoundary>
  );
};

// CSS for animations (add to your global CSS)
const animationCSS = `
@keyframes slide-in-right {
  from {
    transform: translateX(100%);
    opacity: 0;
  }
  to {
    transform: translateX(0);
    opacity: 1;
  }
}

@keyframes slide-out-right {
  from {
    transform: translateX(0);
    opacity: 1;
  }
  to {
    transform: translateX(100%);
    opacity: 0;
  }
}

.animate-slide-in-right {
  animation: slide-in-right 0.3s ease-out;
}

.animate-slide-out-right {
  animation: slide-out-right 0.3s ease-in;
}
`;

export { animationCSS };
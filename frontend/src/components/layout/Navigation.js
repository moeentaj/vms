// Updated Navigation.js to include CPE-CVE Lookup
import React from 'react';
import { Shield, User, LogOut, Layers, Search, Target } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';

const Navigation = ({ currentView, setCurrentView }) => {
  const { user, logout } = useAuth();

  return (
    <div>
      <nav className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <div className="flex-shrink-0 flex items-center">
                <Shield className="h-8 w-8 text-blue-600" />
                <span className="ml-2 text-xl font-bold">VulnMgmt</span>
              </div>
              <div className="ml-10 flex space-x-8">
                <button
                  onClick={() => setCurrentView('dashboard')}
                  className={`px-3 py-2 text-sm font-medium ${
                    currentView === 'dashboard' 
                      ? 'text-blue-600 border-b-2 border-blue-600' 
                      : 'text-gray-500 hover:text-gray-700'
                  }`}
                >
                  Dashboard
                </button>
                <button
                  onClick={() => setCurrentView('cves')}
                  className={`px-3 py-2 text-sm font-medium ${
                    currentView === 'cves' 
                      ? 'text-blue-600 border-b-2 border-blue-600' 
                      : 'text-gray-500 hover:text-gray-700'
                  }`}
                >
                  CVEs
                </button>
                <button
                  onClick={() => setCurrentView('assets')}
                  className={`px-3 py-2 text-sm font-medium relative ${
                    currentView === 'assets' 
                      ? 'text-blue-600 border-b-2 border-blue-600' 
                      : 'text-gray-500 hover:text-gray-700'
                  }`}
                >
                  Assets
                  <span className="ml-1 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                    Latest
                  </span>
                </button>
                {/* NEW: CPE-CVE Lookup */}
                <button
                  onClick={() => setCurrentView('cpe-lookup')}
                  className={`px-3 py-2 text-sm font-medium relative ${
                    currentView === 'cpe-lookup' 
                      ? 'text-blue-600 border-b-2 border-blue-600' 
                      : 'text-gray-500 hover:text-gray-700'
                  }`}
                >
                  <div className="flex items-center gap-1">
                    <Target className="h-4 w-4" />
                    CPE Lookup
                  </div>
                  <span className="ml-1 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                    New
                  </span>
                </button>
                <button
                  onClick={() => setCurrentView('assignments')}
                  className={`px-3 py-2 text-sm font-medium ${
                    currentView === 'assignments' 
                      ? 'text-blue-600 border-b-2 border-blue-600' 
                      : 'text-gray-500 hover:text-gray-700'
                  }`}
                >
                  Assignments
                </button>
              </div>
            </div>

            {/* User Menu */}
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-700">
                Welcome, {user?.first_name || user?.username}
              </span>
              <button
                onClick={() => setCurrentView('profile')}
                className="p-2 text-gray-600 hover:text-gray-900"
              >
                <User className="h-5 w-5" />
              </button>
              <button
                onClick={logout}
                className="p-2 text-gray-600 hover:text-gray-900"
              >
                <LogOut className="h-5 w-5" />
              </button>
            </div>
          </div>
        </div>
      </nav>
    </div>
  );
};

export default Navigation;
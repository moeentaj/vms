import React, { useState } from 'react';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import LoginForm from './components/auth/LoginForm';
import Navigation from './components/layout/Navigation';
import Dashboard from './components/dashboard/Dashboard';
import CVEManagement from './components/cves/CVEManagement';
import AssetManagement from './components/assets/AssetManagement';
import AssignmentManagement from './components/assignments/AssignmentManagement';
import UserProfile from './components/profile/UserProfile';
import CPECVELookup from './components/cpe/CPECVELookup'; // New import

const VulnerabilityManagementApp = () => {
  const { user, loading } = useAuth();
  const [currentView, setCurrentView] = useState('dashboard');

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!user) {
    return <LoginForm />;
  }

  const renderCurrentView = () => {
    switch (currentView) {
      case 'dashboard':
        return <Dashboard />;
      case 'cves':
        return <CVEManagement />;
      case 'assets':
        return <AssetManagement />;
      case 'cpe-lookup': // New case
        return <CPECVELookup />;
      case 'assignments':
        return <AssignmentManagement />;
      case 'profile':
        return <UserProfile />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navigation currentView={currentView} setCurrentView={setCurrentView} />
      <main className="max-w-7xl mx-auto py-6 px-4">
        {renderCurrentView()}
      </main>
    </div>
  );
};

const App = () => {
  return (
    <AuthProvider>
      <VulnerabilityManagementApp />
    </AuthProvider>
  );
};

export default App;
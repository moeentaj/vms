import React, { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';
import { Shield, AlertTriangle, Server, Users, Clock, CheckCircle } from 'lucide-react';
import { api } from '../../services/api';
import { COLORS } from '../../utils/constants';
import StatCard from './StatCard';

const Dashboard = () => {
  const [dashboardData, setDashboardData] = useState(null);
  const [assignmentStats, setAssignmentStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      const [dashboard, assignments] = await Promise.all([
        api.getDashboardData(),
        api.getAssignmentStats()
      ]);
      setDashboardData(dashboard);
      setAssignmentStats(assignments);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
      // Mock data for development
      setDashboardData({
        statistics: {
          total_cves: 1247,
          total_assets: 156,
          high_risk_cves: 89,
          critical_assets: 23,
          recent_cves: 45
        },
        top_cves: [
          { cve_id: 'CVE-2024-0001', cvss_score: 9.8, severity: 'CRITICAL', description: 'Remote code execution in Apache Web Server...' },
          { cve_id: 'CVE-2024-0002', cvss_score: 9.1, severity: 'CRITICAL', description: 'SQL injection vulnerability in MySQL...' }
        ],
        asset_breakdown: {
          by_environment: { production: 89, staging: 34, development: 33 },
          by_criticality: { critical: 23, high: 45, medium: 67, low: 21 }
        }
      });
      setAssignmentStats({
        status_counts: { assigned: 15, in_progress: 8, completed: 32, closed: 12 },
        overdue_count: 3,
        priority_counts: { critical: 5, high: 12, medium: 18, low: 8 },
        total_active: 23
      });
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  const { statistics, top_cves, asset_breakdown } = dashboardData;

  return (
    <div className="space-y-6">
      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
        <StatCard
          title="Total CVEs"
          value={statistics.total_cves}
          icon={<Shield className="h-6 w-6" />}
          color="blue"
        />
        <StatCard
          title="High Risk CVEs"
          value={statistics.high_risk_cves}
          icon={<AlertTriangle className="h-6 w-6" />}
          color="red"
        />
        <StatCard
          title="Total Assets"
          value={statistics.total_assets}
          icon={<Server className="h-6 w-6" />}
          color="green"
        />
        <StatCard
          title="Active Assignments"
          value={assignmentStats?.total_active || 0}
          icon={<Users className="h-6 w-6" />}
          color="purple"
        />
        <StatCard
          title="Overdue"
          value={assignmentStats?.overdue_count || 0}
          icon={<Clock className="h-6 w-6" />}
          color="orange"
        />
        <StatCard
          title="Completed"
          value={assignmentStats?.status_counts?.completed || 0}
          icon={<CheckCircle className="h-6 w-6" />}
          color="green"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Asset Environment Chart */}
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-lg font-semibold mb-4">Assets by Environment</h3>
          <PieChart width={250} height={200}>
            <Pie
              data={Object.entries(asset_breakdown.by_environment).map(([env, count]) => ({
                name: env,
                value: count
              }))}
              cx={125}
              cy={100}
              innerRadius={40}
              outerRadius={80}
              dataKey="value"
            >
              {Object.entries(asset_breakdown.by_environment).map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
        </div>

        {/* Assignment Status Chart */}
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-lg font-semibold mb-4">Assignment Status</h3>
          <BarChart width={250} height={200} data={
            Object.entries(assignmentStats?.status_counts || {}).map(([status, count]) => ({
              name: status.replace('_', ' '),
              value: count
            }))
          }>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" />
            <YAxis />
            <Tooltip />
            <Bar dataKey="value" fill="#3b82f6" />
          </BarChart>
        </div>

        {/* Priority Distribution */}
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-lg font-semibold mb-4">Priority Distribution</h3>
          <PieChart width={250} height={200}>
            <Pie
              data={Object.entries(assignmentStats?.priority_counts || {}).map(([priority, count]) => ({
                name: priority,
                value: count
              }))}
              cx={125}
              cy={100}
              innerRadius={40}
              outerRadius={80}
              dataKey="value"
            >
              {Object.entries(assignmentStats?.priority_counts || {}).map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
        </div>
      </div>

      {/* Top CVEs Table */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b">
          <h3 className="text-lg font-semibold">Top Risk CVEs</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">CVE ID</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">CVSS Score</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {top_cves.map((cve) => (
                <tr key={cve.cve_id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-blue-600">
                    {cve.cve_id}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                      cve.cvss_score >= 9 ? 'bg-red-100 text-red-800' :
                      cve.cvss_score >= 7 ? 'bg-orange-100 text-orange-800' :
                      'bg-yellow-100 text-yellow-800'
                    }`}>
                      {cve.cvss_score}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                      cve.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                      cve.severity === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                      'bg-yellow-100 text-yellow-800'
                    }`}>
                      {cve.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-900">
                    {cve.description}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
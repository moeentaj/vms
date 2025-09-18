import React, { useState, useEffect } from 'react';
import { Plus } from 'lucide-react';
import { api } from '../../services/api';
import { useAuth } from '../../contexts/AuthContext';
import { STATUS_COLORS, PRIORITY_COLORS } from '../../utils/constants';
import CreateAssignmentModal from './CreateAssignmentModal';

const AssignmentManagement = () => {
  const [assignments, setAssignments] = useState([]);
  const [users, setUsers] = useState([]);
  const [cves, setCVEs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [filter, setFilter] = useState({ status: '', assignee_id: '', my_assignments: false });
  const { user } = useAuth();

  useEffect(() => {
    loadData();
  }, [filter]);

  const loadData = async () => {
    setLoading(true);
    try {
      const [assignmentsData, usersData, cvesData] = await Promise.all([
        api.getAssignments(filter),
        api.getUsers().catch(() => []), // May fail for non-admin users
        api.getCVEs({ limit: 50 })
      ]);
      
      setAssignments(assignmentsData);
      setUsers(usersData);
      setCVEs(cvesData);
    } catch (error) {
      console.error('Failed to load data:', error);
      // Mock data for development
      setAssignments([
        {
          id: 1,
          title: 'Investigate Critical CVE',
          cve_id: 'CVE-2024-0001',
          assignee_name: 'John Doe',
          status: 'assigned',
          priority: 'critical',
          due_date: '2024-12-31',
          description: 'Critical vulnerability needs immediate attention'
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateStatus = async (assignmentId, status) => {
    try {
      await api.updateAssignment(assignmentId, { status });
      loadData(); // Reload assignments
    } catch (error) {
      console.error('Failed to update assignment:', error);
    }
  };

  if (loading) {
    return <div className="flex justify-center p-8"><div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div></div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">Vulnerability Assignments</h2>
        {(user?.role === 'admin' || user?.role === 'manager') && (
          <button
            onClick={() => setShowCreateModal(true)}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center gap-2"
          >
            <Plus className="h-4 w-4" />
            Create Assignment
          </button>
        )}
      </div>

      {/* Filters */}
      <div className="bg-white p-4 rounded-lg shadow flex gap-4 flex-wrap">
        <select
          value={filter.status}
          onChange={(e) => setFilter(prev => ({ ...prev, status: e.target.value }))}
          className="px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500"
        >
          <option value="">All Status</option>
          <option value="assigned">Assigned</option>
          <option value="in_progress">In Progress</option>
          <option value="under_review">Under Review</option>
          <option value="completed">Completed</option>
          <option value="closed">Closed</option>
        </select>

        {users.length > 0 && (
          <select
            value={filter.assignee_id}
            onChange={(e) => setFilter(prev => ({ ...prev, assignee_id: e.target.value }))}
            className="px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Assignees</option>
            {users.map(user => (
              <option key={user.id} value={user.id}>
                {user.first_name} {user.last_name} ({user.username})
              </option>
            ))}
          </select>
        )}

        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={filter.my_assignments}
            onChange={(e) => setFilter(prev => ({ ...prev, my_assignments: e.target.checked }))}
            className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
          />
          <span className="text-sm">My Assignments Only</span>
        </label>
      </div>

      {/* Assignments List */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">CVE</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Assignee</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Priority</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Due Date</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {assignments.map((assignment) => (
              <tr key={assignment.id} className="hover:bg-gray-50">
                <td className="px-6 py-4">
                  <div className="text-sm font-medium text-gray-900">{assignment.title}</div>
                  <div className="text-sm text-gray-500">{assignment.description?.substring(0, 50)}...</div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-blue-600">
                  {assignment.cve_id}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  {assignment.assignee_name}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${PRIORITY_COLORS[assignment.priority] || 'bg-gray-100 text-gray-800'}`}>
                    {assignment.priority}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${STATUS_COLORS[assignment.status] || 'bg-gray-100 text-gray-800'}`}>
                    {assignment.status.replace('_', ' ')}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  {assignment.due_date ? new Date(assignment.due_date).toLocaleDateString() : 'No due date'}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  {assignment.status === 'assigned' && (
                    <button
                      onClick={() => handleUpdateStatus(assignment.id, 'in_progress')}
                      className="text-blue-600 hover:text-blue-900 mr-3"
                    >
                      Start
                    </button>
                  )}
                  {assignment.status === 'in_progress' && (
                    <button
                      onClick={() => handleUpdateStatus(assignment.id, 'completed')}
                      className="text-green-600 hover:text-green-900 mr-3"
                    >
                      Complete
                    </button>
                  )}
                  <button className="text-gray-600 hover:text-gray-900">
                    View
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        
        {assignments.length === 0 && (
          <div className="text-center py-8 text-gray-500">
            No assignments found
          </div>
        )}
      </div>

      {/* Create Assignment Modal */}
      {showCreateModal && (
        <CreateAssignmentModal
          users={users}
          cves={cves}
          onClose={() => setShowCreateModal(false)}
          onSuccess={() => {
            setShowCreateModal(false);
            loadData();
          }}
        />
      )}
    </div>
  );
};

export default AssignmentManagement;
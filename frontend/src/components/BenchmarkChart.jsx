import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const BenchmarkChart = ({ history = [] }) => {
  if (history.length === 0) {
    return (
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Performance History</h3>
        <div className="text-center py-8 text-gray-500">
          <p>No performance data available yet.</p>
          <p className="text-sm">Run some operations to see performance metrics here.</p>
        </div>
      </div>
    );
  }

  // Prepare data for the chart - updated for new 3-comparison structure
  const chartData = history.slice(-5).map((item, index) => ({
    name: `${item.algorithm || 'Unknown'}`,
    time: item.time?.summary?.totalAvgMs || 0,
    throughput: item.throughput?.summary?.avgMBps || 0,
    memory: item.memory?.summary?.totalAvgMB || 0,
  }));

  return (
    <div className="card">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Performance History</h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" />
            <YAxis />
            <Tooltip 
              formatter={(value, name) => [
                name === 'time' ? `${value}ms` : 
                name === 'throughput' ? `${value} MB/s` : 
                `${value}MB`,
                name === 'time' ? 'Total Time' : 
                name === 'throughput' ? 'Throughput' : 
                'Memory Usage'
              ]}
            />
            <Bar dataKey="time" fill="#3b82f6" name="Total Time" />
            <Bar dataKey="throughput" fill="#10b981" name="Throughput" />
            <Bar dataKey="memory" fill="#f59e0b" name="Memory Usage" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default BenchmarkChart; 
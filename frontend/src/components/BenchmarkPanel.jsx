import React from 'react';
import { Clock, Cpu, TrendingUp, Zap, Activity } from 'lucide-react';

const BenchmarkPanel = ({ result }) => {
  if (!result) return null;

  const metrics = [
    {
      label: 'Total Time',
      value: `${result.time?.summary?.totalAvgMs || 0}ms`,
      icon: Clock,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50',
      subValue: `Enc: ${result.time?.encryption?.avgMs || 0}ms | Dec: ${result.time?.decryption?.avgMs || 0}ms`
    },
    {
      label: 'Throughput',
      value: `${result.throughput?.summary?.avgMBps || 0} MB/s`,
      icon: TrendingUp,
      color: 'text-green-600',
      bgColor: 'bg-green-50',
      subValue: `Enc: ${result.throughput?.encryption?.MBps || 0} MB/s | Dec: ${result.throughput?.decryption?.MBps || 0} MB/s`
    },
    {
      label: 'Memory Usage',
      value: `${result.memory?.summary?.totalAvgMB || 0} MB`,
      icon: Cpu,
      color: 'text-purple-600',
      bgColor: 'bg-purple-50',
      subValue: `Enc: ${result.memory?.encryption?.avgMB || 0} MB | Dec: ${result.memory?.decryption?.avgMB || 0} MB`
    }
  ];

  return (
    <div className="card">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Performance Metrics</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {metrics.map((metric, index) => {
          const IconComponent = metric.icon;
          return (
            <div key={index} className={`${metric.bgColor} p-4 rounded-lg`}>
              <div className="flex items-center space-x-2">
                <IconComponent className={`w-5 h-5 ${metric.color}`} />
                <span className="text-sm font-medium text-gray-700">{metric.label}</span>
              </div>
              <div className={`text-xl font-bold ${metric.color} mt-1`}>
                {metric.value}
              </div>
              <div className="text-xs text-gray-600 mt-1">
                {metric.subValue}
              </div>
            </div>
          );
        })}
      </div>
      
                           {/* Efficiency Score */}
        {result.memory?.summary?.efficiencyScore && (
          <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
            <div className="flex items-center space-x-2">
              <Activity className="w-4 h-4 text-yellow-600" />
              <div className="text-sm text-yellow-800">
                <div><strong>Efficiency Score:</strong> {result.memory.summary.efficiencyScore}/100</div>
              </div>
            </div>
          </div>
        )}
       

      
      {result.recommendation && (
        <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
          <div className="flex items-center space-x-2">
            <Zap className="w-4 h-4 text-blue-600" />
            <span className="text-sm text-blue-800">
              <strong>Recommendation:</strong> {result.recommendation}
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

export default BenchmarkPanel; 
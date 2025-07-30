import React, { useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';
import { Clock, Cpu, TrendingUp, Zap, Activity, Target, FileText, Type } from 'lucide-react';
import { cryptoAPI } from '../services/api';

const BenchmarkPage = () => {
  const [selectedAlgorithms, setSelectedAlgorithms] = useState(['AES-CBC']); // Array of algorithm-mode combinations
  const [testDataOption, setTestDataOption] = useState('custom'); // 'custom', 'random', 'file'
  const [customTestData, setCustomTestData] = useState('Hello World! This is a test message for benchmarking cryptographic algorithms.');
  const [randomDataSize, setRandomDataSize] = useState(1024); // bytes
  const [iterations, setIterations] = useState(10);
  const [isRunning, setIsRunning] = useState(false);
  const [results, setResults] = useState(null);
  const [benchmarkHistory, setBenchmarkHistory] = useState([]);

  // Available algorithm-mode combinations
  const algorithmModeCombinations = [
    { id: 'AES-CBC', name: 'AES-CBC', algorithm: 'AES', mode: 'CBC', color: '#10b981', description: 'AES in CBC mode' },
    { id: 'AES-CFB', name: 'AES-CFB', algorithm: 'AES', mode: 'CFB', color: '#3b82f6', description: 'AES in CFB mode' },
    { id: 'AES-OFB', name: 'AES-OFB', algorithm: 'AES', mode: 'OFB', color: '#06b6d4', description: 'AES in OFB mode' },
    { id: 'AES-CTR', name: 'AES-CTR', algorithm: 'AES', mode: 'CTR', color: '#8b5cf6', description: 'AES in CTR mode' },
    { id: 'AES-GCM', name: 'AES-GCM', algorithm: 'AES', mode: 'GCM', color: '#f59e0b', description: 'AES in GCM mode' },
    { id: 'AES-ECB', name: 'AES-ECB', algorithm: 'AES', mode: 'ECB', color: '#ef4444', description: 'AES in ECB mode' },
    { id: '3DES-CBC', name: '3DES-CBC', algorithm: '3DES', mode: 'CBC', color: '#84cc16', description: '3DES in CBC mode' },
    { id: '3DES-CFB', name: '3DES-CFB', algorithm: '3DES', mode: 'CFB', color: '#f97316', description: '3DES in CFB mode' },
    { id: '3DES-OFB', name: '3DES-OFB', algorithm: '3DES', mode: 'OFB', color: '#ec4899', description: '3DES in OFB mode' },
    { id: '3DES-ECB', name: '3DES-ECB', algorithm: '3DES', mode: 'ECB', color: '#6366f1', description: '3DES in ECB mode' },
    { id: 'BLOWFISH-CBC', name: 'BLOWFISH-CBC', algorithm: 'BLOWFISH', mode: 'CBC', color: '#06b6d4', description: 'Blowfish in CBC mode' },
    { id: 'BLOWFISH-CFB', name: 'BLOWFISH-CFB', algorithm: 'BLOWFISH', mode: 'CFB', color: '#8b5cf6', description: 'Blowfish in CFB mode' },
    { id: 'BLOWFISH-OFB', name: 'BLOWFISH-OFB', algorithm: 'BLOWFISH', mode: 'OFB', color: '#f59e0b', description: 'Blowfish in OFB mode' },
    { id: 'BLOWFISH-ECB', name: 'BLOWFISH-ECB', algorithm: 'BLOWFISH', mode: 'ECB', color: '#ef4444', description: 'Blowfish in ECB mode' }
  ];

  const dataSizeOptions = [
    { value: 64, label: '64 bytes' },
    { value: 256, label: '256 bytes' },
    { value: 1024, label: '1 KB' },
    { value: 4096, label: '4 KB' },
    { value: 16384, label: '16 KB' },
    { value: 65536, label: '64 KB' },
    { value: 262144, label: '256 KB' },
    { value: 1048576, label: '1 MB' }
  ];

  const iterationOptions = [
    { value: 5, label: '5 iterations' },
    { value: 10, label: '10 iterations' },
    { value: 25, label: '25 iterations' },
    { value: 50, label: '50 iterations' },
    { value: 100, label: '100 iterations' }
  ];

  const generateRandomData = (size) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let result = '';
    for (let i = 0; i < size; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  };

  const getTestData = () => {
    switch (testDataOption) {
      case 'random':
        return generateRandomData(randomDataSize);
      case 'custom':
      default:
        return customTestData;
    }
  };

  const runBenchmark = async () => {
    setIsRunning(true);
    setResults(null);

    try {
      const testData = getTestData();
      const benchmarkResults = [];
      
      // Run benchmark for each selected algorithm-mode combination
      for (const algorithmModeId of selectedAlgorithms) {
        const combination = algorithmModeCombinations.find(c => c.id === algorithmModeId);
        if (!combination) continue;
        
        try {
          const response = await cryptoAPI.benchmark({
            algorithm: combination.algorithm,
            mode: combination.mode,
            testData: testData,
            iterations: iterations
          });

          console.log(`Benchmark response for ${combination.name}:`, response);
          
          if (response.success) {
            const result = response.result;
            console.log(`Success result for ${combination.name}:`, result);
            benchmarkResults.push({
              ...result,
              combinationId: algorithmModeId,
              combinationName: combination.name,
              color: combination.color
            });
          } else {
            console.log(`Error result for ${combination.name}:`, response.error);
            benchmarkResults.push({
              combinationId: algorithmModeId,
              combinationName: combination.name,
              color: combination.color,
              error: response.error
            });
          }
        } catch (error) {
          benchmarkResults.push({
            combinationId: algorithmModeId,
            combinationName: combination.name,
            color: combination.color,
            error: error.message
          });
        }
      }

      setResults(benchmarkResults);
      
      // Add successful results to history
      const successfulResults = benchmarkResults.filter(r => !r.error);
      if (successfulResults.length > 0) {
        const historyEntry = {
          timestamp: new Date().toISOString(),
          testDataOption,
          dataSize: testData.length,
          results: successfulResults
        };
        setBenchmarkHistory(prev => [historyEntry, ...prev.slice(0, 9)]); // Keep last 10
      }
    } catch (error) {
      console.error('Benchmark failed:', error);
      setResults({ error: error.message });
    } finally {
      setIsRunning(false);
    }
  };

  const getChartData = () => {
    if (!results || results.error || !Array.isArray(results)) return [];
    
    console.log('Raw results:', results);
    const filteredResults = results.filter(r => !r.error);
    console.log('Filtered results (no errors):', filteredResults);
    
    const chartData = filteredResults.map(result => ({
      name: result.combinationName,
      // Time metrics
      encryptionTime: result.time?.encryption?.avgMs || 0,
      decryptionTime: result.time?.decryption?.avgMs || 0,
      totalTime: result.time?.summary?.totalAvgMs || 0,
      // Throughput metrics
      encryptionThroughput: result.throughput?.encryption?.MBps || 0,
      decryptionThroughput: result.throughput?.decryption?.MBps || 0,
      avgThroughput: result.throughput?.summary?.avgMBps || 0,
      // Memory metrics (properly scaled)
      encryptionMemory: result.memory?.encryption?.avgMB || 0,
      decryptionMemory: result.memory?.decryption?.avgMB || 0,
      color: result.color
    }));
    
    // Handle outliers for better graph visualization
    const handleOutliers = (data, key) => {
      const values = data.map(d => d[key]).filter(v => v > 0);
      if (values.length === 0) return data;
      
      // Calculate quartiles
      const sorted = values.sort((a, b) => a - b);
      const q1 = sorted[Math.floor(sorted.length * 0.25)];
      const q3 = sorted[Math.floor(sorted.length * 0.75)];
      const iqr = q3 - q1;
      const upperBound = q3 + 1.5 * iqr;
      
      // Cap outliers at upper bound for better visualization
      return data.map(d => ({
        ...d,
        [key]: d[key] > upperBound ? upperBound : d[key]
      }));
    };
    
    // Apply outlier handling to memory data for better graphs
    let processedData = handleOutliers(chartData, 'encryptionMemory');
    processedData = handleOutliers(processedData, 'decryptionMemory');
    
    console.log('Chart data (outliers handled):', processedData);
    return processedData;
  };

  const getHistoryChartData = () => {
    return benchmarkHistory.map(entry => {
      const data = {
        timestamp: new Date(entry.timestamp).toLocaleTimeString()
      };
      
      // Add data for each algorithm-mode combination
      if (entry.results) {
        entry.results.forEach(result => {
          data[`${result.combinationName}-Encryption`] = result.encryption.avgTimeMs;
          data[`${result.combinationName}-Decryption`] = result.decryption.avgTimeMs;
        });
      }
      
      return data;
    });
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="h-screen bg-gray-50 flex flex-col">
      {/* Header */}
      <div className="bg-white border-b border-gray-200 px-6 py-4 flex-shrink-0">
        <h1 className="text-2xl font-bold text-gray-900 mb-1">Algorithm Benchmarking</h1>
        <p className="text-gray-600 text-sm">Test and compare the performance of cryptographic algorithms with high-precision timing measurements</p>
      </div>

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto px-6 py-6">

        {/* Configuration Panel */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Benchmark Configuration</h2>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Algorithm-Mode Selection */}
            <div className="lg:col-span-2">
              <label className="block text-sm font-medium text-gray-700 mb-2">Select Algorithm-Mode Combinations (Max 5)</label>
              <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto border border-gray-300 rounded-lg p-3">
                {algorithmModeCombinations.map((combination) => (
                  <label key={combination.id} className="flex items-center">
                    <input
                      type="checkbox"
                      checked={selectedAlgorithms.includes(combination.id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          if (selectedAlgorithms.length < 5) {
                            setSelectedAlgorithms([...selectedAlgorithms, combination.id]);
                          }
                        } else {
                          setSelectedAlgorithms(selectedAlgorithms.filter(id => id !== combination.id));
                        }
                      }}
                      disabled={!selectedAlgorithms.includes(combination.id) && selectedAlgorithms.length >= 5}
                      className="mr-2 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="text-sm text-gray-700">{combination.name}</span>
                  </label>
                ))}
              </div>
              <p className="text-xs text-gray-500 mt-1">
                Selected: {selectedAlgorithms.length}/5 combinations
              </p>
            </div>

            {/* Test Configuration */}
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Test Data</label>
                <select
                  value={testDataOption}
                  onChange={(e) => setTestDataOption(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="custom">Custom Text</option>
                  <option value="random">Random Data</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Iterations</label>
                <select
                  value={iterations}
                  onChange={(e) => setIterations(parseInt(e.target.value))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  {iterationOptions.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* Test Data Configuration */}
          <div className="mt-6">
            {testDataOption === 'custom' ? (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Custom Test Data</label>
                <textarea
                  value={customTestData}
                  onChange={(e) => setCustomTestData(e.target.value)}
                  rows={2}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Enter your test data here..."
                />
                <p className="text-xs text-gray-500 mt-1">
                  Data size: {formatBytes(customTestData.length)}
                </p>
              </div>
            ) : (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Random Data Size</label>
                <select
                  value={randomDataSize}
                  onChange={(e) => setRandomDataSize(parseInt(e.target.value))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  {dataSizeOptions.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>

          {/* Run Button */}
          <div className="mt-6 flex items-center justify-between">
            <button
              onClick={runBenchmark}
              disabled={isRunning || selectedAlgorithms.length === 0}
              className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white px-8 py-3 rounded-lg font-medium flex items-center space-x-2 transition-colors"
            >
              {isRunning ? (
                <>
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                  <span>Running...</span>
                </>
              ) : (
                <>
                  <Zap className="w-5 h-5" />
                  <span>Run Benchmark ({selectedAlgorithms.length})</span>
                </>
              )}
            </button>
            <p className="text-xs text-gray-500">
              ⚡ High-precision timing with system warm-up
            </p>
          </div>
        </div>

        {/* Results Section - Only show after benchmark completes */}
        {results && !results.error && Array.isArray(results) && (
          <div className="space-y-6">
            {/* Performance Overview - 3 Comparison Categories */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Time Performance */}
              <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
                <div className="flex items-center space-x-2 mb-2">
                  <Clock className="w-4 h-4 text-blue-600" />
                  <span className="text-xs font-medium text-gray-700">Fastest Total Time</span>
                </div>
                <div className="text-sm font-bold text-blue-900">
                  {(() => {
                    const fastest = results.filter(r => !r.error).sort((a, b) => a.time?.summary?.totalAvgMs - b.time?.summary?.totalAvgMs)[0];
                    return fastest ? `${fastest.combinationName} (${fastest.time?.summary?.totalAvgMs}ms)` : 'N/A';
                  })()}
                </div>
              </div>
              
              {/* Throughput Performance */}
              <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
                <div className="flex items-center space-x-2 mb-2">
                  <TrendingUp className="w-4 h-4 text-green-600" />
                  <span className="text-xs font-medium text-gray-700">Highest Throughput</span>
                </div>
                <div className="text-sm font-bold text-green-900">
                  {(() => {
                    const fastest = results.filter(r => !r.error).sort((a, b) => b.throughput?.summary?.avgMBps - a.throughput?.summary?.avgMBps)[0];
                    return fastest ? `${fastest.combinationName} (${fastest.throughput?.summary?.avgMBps} MB/s)` : 'N/A';
                  })()}
                </div>
              </div>
              
              {/* Memory Performance */}
              <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
                <div className="flex items-center space-x-2 mb-2">
                  <Cpu className="w-4 h-4 text-purple-600" />
                  <span className="text-xs font-medium text-gray-700">Best Efficiency</span>
                </div>
                <div className="text-sm font-bold text-purple-900">
                  {(() => {
                    const bestPerformer = results.filter(r => !r.error).sort((a, b) => 
                      (b.memory?.summary?.efficiencyScore || 0) - (a.memory?.summary?.efficiencyScore || 0)
                    )[0];
                    return bestPerformer ? `${bestPerformer.combinationName} (${bestPerformer.memory?.summary?.efficiencyScore || 0}/100)` : 'N/A';
                  })()}
                </div>
              </div>
              
              <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
                <div className="flex items-center space-x-2 mb-2">
                  <Activity className="w-4 h-4 text-orange-600" />
                  <span className="text-xs font-medium text-gray-700">Tests Completed</span>
                </div>
                <div className="text-lg font-bold text-orange-900">
                  {results.filter(r => !r.error).length}/{results.length}
                </div>
                <div className="text-xs text-gray-500">
                  {results.filter(r => r.error).length} failed
                </div>
              </div>
            </div>

            {/* Charts - 3 Comparison Categories */}
            {results && Array.isArray(results) && results.length > 0 && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Time Comparison Chart */}
                <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
                  <h3 className="text-base font-semibold text-gray-900 mb-3">Time Comparison</h3>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={getChartData()}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis 
                          dataKey="name" 
                          interval={0}
                          fontSize={11}
                        />
                        <YAxis 
                          domain={[0, 'dataMax * 1.1']}
                        />
                        <Tooltip formatter={(value, name) => [`${value}ms`, name]} />
                        <Bar dataKey="encryptionTime" fill="#3b82f6" name="Encryption" />
                        <Bar dataKey="decryptionTime" fill="#10b981" name="Decryption" />
                        <Bar dataKey="totalTime" fill="#1e40af" name="Total" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Throughput Comparison Chart */}
                <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
                  <h3 className="text-base font-semibold text-gray-900 mb-3">Throughput Comparison</h3>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={getChartData()}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis 
                          dataKey="name" 
                          interval={0}
                          fontSize={11}
                        />
                        <YAxis 
                          domain={[0, 'dataMax * 1.1']}
                        />
                        <Tooltip formatter={(value, name) => [`${value} MB/s`, name]} />
                        <Bar dataKey="encryptionThroughput" fill="#8b5cf6" name="Encryption" />
                        <Bar dataKey="decryptionThroughput" fill="#f59e0b" name="Decryption" />
                        <Bar dataKey="avgThroughput" fill="#7c3aed" name="Average" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Memory Comparison Chart */}
                <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
                  <h3 className="text-base font-semibold text-gray-900 mb-3">Memory Comparison</h3>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={getChartData()}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis 
                          dataKey="name" 
                          interval={0}
                          fontSize={11}
                        />
                        <YAxis 
                          domain={[0, 'dataMax * 1.1']}
                          tickFormatter={(value) => value.toFixed(4)}
                        />
                        <Tooltip formatter={(value, name) => [`${value.toFixed(6)} MB`, name]} />
                        <Bar dataKey="encryptionMemory" fill="#ec4899" name="Encryption" />
                        <Bar dataKey="decryptionMemory" fill="#be185d" name="Decryption" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>
            )}

            {/* Detailed Results Table */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Detailed Results</h3>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Algorithm-Mode
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Time (ms)
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Throughput (MB/s)
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Memory (MB)
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Efficiency Score
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Status
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {results.map((result, index) => (
                      <tr key={index}>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                          {result.combinationName}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {result.error ? 'N/A' : (
                            <div>
                              <div className="font-medium">{result.time?.summary?.totalAvgMs || 0}ms</div>
                              <div className="text-xs text-gray-500">
                                Enc: {result.time?.encryption?.avgMs || 0}ms | Dec: {result.time?.decryption?.avgMs || 0}ms
                              </div>
                            </div>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {result.error ? 'N/A' : (
                            <div>
                              <div className="font-medium">{result.throughput?.summary?.avgMBps || 0} MB/s</div>
                              <div className="text-xs text-gray-500">
                                Enc: {result.throughput?.encryption?.MBps || 0} MB/s | Dec: {result.throughput?.decryption?.MBps || 0} MB/s
                              </div>
                            </div>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {result.error ? 'N/A' : (
                            <div>
                              <div className="font-medium">{result.memory?.summary?.totalAvgMB || 0} MB</div>
                              <div className="text-xs text-gray-500">
                                Enc: {result.memory?.encryption?.avgMB || 0} MB | Dec: {result.memory?.decryption?.avgMB || 0} MB
                              </div>
                            </div>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {result.error ? 'N/A' : (
                            <div>
                              <div className="font-medium text-purple-600">
                                {result.memory?.summary?.efficiencyScore || 0}/100
                              </div>
                            </div>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                            result.error 
                              ? 'bg-red-100 text-red-800' 
                              : 'bg-green-100 text-green-800'
                          }`}>
                            {result.error ? 'Failed' : 'Success'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              
              {/* Test Configuration Summary */}
              <div className="mt-6 pt-6 border-t border-gray-200">
                <h4 className="font-medium text-gray-900 mb-2">Test Configuration</h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm text-gray-600">
                  <div><span className="font-medium">Data Size:</span> {formatBytes(results[0]?.dataSize || 0)}</div>
                  <div><span className="font-medium">Iterations:</span> {results[0]?.iterations || 0}</div>
                  <div><span className="font-medium">Test Data Type:</span> {testDataOption === 'custom' ? 'Custom Text' : 'Random Data'}</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Loading State */}
        {isRunning && (
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <div className="flex items-center space-x-3">
              <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
              <div>
                <h3 className="text-base font-semibold text-blue-900">Running Benchmark...</h3>
                <p className="text-blue-700 text-sm">
                  Testing {selectedAlgorithms.length} combinations with {iterations} iterations each
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Error Display */}
        {results && results.error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
            <div className="flex items-center space-x-2">
              <Activity className="w-5 h-5 text-red-600" />
              <span className="text-red-800 font-medium">Benchmark Failed</span>
            </div>
            <p className="text-red-700 mt-2">{results.error}</p>
          </div>
        )}

        {/* Benchmark History - Only show when there's actual history data */}
        {benchmarkHistory.length > 0 && benchmarkHistory.some(entry => entry.encryption && entry.decryption) && (
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Benchmark History</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={getHistoryChartData()}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp" />
                  <YAxis />
                  <Tooltip 
                    formatter={(value, name) => [`${value}ms`, name]}
                    labelFormatter={(value) => value}
                  />
                  <Line
                    type="monotone"
                    dataKey="encryption"
                    stroke="#3b82f6"
                    name="Encryption"
                    strokeWidth={2}
                  />
                  <Line
                    type="monotone"
                    dataKey="decryption"
                    stroke="#10b981"
                    name="Decryption"
                    strokeWidth={2}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default BenchmarkPage; 
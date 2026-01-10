import React, { useState, useCallback, useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';
import { Clock, Cpu, TrendingUp, Zap, Activity, Target, FileText, Type, Play, Settings, BarChart3, Shield, Timer, Database, CheckCircle, AlertCircle, Info, Plus, Trash2, ChevronDown, X } from 'lucide-react';
import { cryptoAPI } from '../services/api';

const ALGORITHMS = {
  'AES': {
    name: 'Advanced Encryption Standard',
    modes: ['CBC', 'CFB', 'OFB', 'CTR', 'GCM', 'ECB'],
    description: 'Modern symmetric encryption standard with native GCM support',
    security: 'High',
    speed: 'Very Fast',
    blockSize: '128-bit (16 bytes)',
    keyLengths: '128, 192, 256-bit',
    ivSize: '128-bit (CBC mode)',
    parallelizable: 'Yes (CTR, GCM modes)',
    color: '#10b981'
  },
  '3DES': {
    name: 'Triple Data Encryption Standard',
    modes: ['CBC', 'CFB', 'OFB', 'CTR', 'ECB'],
    description: 'Legacy triple encryption (3 DES rounds) - deprecated standard',
    security: 'Medium',
    speed: 'Slow',
    blockSize: '64-bit (8 bytes)',
    keyLengths: '112, 168-bit (3 keys)',
    ivSize: '64-bit (CBC mode)',
    parallelizable: 'Limited',
    color: '#f59e0b'
  },
  'BLOWFISH': {
    name: 'Blowfish Cipher',
    modes: ['CBC', 'CFB', 'OFB', 'CTR', 'ECB'],
    description: 'Variable key-length block cipher with key-dependent S-boxes',
    security: 'Medium',
    speed: 'Medium',
    blockSize: '64-bit (8 bytes)',
    keyLengths: '32-448 bit variable',
    ivSize: '64-bit (CBC mode)',
    parallelizable: 'Limited',
    color: '#8b5cf6'
  },
  'RC2': {
    name: 'Rivest Cipher 2',
    modes: ['CBC', 'ECB'],
    description: 'Variable key-length legacy cipher - cryptographically weak',
    security: 'Low',
    speed: 'Very Slow',
    blockSize: '64-bit (8 bytes)',
    keyLengths: '40-128 bit variable',
    ivSize: '64-bit (CBC mode)',
    parallelizable: 'No',
    color: '#ef4444'
  },
  'SM4': {
    name: 'SM4 (Chinese National Standard)',
    modes: ['CBC', 'CFB', 'OFB', 'CTR', 'GCM', 'ECB'],
    description: 'Chinese national block cipher standard - secure for general use',
    security: 'High',
    speed: 'Medium',
    blockSize: '128-bit (16 bytes)',
    keyLengths: '128-bit fixed',
    ivSize: '128-bit (16 bytes)',
    parallelizable: 'Yes (CTR, GCM)',
    color: '#dc2626'
  },
  'SALSA20': {
    name: 'Salsa20 Stream Cipher',
    modes: ['STREAM'],
    description: 'Fast ARX-based stream cipher (8/12/20 rounds) that XORs a keystream with plaintext.',
    security: 'High (20 rounds)',
    speed: 'Extremely Fast',
    blockSize: 'Stream (512-bit internal state)',
    keyLengths: '128 or 256-bit',
    ivSize: '64-bit nonce',
    parallelizable: 'Yes',
    color: '#be123c'
  },
  'CHACHA20': {
    name: 'ChaCha20 Stream Cipher',
    modes: ['STREAM'],
    description: 'Modern stream cipher (RFC 8439) by D.J. Bernstein; typically paired with Poly1305.',
    security: 'High (20 rounds)',
    speed: 'Extremely Fast',
    blockSize: 'Stream (512-bit internal state)',
    keyLengths: '256-bit fixed',
    ivSize: '96-bit nonce',
    parallelizable: 'Yes',
    color: '#f97316'
  }
  /*
  , 'RAILFENCE': {
    name: 'Rail Fence Cipher',
    modes: ['RAILFENCE'],
    description: 'Classical transposition cipher using zigzag rails (educational only).',
    security: 'Low',
    speed: 'Fast',
    blockSize: 'N/A (transposition)',
    keyLengths: 'Rails 2-64',
    offset: '0+ (optional)',
    ivSize: 'None',
    parallelizable: 'No',
    color: '#14b8a6'
  }
  , 'MORSE': {
    name: 'Morse Code',
    modes: ['MORSE'],
    description: 'Symbol encoding with configurable dot/dash and delimiters (educational).',
    security: 'Low',
    speed: 'Fast',
    blockSize: 'N/A (symbol encoding)',
    keyLengths: 'No key (delimiters only)',
    ivSize: 'None',
    parallelizable: 'Yes',
    color: '#22c55e'
  }
  */
};

const MODE_RECOMMENDATIONS = {
  AES: {
    CBC: 'Secure with random IV',
    CFB: 'Good for streaming data',
    OFB: 'Stream cipher mode',
    CTR: 'Parallelizable, excellent performance',
    GCM: 'Authenticated encryption - highly recommended',
    ECB: 'Insecure - exposes patterns'
  },
  '3DES': {
    CBC: 'Acceptable for legacy systems',
    CFB: 'Stream-like but slow',
    OFB: 'Output feedback mode',
    CTR: 'Better than CBC but still deprecated',
    ECB: 'Very insecure - pattern leakage'
  },
  BLOWFISH: {
    CBC: 'Good performance, limited block size',
    CFB: 'Stream mode with 64-bit blocks',
    OFB: 'Feedback mode',
    CTR: 'Counter mode, better parallelization',
    ECB: 'Insecure - avoid pattern exposure'
  },
  RC2: {
    CBC: 'Cryptographically weak algorithm',
    ECB: 'Extremely insecure - double vulnerability'
  },
  SM4: {
    CBC: 'Secure with random IV',
    CFB: 'Stream-like mode',
    OFB: 'Output feedback mode',
    CTR: 'Parallelizable counter mode',
    GCM: 'Authenticated encryption - recommended',
    ECB: 'Insecure - exposes patterns'
  },
  SALSA20: {
    STREAM: 'Use unique nonce per key; 20 rounds recommended'
  }
  /*
  , RAILFENCE: {
    RAILFENCE: 'Educational transposition cipher (not secure)'
  }
  , MORSE: {
    MORSE: 'Dot/dash symbol encoding (not secure)'
  }
  */
};

const DATA_SIZE_OPTIONS = [
  { value: 64, label: '64 bytes', category: 'Small' },
  { value: 256, label: '256 bytes', category: 'Small' },
  { value: 1024, label: '1 KB', category: 'Medium' },
  { value: 4096, label: '4 KB', category: 'Medium' },
  { value: 16384, label: '16 KB', category: 'Large' },
  { value: 65536, label: '64 KB', category: 'Large' },
  { value: 262144, label: '256 KB', category: 'XL' },
  { value: 1048576, label: '1 MB', category: 'XL' }
];

const ITERATION_OPTIONS = [
  { value: 5, label: '5 iterations', time: 'Quick' },
  { value: 10, label: '10 iterations', time: 'Standard' },
  { value: 25, label: '25 iterations', time: 'Detailed' },
  { value: 50, label: '50 iterations', time: 'Thorough' },
  { value: 100, label: '100 iterations', time: 'Comprehensive' }
];

const ALGORITHM_LABELS = {
  'SALSA20': 'Salsa20',
  'CHACHA20': 'ChaCha20'
  /*
  , 'RAILFENCE': 'Rail Fence'
  , 'MORSE': 'Morse Code'
  */
};

const RANDOM_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';

const generateRandomData = (size) => {
  let result = '';
  for (let i = 0; i < size; i++) {
    result += RANDOM_CHARS.charAt(Math.floor(Math.random() * RANDOM_CHARS.length));
  }
  return result;
};

const getModeRecommendation = (algorithm, mode) => {
  return MODE_RECOMMENDATIONS[algorithm]?.[mode] || 'Unknown combination';
};
const BenchmarkPage = () => {
  // State for algorithm-mode selections (array of objects with algorithm and mode)
  const [algorithmSelections, setAlgorithmSelections] = useState([
    { id: 1, algorithm: 'AES', mode: 'CBC' }
  ]);
  const [testDataOption, setTestDataOption] = useState('custom');
  const [customTestData, setCustomTestData] = useState('Hello World! This is a test message for benchmarking cryptographic algorithms.');
  const [randomDataSize, setRandomDataSize] = useState(1024);
  const [uploadedFile, setUploadedFile] = useState(null);
  const [uploadedFileContent, setUploadedFileContent] = useState('');
  const [iterations, setIterations] = useState(10);
  const [isRunning, setIsRunning] = useState(false);
  const [results, setResults] = useState(null);
  const [benchmarkHistory, setBenchmarkHistory] = useState([]);
  const [scoringModel, setScoringModel] = useState('general');
  const [powerWatts, setPowerWatts] = useState(1);
  const getTestData = () => {
    switch (testDataOption) {
      case 'random':
        return generateRandomData(randomDataSize);
      case 'file':
        return uploadedFileContent;
      case 'custom':
      default:
        return customTestData;
    }
  };

  const formatMemory = (mb) => {
    if (mb === null || mb === undefined || isNaN(mb)) return 'N/A';
    const kb = mb * 1024;
    return `${kb.toFixed(kb >= 10 ? 2 : 3)} KB`;
  };

  const formatAlgorithmName = (alg) => {
    if (!alg) return '';
    return ALGORITHM_LABELS[alg] || alg;
  };
  // Handle file upload and read as text
  const handleFileChange = (e) => {
    const file = e.target.files[0];
    setUploadedFile(file);
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        setUploadedFileContent(event.target.result);
      };
      reader.readAsText(file);
    } else {
      setUploadedFileContent('');
    }
  };
  const addAlgorithmSelection = () => {
    const newId = Math.max(...algorithmSelections.map(a => a.id)) + 1;
    const usedCombinations = new Set(algorithmSelections.map(selection => `${selection.algorithm}-${selection.mode}`));
    // Find first available algorithm-mode combination
    let newAlgorithm = 'AES';
    let newMode = 'CBC';
    for (const [alg, algInfo] of Object.entries(ALGORITHMS)) {
      for (const mode of algInfo.modes) {
        const combination = `${alg}-${mode}`;
        if (!usedCombinations.has(combination)) {
          newAlgorithm = alg;
          newMode = mode;
          break;
        }
      }
      if (newAlgorithm !== 'AES' || newMode !== 'CBC') break;
    }
    setAlgorithmSelections([...algorithmSelections, { id: newId, algorithm: newAlgorithm, mode: newMode }]);
  };
  const removeAlgorithmSelection = (id) => {
    if (algorithmSelections.length > 1) {
      setAlgorithmSelections(algorithmSelections.filter(a => a.id !== id));
    }
  };
  const updateAlgorithmSelection = (id, field, value) => {
    setAlgorithmSelections(algorithmSelections.map(selection => {
      if (selection.id === id) {
        const updated = { ...selection, [field]: value };
        // Handle algorithm change
        if (field === 'algorithm') {
          // Reset mode if current mode not supported by new algorithm
          if (!ALGORITHMS[value].modes.includes(selection.mode)) {
            // Find first available mode for this algorithm
            const availableModes = ALGORITHMS[value].modes.filter(mode => {
              const wouldBeDuplicate = algorithmSelections.some(other =>
                other.id !== id && other.algorithm === value && other.mode === mode
              );
              return !wouldBeDuplicate;
            });
            updated.mode = availableModes[0] || ALGORITHMS[value].modes[0];
          } else {
            // Check if current mode would create duplicate
            const wouldBeDuplicate = algorithmSelections.some(other =>
              other.id !== id && other.algorithm === value && other.mode === selection.mode
            );
            if (wouldBeDuplicate) {
              const availableModes = ALGORITHMS[value].modes.filter(mode => {
                const isDuplicate = algorithmSelections.some(other =>
                  other.id !== id && other.algorithm === value && other.mode === mode
                );
                return !isDuplicate;
              });
              updated.mode = availableModes[0] || ALGORITHMS[value].modes[0];
            }
          }
        }
        // Handle mode change - check for duplicates
        if (field === 'mode') {
          const wouldBeDuplicate = algorithmSelections.some(other =>
            other.id !== id && other.algorithm === selection.algorithm && other.mode === value
          );
          if (wouldBeDuplicate) {
            // Don't allow the change
            return selection;
          }
          updated.mode = value;
        }
        return updated;
      }
      return selection;
    }));
  };
  const chartData = useMemo(() => {
    try {
      if (!results || !Array.isArray(results)) return [];
      const successfulResults = results.filter(r => !r.error);
      if (successfulResults.length === 0) return [];
      return successfulResults.map(result => {
        // Safely access nested properties with fallbacks
        const encryptionTime = result.time?.encryption?.avgMs || 0;
        const decryptionTime = result.time?.decryption?.avgMs || 0;
        const totalTime = result.time?.summary?.totalAvgMs || (encryptionTime + decryptionTime);
        return {
          name: (result.combinationName || 'Unknown').replace('-', '\n'),
          encryptionTime: Number(encryptionTime) || 0,
          decryptionTime: Number(decryptionTime) || 0,
          totalTime: Number(totalTime) || 0,
          encryptionThroughput: Number(result.throughput?.encryption?.MBps) || 0,
          decryptionThroughput: Number(result.throughput?.decryption?.MBps) || 0,
          avgThroughput: Number(result.throughput?.summary?.avgMBps) || 0,
          encryptionMemory: Number(result.memory?.encryption?.avgMB) || 0,
          decryptionMemory: Number(result.memory?.decryption?.avgMB) || 0,
          efficiencyScore: Number(result.memory?.summary?.efficiencyScore) || 0,
          color: ALGORITHMS[result.algorithm]?.color || '#6b7280'
        };
      });
    } catch (error) {
      console.error('Error generating chart data:', error);
      return [];
    }
  }, [results]);

  const runBenchmark = useCallback(async () => {
    // Prevent multiple simultaneous benchmark runs
    if (isRunning) {
      console.warn('Benchmark already running, ignoring duplicate request');
      return;
    }
    setIsRunning(true);
    setResults(null);
    try {
      console.log('Starting benchmark with selections:', algorithmSelections);
      if (!algorithmSelections || algorithmSelections.length === 0) {
        throw new Error('No algorithms selected for benchmarking');
      }
      const testData = getTestData();
      console.log('Test data prepared:', testData?.length, 'bytes');
      const benchmarkResults = [];
      // Run benchmark for each selected algorithm-mode combination
      for (let i = 0; i < algorithmSelections.length; i++) {
        const selection = algorithmSelections[i];
        const combinationName = `${selection.algorithm}-${selection.mode}`;
        console.log(`Running benchmark ${i + 1}/${algorithmSelections.length}: ${combinationName}`);
        try {
          // Add timeout to prevent hanging requests
          const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Request timeout after 30 seconds')), 30000)
          );
          const benchmarkPromise = cryptoAPI.benchmark({
            algorithm: selection.algorithm,
            mode: selection.mode,
            testData: testData,
            iterations: iterations,
            scoringModel: scoringModel,
            powerConsumption: powerWatts
          });
          const response = await Promise.race([benchmarkPromise, timeoutPromise]);
          console.log(`Benchmark response for ${combinationName}:`, response);
          if (response && response.success && response.result) {
            const result = response.result;
            console.log(`Success result for ${combinationName}:`, result);
            benchmarkResults.push({
              combinationId: `${selection.algorithm}-${selection.mode}`,
              combinationName: combinationName,
              algorithm: selection.algorithm,
              mode: selection.mode,
              ...result,
              color: ALGORITHMS[selection.algorithm]?.color || '#6b7280'
            });
          } else {
            const errorMsg = response?.error || 'Unknown error occurred';
            console.error(`Benchmark failed for ${combinationName}:`, errorMsg);
            benchmarkResults.push({
              combinationId: `${selection.algorithm}-${selection.mode}`,
              combinationName: combinationName,
              algorithm: selection.algorithm,
              mode: selection.mode,
              error: errorMsg,
              color: ALGORITHMS[selection.algorithm]?.color || '#6b7280'
            });
          }
        } catch (error) {
          console.error(`Exception during benchmark for ${combinationName}:`, error);
          benchmarkResults.push({
            combinationId: `${selection.algorithm}-${selection.mode}`,
            combinationName: combinationName,
            algorithm: selection.algorithm,
            mode: selection.mode,
            error: error.message || 'Network or processing error',
            color: ALGORITHMS[selection.algorithm]?.color || '#6b7280'
          });
        }
      }
      console.log('Final benchmark results:', benchmarkResults);
      // Ensure we have valid results before setting
      if (benchmarkResults.length > 0) {
      setResults(benchmarkResults);
        // Update history if we have successful results
      const successfulResults = benchmarkResults.filter(r => !r.error);
      if (successfulResults.length > 0) {
          const avgEncryption = successfulResults.reduce((sum, r) => sum + Number(r.time?.encryption?.avgMs || 0), 0) / successfulResults.length;
          const avgDecryption = successfulResults.reduce((sum, r) => sum + Number(r.time?.decryption?.avgMs || 0), 0) / successfulResults.length;
          setBenchmarkHistory(prev => [...prev, {
            timestamp: new Date().toLocaleTimeString(),
            encryption: avgEncryption,
            decryption: avgDecryption
          }].slice(-10)); // Keep only last 10 entries
        }
      } else {
        throw new Error('No benchmark results generated');
      }
    } catch (error) {
      console.error('Benchmark error:', error);
      setResults([{
        combinationId: 'error',
        combinationName: 'Error',
        algorithm: 'Error',
        mode: 'Error',
        error: error.message || 'Failed to run benchmark',
        color: '#ef4444'
      }]);
    } finally {
      setIsRunning(false);
    }
  }, [algorithmSelections, iterations, testDataOption, customTestData, randomDataSize]);
  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };
  const getSecurityBadgeColor = (security) => {
    switch (security) {
      case 'High': return 'bg-green-100 text-green-800 border-green-200';
      case 'High (20 rounds)': return 'bg-green-100 text-green-800 border-green-200';
      case 'Medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'Low': return 'bg-red-100 text-red-800 border-red-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };
  const getSpeedBadgeColor = (speed) => {
    switch (speed) {
      case 'Very Fast': return 'bg-emerald-100 text-emerald-800 border-emerald-200';
      case 'Extremely Fast': return 'bg-emerald-100 text-emerald-800 border-emerald-200';
      case 'Fast': return 'bg-blue-100 text-blue-800 border-blue-200';
      case 'Medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'Slow': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'Very Slow': return 'bg-red-100 text-red-800 border-red-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };
  const getRecommendationColor = (recommendation) => {
    if (recommendation.includes('🟢')) return 'text-green-600';
    if (recommendation.includes('🔴')) return 'text-red-600';
    if (recommendation.includes('🟡')) return 'text-amber-600';
    if (recommendation.includes('❓')) return 'text-gray-600';
    return 'text-gray-600';
  };
  // Check if algorithm-mode combination is already selected
  const isCombinationUsed = (algorithm, mode, excludeId = null) => {
    return algorithmSelections.some(selection =>
      selection.id !== excludeId &&
      selection.algorithm === algorithm &&
      selection.mode === mode
    );
  };
  // Get available modes for an algorithm (excluding already used combinations)
  const getAvailableModes = (algorithm, currentId) => {
    return ALGORITHMS[algorithm]?.modes.filter(mode =>
      !isCombinationUsed(algorithm, mode, currentId)
    ) || [];
  };
  // Check if we can add more algorithm selections (maximum 5)
  const canAddMoreSelections = () => {
    const totalPossibleCombinations = Object.entries(ALGORITHMS).reduce((total, [alg, algInfo]) => {
      return total + algInfo.modes.length;
    }, 0);
    return algorithmSelections.length < Math.min(5, totalPossibleCombinations);
  };
return (
    <div className="h-screen flex flex-col bg-white overflow-hidden">
      {/* Header Section */}
      <div className="bg-white border-b border-gray-200">
        <div className="w-full px-6 py-6 border-b border-gray-100">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                <BarChart3 className="w-5 h-5 text-white" />
      </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Algorithm Benchmark</h1>
                <p className="text-gray-600 text-sm">Compare encryption performance and analyze cryptographic algorithms</p>
              </div>
            </div>
            <div className="hidden md:flex items-center space-x-4 text-sm text-gray-500">
              <div className="flex items-center space-x-1">
                <Shield className="w-4 h-4" />
                <span>Security Analysis</span>
              </div>
              <div className="flex items-center space-x-1">
                <Timer className="w-4 h-4" />
                <span>Performance Testing</span>
              </div>
            </div>
              </div>
            </div>
          </div>
      <main className="w-full flex-1 overflow-auto">
        {/* Results Section - Show at top when available */}
        {results && Array.isArray(results) && results.length > 0 && !isRunning && (
          <div className="bg-white border-b border-gray-200">
            {/* Results Header with Clear Button */}
            <div className="px-6 py-4 border-b border-gray-200 bg-gradient-to-r from-blue-50 to-purple-50">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                    <BarChart3 className="w-5 h-5 text-white" />
                  </div>
              <div>
                    <h2 className="text-xl font-bold text-gray-900">Benchmark Results</h2>
                    <p className="text-sm text-gray-600">
                      {results.filter(r => !r.error).length} of {results.length} tests completed successfully
                </p>
              </div>
                </div>
                <button
                  onClick={() => setResults(null)}
                  className="flex items-center space-x-2 px-4 py-2 text-sm font-medium text-gray-600 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 hover:text-gray-800 transition-colors"
                >
                  <X className="w-4 h-4" />
                  <span>Clear Results</span>
                </button>
              </div>
          </div>
            {/* Debug Info */}
            <div className="px-6 py-2 border-b border-gray-200 bg-gray-100">
              <details className="text-xs text-gray-600">
                <summary className="cursor-pointer hover:text-gray-800">🔍 Debug Info (Click to expand)</summary>
                <div className="mt-2 bg-gray-200 p-3 rounded text-xs">
                  <div className="space-y-2">
                    <div><strong>Results Count:</strong> {results.length}</div>
                    <div><strong>Chart Data Count:</strong> {chartData.length}</div>
                    <div><strong>Successful Results:</strong> {results.filter(r => !r.error).length}</div>
                    <div><strong>Failed Results:</strong> {results.filter(r => r.error).length}</div>
                    <div><strong>Average Efficiency:</strong> {results.filter(r => !r.error).length > 0 ?
                      (results.filter(r => !r.error).reduce((sum, r) => sum + (r.memory?.summary?.efficiencyScore || 0), 0) / results.filter(r => !r.error).length).toFixed(1)
                      : 'N/A'}/100</div>
                    {results.length > 0 && (
                      <details>
                        <summary className="cursor-pointer text-blue-600">View First Result</summary>
                        <pre className="mt-1 text-xs overflow-x-auto bg-white p-2 rounded border">
                          {JSON.stringify(results[0], null, 2)}
                        </pre>
                      </details>
                    )}
                    {chartData.length > 0 && (
                      <details>
                        <summary className="cursor-pointer text-blue-600">View Chart Data</summary>
                        <pre className="mt-1 text-xs overflow-x-auto bg-white p-2 rounded border">
                          {JSON.stringify(chartData, null, 2)}
                        </pre>
                      </details>
                    )}
          </div>
                </div>
              </details>
        </div>
            {/* Performance Summary Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 border-b border-gray-200">
              {/* Fastest Algorithm */}
              <div className="bg-green-50 p-6 border-r border-gray-200">
                <div className="flex items-center space-x-3 mb-3">
                  <div className="w-10 h-10 bg-green-100 rounded-full flex items-center justify-center">
                    <Zap className="w-5 h-5 text-green-600" />
                </div>
                  <div>
                    <h3 className="text-sm font-medium text-green-900">Fastest</h3>
                    <p className="text-xs text-green-600">Total Time</p>
                  </div>
                </div>
                <div className="text-xl font-bold text-green-900">
                  {(() => {
                    const fastest = results.filter(r => !r.error).sort((a, b) =>
                      (a.time?.summary?.totalAvgMs || 0) - (b.time?.summary?.totalAvgMs || 0)
                    )[0];
                    return fastest ? fastest.combinationName : 'N/A';
                  })()}
                </div>
                <div className="text-sm text-green-700 mt-1">
                  {(() => {
                    const fastest = results.filter(r => !r.error).sort((a, b) =>
                      (a.time?.summary?.totalAvgMs || 0) - (b.time?.summary?.totalAvgMs || 0)
                    )[0];
                    return fastest ? `${(fastest.time?.summary?.totalAvgMs || 0).toFixed(2)}ms` : 'N/A';
                  })()}
                </div>
              </div>
              {/* Highest Throughput */}
              <div className="bg-blue-50 p-6 border-r border-gray-200">
                <div className="flex items-center space-x-3 mb-3">
                  <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
                    <TrendingUp className="w-5 h-5 text-blue-600" />
                </div>
                  <div>
                    <h3 className="text-sm font-medium text-blue-900">Highest Throughput</h3>
                    <p className="text-xs text-blue-600">MB/second</p>
                  </div>
                </div>
                <div className="text-xl font-bold text-blue-900">
                  {(() => {
                    const highest = results.filter(r => !r.error).sort((a, b) =>
                      (b.throughput?.summary?.avgMBps || 0) - (a.throughput?.summary?.avgMBps || 0)
                    )[0];
                    return highest ? highest.combinationName : 'N/A';
                  })()}
                </div>
                <div className="text-sm text-blue-700 mt-1">
                  {(() => {
                    const highest = results.filter(r => !r.error).sort((a, b) =>
                      (b.throughput?.summary?.avgMBps || 0) - (a.throughput?.summary?.avgMBps || 0)
                    )[0];
                    return highest ? `${(highest.throughput?.summary?.avgMBps || 0).toFixed(2)} MB/s` : 'N/A';
                  })()}
                </div>
              </div>
              {/* Most Memory Efficient */}
              <div className="bg-purple-50 p-6 border-r border-gray-200">
                <div className="flex items-center space-x-3 mb-3">
                  <div className="w-10 h-10 bg-purple-100 rounded-full flex items-center justify-center">
                    <Database className="w-5 h-5 text-purple-600" />
                </div>
                  <div>
                    <h3 className="text-sm font-medium text-purple-900">Most Efficient</h3>
                    <p className="text-xs text-purple-600">Memory Usage</p>
                  </div>
                </div>
                <div className="text-xl font-bold text-purple-900">
                  {(() => {
                    const bestMemory = results.filter(r => !r.error).sort((a, b) =>
                      (a.memory?.summary?.totalAvgMB || Infinity) - (b.memory?.summary?.totalAvgMB || Infinity)
                    )[0];
                    return bestMemory ? bestMemory.combinationName : 'N/A';
                  })()}
                </div>
                <div className="text-sm text-purple-700 mt-1">
                  {(() => {
                    const bestMemory = results.filter(r => !r.error).sort((a, b) =>
                      (a.memory?.summary?.totalAvgMB || Infinity) - (b.memory?.summary?.totalAvgMB || Infinity)
                    )[0];
                    return bestMemory ? formatMemory(bestMemory.memory?.summary?.totalAvgMB || 0) : 'N/A';
                  })()}
                </div>
              </div>
              {/* Highest Efficiency Score */}
              <div className="bg-amber-50 p-6">
                <div className="flex items-center space-x-3 mb-3">
                  <div className="w-10 h-10 bg-amber-100 rounded-full flex items-center justify-center">
                    <Target className="w-5 h-5 text-amber-600" />
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-amber-900">Highest Efficiency</h3>
                    <p className="text-xs text-amber-600">Overall Performance</p>
                  </div>
                </div>
                <div className="text-xl font-bold text-amber-900">
                  {(() => {
                    const bestEfficiency = results.filter(r => !r.error).sort((a, b) =>
                      (b.memory?.summary?.efficiencyScore || 0) - (a.memory?.summary?.efficiencyScore || 0)
                    )[0];
                    return bestEfficiency ? `${bestEfficiency.combinationName}` : 'N/A';
                  })()}
                </div>
                <div className="text-sm text-amber-700 mt-1">
                  {(() => {
                    const bestEfficiency = results.filter(r => !r.error).sort((a, b) =>
                      (b.memory?.summary?.efficiencyScore || 0) - (a.memory?.summary?.efficiencyScore || 0)
                    )[0];
                    return bestEfficiency ? `${(bestEfficiency.memory?.summary?.efficiencyScore || 0).toFixed(1)}/100` : 'N/A';
                  })()}
                </div>
                </div>
              </div>
            {/* Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-4 border-b border-gray-200">
              {/* Time Performance Chart */}
              <div className="p-6 border-r border-gray-200">
                <div className="flex items-center space-x-2 mb-4">
                  <Clock className="w-5 h-5 text-gray-600" />
                  <h3 className="text-lg font-semibold text-gray-900">Time Performance</h3>
                </div>
                                  <div className="h-64">
                    {chartData.length > 0 ? (
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={chartData} margin={{ top: 20, right: 30, left: 20, bottom: 40 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                          <XAxis
                            dataKey="name"
                            tick={{ fontSize: 12 }}
                            interval={0}
                            textAnchor="middle"
                            height={50}
                          />
                          <YAxis tick={{ fontSize: 12 }} />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#f8fafc',
                              border: '1px solid #e2e8f0',
                              borderRadius: '8px'
                            }}
                            formatter={(value, name) => [
                              `${Number(value).toFixed(2)}ms`,
                              name === 'encryptionTime' ? 'Encryption' : name === 'decryptionTime' ? 'Decryption' : name
                            ]}
                          />
                          <Bar dataKey="encryptionTime" fill="#10b981" name="Encryption" />
                          <Bar dataKey="decryptionTime" fill="#3b82f6" name="Decryption" />
                        </BarChart>
                      </ResponsiveContainer>
                    ) : (
                      <div className="flex items-center justify-center h-full text-gray-500">
                        <div className="text-center">
                          <AlertCircle className="w-8 h-8 mx-auto mb-2" />
                          <p>No data available for chart</p>
                </div>
                </div>
                    )}
              </div>
            </div>
              {/* Throughput Chart */}
              <div className="p-6 border-r border-gray-200">
                <div className="flex items-center space-x-2 mb-4">
                  <Activity className="w-5 h-5 text-gray-600" />
                  <h3 className="text-lg font-semibold text-gray-900">Throughput</h3>
                </div>
                  <div className="h-64">
                    {chartData.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={chartData} margin={{ top: 20, right: 30, left: 20, bottom: 40 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                        <XAxis
                          dataKey="name"
                            tick={{ fontSize: 12 }}
                          interval={0}
                            textAnchor="middle"
                            height={50}
                          />
                          <YAxis tick={{ fontSize: 12 }} />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#f8fafc',
                              border: '1px solid #e2e8f0',
                              borderRadius: '8px'
                            }}
                            formatter={(value) => [`${Number(value).toFixed(2)} MB/s`, 'Throughput']}
                          />
                          <Bar dataKey="avgThroughput" fill="#8b5cf6" />
                      </BarChart>
                    </ResponsiveContainer>
                    ) : (
                      <div className="flex items-center justify-center h-full text-gray-500">
                        <div className="text-center">
                          <AlertCircle className="w-8 h-8 mx-auto mb-2" />
                          <p>No data available for chart</p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              {/* Memory Usage Chart */}
              <div className="p-6 border-r border-gray-200">
                <div className="flex items-center space-x-2 mb-4">
                  <Database className="w-5 h-5 text-gray-600" />
                  <h3 className="text-lg font-semibold text-gray-900">Memory Usage</h3>
                </div>
                  <div className="h-64">
                    {chartData.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={chartData} margin={{ top: 20, right: 30, left: 20, bottom: 40 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                        <XAxis
                          dataKey="name"
                            tick={{ fontSize: 12 }}
                          interval={0}
                            textAnchor="middle"
                            height={50}
                          />
                          <YAxis tick={{ fontSize: 12 }} />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#f8fafc',
                              border: '1px solid #e2e8f0',
                              borderRadius: '8px'
                            }}
                            formatter={(value, name) => [
                              formatMemory(Number(value)),
                              name === 'encryptionMemory' ? 'Encryption' : name === 'decryptionMemory' ? 'Decryption' : name
                            ]}
                          />
                          <Bar dataKey="encryptionMemory" fill="#f59e0b" name="Encryption" />
                          <Bar dataKey="decryptionMemory" fill="#ef4444" name="Decryption" />
                      </BarChart>
                    </ResponsiveContainer>
                    ) : (
                      <div className="flex items-center justify-center h-full text-gray-500">
                        <div className="text-center">
                          <AlertCircle className="w-8 h-8 mx-auto mb-2" />
                          <p>No data available for chart</p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              {/* Efficiency Score Chart */}
              <div className="p-6">
                <div className="flex items-center space-x-2 mb-4">
                  <Target className="w-5 h-5 text-gray-600" />
                  <h3 className="text-lg font-semibold text-gray-900">Efficiency Score</h3>
                </div>
                  <div className="h-64">
                    {chartData.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={results.filter(r => !r.error).map(result => ({
                          name: (result.combinationName || 'Unknown').replace('-', '\n'),
                          efficiencyScore: Number(result.memory?.summary?.efficiencyScore) || 0,
                          color: result.color
                        }))} margin={{ top: 20, right: 30, left: 20, bottom: 40 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                        <XAxis
                          dataKey="name"
                            tick={{ fontSize: 12 }}
                          interval={0}
                            textAnchor="middle"
                            height={50}
                        />
                        <YAxis
                            tick={{ fontSize: 12 }}
                            domain={[0, 100]}
                          />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#f8fafc',
                              border: '1px solid #e2e8f0',
                              borderRadius: '8px'
                            }}
                            formatter={(value) => [`${Number(value).toFixed(1)}/100`, 'Efficiency Score']}
                          />
                          <Bar dataKey="efficiencyScore" fill="#f59e0b" name="Efficiency" />
                      </BarChart>
                    </ResponsiveContainer>
                    ) : (
                      <div className="flex items-center justify-center h-full text-gray-500">
                        <div className="text-center">
                          <AlertCircle className="w-8 h-8 mx-auto mb-2" />
                          <p>No data available for chart</p>
                </div>
              </div>
            )}
                  </div>
              </div>
            </div>
            {/* Results Table */}
            <div className="overflow-x-auto border-b border-gray-200">
              <table className="w-full">
                  <thead className="bg-gray-50">
                    <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Algorithm</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Mode</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Encryption Time</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Decryption Time</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Throughput</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Memory Usage</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Efficiency Score</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {results.map((result, index) => (
                    <tr key={result.combinationId || index} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center space-x-3">
                          <div
                            className="w-3 h-3 rounded-full border-2 border-white shadow-sm"
                            style={{ backgroundColor: result.color }}
                          ></div>
                          <span className="text-sm font-medium text-gray-900">{formatAlgorithmName(result.algorithm)}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="px-2 py-1 text-xs font-medium bg-gray-100 text-gray-800 rounded-full">
                          {result.mode}
                        </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {result.error ? '—' : `${(result.time?.encryption?.avgMs || 0).toFixed(2)}ms`}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {result.error ? '—' : `${(result.time?.decryption?.avgMs || 0).toFixed(2)}ms`}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {result.error ? '—' : `${(result.throughput?.summary?.avgMBps || 0).toFixed(2)} MB/s`}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {result.error ? '—' : formatMemory(result.memory?.summary?.totalAvgMB || 0)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {result.error ? (
                          <span className="text-gray-400">—</span>
                        ) : (
                          <div className="flex items-center space-x-2">
                            <div className={`px-2 py-1 text-xs font-medium rounded-full ${
                              (result.memory?.summary?.efficiencyScore || 0) >= 90 ? 'bg-green-100 text-green-800' :
                              (result.memory?.summary?.efficiencyScore || 0) >= 75 ? 'bg-blue-100 text-blue-800' :
                              (result.memory?.summary?.efficiencyScore || 0) >= 60 ? 'bg-yellow-100 text-yellow-800' :
                              'bg-red-100 text-red-800'
                            }`}>
                              {(result.memory?.summary?.efficiencyScore || 0).toFixed(1)}/100
                            </div>
                              <div className="text-xs text-gray-500">
                              {(result.memory?.summary?.efficiencyScore || 0) >= 90 ? 'Excellent' :
                               (result.memory?.summary?.efficiencyScore || 0) >= 75 ? 'Good' :
                               (result.memory?.summary?.efficiencyScore || 0) >= 60 ? 'Average' : 'Poor'}
                              </div>
                            </div>
                          )}
                        </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {result.error ? (
                          <div className="flex items-center space-x-2">
                            <AlertCircle className="w-4 h-4 text-red-500" />
                            <span className="text-xs text-red-600">Failed</span>
                              </div>
                        ) : (
                          <div className="flex items-center space-x-2">
                            <CheckCircle className="w-4 h-4 text-green-500" />
                            <span className="text-xs text-green-600">Success</span>
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
        )}
        {/* Configuration Panel */}
        <div className="grid grid-cols-1 lg:grid-cols-4">
          {/* Algorithm Selection with Dropdowns */}
          <div className="lg:col-span-3 border-r border-gray-200">
            <div className="bg-white">
              <div className={`px-6 py-4 border-b border-gray-200 ${results && results.length > 0 ? 'bg-yellow-50' : 'bg-gray-50'}`}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <Shield className={`w-5 h-5 ${results && results.length > 0 ? 'text-yellow-600' : 'text-blue-600'}`} />
                    <h2 className="text-lg font-semibold text-gray-900">Algorithm Selection</h2>
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                      results && results.length > 0
                        ? 'bg-yellow-100 text-yellow-800'
                        : 'bg-blue-100 text-blue-800'
                    }`}>
                      {algorithmSelections.length} of {Math.min(5, Object.entries(ALGORITHMS).reduce((total, [alg, algInfo]) => total + algInfo.modes.length, 0))} algorithms
                    </span>
                    {results && results.length > 0 && (
                      <span className="px-2 py-1 text-xs font-medium bg-amber-100 text-amber-800 rounded-full">
                        Configure for next test
                      </span>
                    )}
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={addAlgorithmSelection}
                      disabled={!canAddMoreSelections()}
                      className={`flex items-center space-x-2 px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
                        canAddMoreSelections()
                          ? 'text-blue-600 bg-blue-50 hover:bg-blue-100'
                          : 'text-gray-400 bg-gray-50 cursor-not-allowed'
                      }`}
                    >
                      <Plus className="w-4 h-4" />
                      <span>Add Algorithm</span>
                    </button>
                    <button
                      onClick={runBenchmark}
                      disabled={isRunning || algorithmSelections.length === 0}
                      className={`flex items-center space-x-2 px-4 py-2 text-sm font-semibold rounded-lg shadow-sm transition-colors ${
                        isRunning || algorithmSelections.length === 0
                          ? 'bg-gray-400 text-white cursor-not-allowed'
                          : 'bg-blue-600 text-white hover:bg-blue-700'
                      }`}
                    >
                      <Play className="w-4 h-4" />
                      <span>Run Benchmark</span>
                    </button>
                  </div>
                </div>
                <p className={`text-sm mt-1 ${results && results.length > 0 ? 'text-yellow-700' : 'text-gray-600'}`}>
                  {results && results.length > 0
                    ? 'Modify algorithm selection for your next benchmark test'
                    : 'Choose algorithms and modes to benchmark (no duplicate combinations allowed)'
                  }
                </p>
                {!canAddMoreSelections() && (
                  <div className="mt-2 text-xs text-amber-600 bg-amber-50 px-3 py-2 rounded-lg flex items-center space-x-2">
                    <Info className="w-4 h-4 flex-shrink-0" />
                    <span>{algorithmSelections.length >= 5 ? 'Maximum 5 algorithms reached' : 'All algorithm-mode combinations are selected'}</span>
          </div>
        )}
              </div>
              <div className="p-6">
                {algorithmSelections.map((selection, index) => (
                  <div key={selection.id} className="flex items-center space-x-4 p-4 border-b border-gray-100 last:border-b-0">
                    {/* Number */}
                    <div className="flex-shrink-0 w-8 h-8 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center text-sm font-semibold">
                      {index + 1}
                    </div>
                    {/* Algorithm Dropdown */}
                    <div className="flex-1">
                      <label className="block text-xs font-medium text-gray-700 mb-1">Algorithm</label>
                      <div className="relative">
                <select
                          value={selection.algorithm}
                          onChange={(e) => updateAlgorithmSelection(selection.id, 'algorithm', e.target.value)}
                          className="w-full appearance-none bg-white border border-gray-300 px-3 py-2 pr-8 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        >
                          {Object.entries(ALGORITHMS).map(([key, algo]) => {
                            const hasAvailableModes = algo.modes.some(mode =>
                              !isCombinationUsed(key, mode, selection.id)
                            );
                            return (
                              <option key={key} value={key} disabled={!hasAvailableModes && selection.algorithm !== key}>
                                {key} - {algo.name} {!hasAvailableModes && selection.algorithm !== key ? '(All modes used)' : ''}
                              </option>
                            );
                          })}
                </select>
                        <ChevronDown className="absolute right-2 top-2.5 h-4 w-4 text-gray-400 pointer-events-none" />
                      </div>
              </div>
                    {/* Mode Dropdown */}
                    <div className="flex-1">
                      <label className="block text-xs font-medium text-gray-700 mb-1">Mode</label>
                      <div className="relative">
                <select
                          value={selection.mode}
                          onChange={(e) => updateAlgorithmSelection(selection.id, 'mode', e.target.value)}
                          className="w-full appearance-none bg-white border border-gray-300 px-3 py-2 pr-8 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        >
                          {ALGORITHMS[selection.algorithm]?.modes.map((mode) => {
                            const isUsed = isCombinationUsed(selection.algorithm, mode, selection.id);
                            return (
                              <option key={mode} value={mode} disabled={isUsed}>
                                {mode} {isUsed ? '(Already selected)' : ''}
                    </option>
                            );
                          })}
                </select>
                        <ChevronDown className="absolute right-2 top-2.5 h-4 w-4 text-gray-400 pointer-events-none" />
                      </div>
                    </div>
                    {/* Algorithm Info */}
                    <div className="flex-1">
                      <div className="text-xs text-gray-600 mb-2">{ALGORITHMS[selection.algorithm]?.description}</div>
                      <div className="flex flex-wrap gap-1 mb-2">
                        <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getSecurityBadgeColor(ALGORITHMS[selection.algorithm]?.security)}`}>
                          {ALGORITHMS[selection.algorithm]?.security} Security
                        </span>
                        <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getSpeedBadgeColor(ALGORITHMS[selection.algorithm]?.speed)}`}>
                          {ALGORITHMS[selection.algorithm]?.speed}
                        </span>
                      </div>
                                            <div className="text-xs space-y-1">
                        <div><span className="font-medium">Block:</span> {ALGORITHMS[selection.algorithm]?.blockSize}</div>
                        <div><span className="font-medium">Keys:</span> {ALGORITHMS[selection.algorithm]?.keyLengths}</div>
                        <div><span className="font-medium">IV:</span> {ALGORITHMS[selection.algorithm]?.ivSize}</div>
                        <div className={`font-medium ${getRecommendationColor(getModeRecommendation(selection.algorithm, selection.mode))}`}>
                          {getModeRecommendation(selection.algorithm, selection.mode)}
                        </div>
                      </div>
          </div>
                    {/* Color Indicator */}
                    <div className="flex-shrink-0 flex flex-col items-center space-y-1">
                      <div
                        className="w-4 h-4 rounded-full border-2 border-white shadow-sm"
                        style={{ backgroundColor: ALGORITHMS[selection.algorithm]?.color }}
                      ></div>
                      <CheckCircle className="w-3 h-3 text-green-500" />
                    </div>
                    {/* Remove Button */}
                    <button
                      onClick={() => removeAlgorithmSelection(selection.id)}
                      disabled={algorithmSelections.length === 1}
                      className={`flex-shrink-0 p-2 rounded-lg transition-colors ${
                        algorithmSelections.length === 1
                          ? 'text-gray-300 cursor-not-allowed'
                          : 'text-red-500 hover:bg-red-50'
                      }`}
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
          {/* Test Configuration */}
          <div>
          {/* Test Data Configuration */}
            <div className="bg-white">
              <div className="px-6 py-4 border-b border-gray-200 bg-gray-50">
            <div className="flex items-center space-x-3">
                  <FileText className="w-5 h-5 text-green-600" />
                  <h2 className="text-lg font-semibold text-gray-900">Test Data</h2>
                </div>
              </div>
              <div className="p-6 space-y-4">
                {/* Data Type Selection */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-3">Data Type</label>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <button
                      type="button"
                      onClick={() => setTestDataOption('custom')}
                      className={`flex items-center justify-center space-x-2 p-3 rounded-xl border transition-all duration-200 w-full ${
                      testDataOption === 'custom'
                        ? 'border-indigo-400 bg-gradient-to-r from-purple-500 to-indigo-500 text-white shadow'
                        : 'border-gray-200 bg-white hover:border-blue-400 hover:shadow-sm'
                    }`}
                    >
                      <Type className={`w-4 h-4 ${testDataOption === 'custom' ? 'text-white' : 'text-gray-500'}`} />
                      <span className={`text-sm font-medium ${testDataOption === 'custom' ? 'text-white' : 'text-gray-900'}`}>Custom Text</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setTestDataOption('random')}
                      className={`flex items-center justify-center space-x-2 p-3 rounded-xl border transition-all duration-200 w-full ${
                      testDataOption === 'random'
                        ? 'border-indigo-400 bg-gradient-to-r from-purple-500 to-indigo-500 text-white shadow'
                        : 'border-gray-200 bg-white hover:border-blue-400 hover:shadow-sm'
                    }`}
                    >
                      <Zap className={`w-4 h-4 ${testDataOption === 'random' ? 'text-white' : 'text-gray-500'}`} />
                      <span className={`text-sm font-medium ${testDataOption === 'random' ? 'text-white' : 'text-gray-900'}`}>Random Data</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setTestDataOption('file')}
                      className={`flex items-center justify-center space-x-2 p-3 rounded-xl border transition-all duration-200 w-full ${
                      testDataOption === 'file'
                        ? 'border-indigo-400 bg-gradient-to-r from-purple-500 to-indigo-500 text-white shadow'
                        : 'border-gray-200 bg-white hover:border-blue-400 hover:shadow-sm'
                    }`}
                    >
                      <FileText className={`w-4 h-4 ${testDataOption === 'file' ? 'text-white' : 'text-gray-500'}`} />
                      <span className={`text-sm font-medium ${testDataOption === 'file' ? 'text-white' : 'text-gray-900'}`}>File Upload</span>
                    </button>
                  </div>
                </div>
                {/* Custom Text Input */}
                {testDataOption === 'custom' && (
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-gray-700">Custom Text</span>
                      <span className="text-xs text-gray-500">{customTestData ? `${new Blob([customTestData]).size} bytes` : '0 bytes'}</span>
                    </div>
                    <textarea
                      value={customTestData}
                      onChange={(e) => setCustomTestData(e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none"
                      rows={4}
                      placeholder="Enter your test data..."
                    />
                  </div>
                )}
                {/* File Upload Input */}
                {testDataOption === 'file' && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Upload File
                    </label>
                    <input
                      type="file"
                      accept=".txt,.csv,.json,.bin,.log,.xml,.html,.md,.js,.py,.java,.c,.cpp,.h,.cs,.ts,.tsx,.jsx,.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.rtf,.yml,.yaml,.ini,.conf,.cfg,.bat,.sh,.go,.rs,.php,.rb,.swift,.kt,.scala,.pl,.sql,.db,.sqlite,.zip,.tar,.gz,.7z,.rar,.mp3,.wav,.mp4,.avi,.mov,.jpg,.jpeg,.png,.gif,.bmp,.svg,.webp,.ico"
                      onChange={handleFileChange}
                      className="w-full px-3 py-2 border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                    {uploadedFile && (
                      <div className="mt-2 text-xs text-gray-600">
                        <span className="font-medium">Selected:</span> {uploadedFile.name} ({uploadedFile.size} bytes)
                      </div>
                    )}
                    {uploadedFileContent && (
                      <div className="mt-2 text-xs text-gray-500">
                        <span className="font-medium">Preview:</span> {uploadedFileContent.slice(0, 200)}{uploadedFileContent.length > 200 ? '...' : ''}
                      </div>
                    )}
                  </div>
                )}
                {/* Random Data Size */}
                {testDataOption === 'random' && (
              <div>
                    <label className="block text-sm font-medium text-gray-700 mb-3">
                      Data Size: {formatBytes(randomDataSize)}
                    </label>
                    <div className="relative">
                <select
                  value={randomDataSize}
                  onChange={(e) => setRandomDataSize(parseInt(e.target.value))}
                        className="w-full appearance-none bg-white border border-gray-300 px-3 py-2 pr-8 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  {DATA_SIZE_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                            {option.label} ({option.category})
                    </option>
                  ))}
                </select>
                      <ChevronDown className="absolute right-2 top-2.5 h-4 w-4 text-gray-400 pointer-events-none" />
            </div>
          </div>
        )}
              </div>
          </div>
            {/* Iterations and Run */}
            <div className="bg-white border-t border-gray-200 p-4 space-y-4 rounded-lg shadow-sm">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Iterations ({iterations}x)
                  </label>
                  <div className="relative">
                    <select
                      value={iterations}
                      onChange={(e) => setIterations(parseInt(e.target.value))}
                      className="w-full appearance-none bg-white border border-gray-300 px-3 py-2 pr-8 rounded focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    >
                      {ITERATION_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label} ({option.time})
                        </option>
                      ))}
                    </select>
                    <ChevronDown className="absolute right-2 top-2.5 h-4 w-4 text-gray-400 pointer-events-none" />
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Scoring model
                  </label>
                  <div className="relative">
                    <select
                      value={scoringModel}
                      onChange={(e) => setScoringModel(e.target.value)}
                      className="w-full appearance-none bg-white border border-gray-300 px-3 py-2 pr-8 rounded focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    >
                      <option value="general">General-purpose (weighted)</option>
                      <option value="throughput">Throughput-weighted</option>
                      <option value="energy">Energy-aware</option>
                    </select>
                    <ChevronDown className="absolute right-2 top-2.5 h-4 w-4 text-gray-400 pointer-events-none" />
                  </div>
                  {scoringModel === 'energy' && (
                    <div className="mt-2">
                      <label className="block text-xs font-medium text-gray-600 mb-1">
                        Power (Watts)
                      </label>
                      <input
                        type="number"
                        min="0"
                        step="0.1"
                        value={powerWatts}
                        onChange={(e) => setPowerWatts(parseFloat(e.target.value) || 1)}
                        className="w-full border border-gray-300 rounded px-3 py-2 focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                      />
                    </div>
                  )}
                </div>
              </div>

              <p className="text-xs text-gray-500 bg-gray-50 border border-gray-200 rounded px-3 py-2">
                {scoringModel === 'general' && 'General-purpose blends time, memory, and throughput with balanced weights.'}
                {scoringModel === 'throughput' && 'Throughput-weighted favors raw MB/s relative to latency and memory.'}
                {scoringModel === 'energy' && 'Energy-aware prioritizes performance per watt and per watt per MB.'}
              </p>
            </div>
          </div>
        </div>
        {/* Loading State - Modal Overlay */}
        {isRunning && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-8 shadow-xl max-w-md mx-4">
              <div className="text-center">
                <div className="w-16 h-16 mx-auto mb-4 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                <h3 className="text-xl font-semibold text-gray-900 mb-2">Running Benchmark Suite</h3>
                <div className="space-y-2">
                  <p className="text-gray-700">
                    Testing {algorithmSelections.length} algorithm{algorithmSelections.length !== 1 ? 's' : ''} with {iterations} iterations each
                  </p>
                  <div className="mt-3 text-sm text-gray-600 bg-gray-50 p-3 rounded">
                    <p>⏱️ This may take 10-30 seconds per algorithm</p>
                    <p>🔒 Please do not close this tab</p>
                  </div>
                  <button
                    onClick={() => {
                      setIsRunning(false);
                      setResults(null);
                    }}
                    className="mt-4 px-4 py-2 text-sm text-red-600 hover:text-red-800 transition-colors border border-red-200 rounded"
                  >
                    Cancel Benchmark
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};
export default BenchmarkPage;

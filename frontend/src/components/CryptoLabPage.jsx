import React, { useState, useEffect } from 'react';
import { Shield, Zap } from 'lucide-react';
import ResizablePanel from './ResizablePanel';
import AlgorithmSelector from './AlgorithmSelector';
import { cryptoAPI } from '../services/api';

const spinnerCSS = `
html, body, #root {
  height: 100%;
  overflow: hidden;
}
.spinner {
  width: 48px;
  height: 48px;
  animation: spinner-rotate 1s linear infinite;
}
.spinner circle {
  fill: none;
  stroke: #3b82f6;
  stroke-width: 4;
  stroke-linecap: round;
  stroke-dasharray: 90 150;
  stroke-dashoffset: 0;
  animation: spinner-dash 1.5s ease-in-out infinite;
}
@keyframes spinner-rotate {
  100% { transform: rotate(360deg); }
}
@keyframes spinner-dash {
  0% { stroke-dasharray: 1, 200; stroke-dashoffset: 0; }
  50% { stroke-dasharray: 90, 150; stroke-dashoffset: -40px; }
  100% { stroke-dasharray: 90, 150; stroke-dashoffset: -120px; }
}
`;

// Vertical Resizable Panel Component
const VerticalResizablePanel = ({
  children,
  height,
  minHeight = 100,
  maxHeight = 800,
  onResize,
  className = "",
  ...props
}) => {
  const [isResizing, setIsResizing] = useState(false);
  const [startY, setStartY] = useState(0);
  const [startHeight, setStartHeight] = useState(height);

  const handleMouseDown = (e) => {
    setIsResizing(true);
    setStartY(e.clientY);
    setStartHeight(height);
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
  };

  const handleMouseMove = (e) => {
    if (!isResizing) return;

    const deltaY = e.clientY - startY;
    const newHeight = Math.max(minHeight, Math.min(maxHeight, startHeight + deltaY));

    if (onResize) {
      onResize(newHeight);
    }
  };

  const handleMouseUp = () => {
    setIsResizing(false);
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  };

  React.useEffect(() => {
    if (isResizing) {
      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);

      return () => {
        document.removeEventListener('mousemove', handleMouseMove);
        document.removeEventListener('mouseup', handleMouseUp);
      };
    }
  }, [isResizing, startY, startHeight]);

  return (
    <div
      className={`vertical-resizable-panel ${isResizing ? 'resizing' : ''} ${className}`}
      style={{ height: `${height}px` }}
      {...props}
    >
      {children}
      <div
        className="absolute bottom-0 left-0 w-full h-1 cursor-row-resize bg-transparent hover:bg-blue-400 transition-colors duration-200 z-10"
        onMouseDown={handleMouseDown}
      />
    </div>
  );
};

const CryptoLabPage = () => {
  const [tabs, setTabs] = useState([{ id: 1, name: 'Tab 1', inputText: '', inputFile: null, result: null }]);
  const [activeTabId, setActiveTabId] = useState(1);
  const [selectedAlgorithm, setSelectedAlgorithm] = useState('');
  const [selectedMode, setSelectedMode] = useState('CBC'); // All AES modes supported
  const [selectedKeySize, setSelectedKeySize] = useState(''); // AES: 128/192/256, Blowfish: 32-448
  const [inputFormat, setInputFormat] = useState('RAW');
  const [outputFormat, setOutputFormat] = useState('HEX');
  const [inputType, setInputType] = useState('text');
  const [customKey, setCustomKey] = useState('');
  const [customIV, setCustomIV] = useState('');
  const [salsaRounds, setSalsaRounds] = useState(20);
  const [salsaCounter, setSalsaCounter] = useState(0);
  const [chachaRounds, setChachaRounds] = useState(20);
  const [chachaCounter, setChachaCounter] = useState(0);
  const [operation, setOperation] = useState('encrypt');
  const [isLoading, setIsLoading] = useState(false);
  const [history, setHistory] = useState([]);
  
  // Panel width states - set better default widths for proper initial layout
  const [operationsWidth, setOperationsWidth] = useState(216); // 240 - 10% = 216
  const [benchmarkWidth, setBenchmarkWidth] = useState(506); // 460 + 10% = 506
  
  // Panel height states for input/output sections
  const [inputHeight, setInputHeight] = useState(400); // Make input panel much bigger than output

  const activeTab = tabs.find(tab => tab.id === activeTabId) || tabs[0];
  const inputText = activeTab?.inputText || '';
  const inputFile = activeTab?.inputFile || null;
  const result = activeTab?.result || null;

  const updateActiveTab = (updates) => {
    setTabs(prevTabs => prevTabs.map(tab => (
      tab.id === activeTabId ? { ...tab, ...updates } : tab
    )));
  };

  const handleAddTab = () => {
    setTabs(prevTabs => {
      const newId = prevTabs.length ? Math.max(...prevTabs.map(tab => tab.id)) + 1 : 1;
      const newTab = { id: newId, name: `Tab ${prevTabs.length + 1}`, inputText: '', inputFile: null, result: null };
      setActiveTabId(newId);
      return [...prevTabs, newTab];
    });
  };

  const setActiveInputText = (text) => updateActiveTab({ inputText: text });
  const setActiveInputFile = (file) => updateActiveTab({ inputFile: file });
  const setActiveResult = (value) => updateActiveTab({ result: value });

  const handleCloseTab = (tabId) => {
    setTabs(prevTabs => {
      if (prevTabs.length === 1) {
        // Keep at least one tab; clearing its contents instead of removing it
        setActiveTabId(prevTabs[0].id);
        return prevTabs.map(tab => ({
          ...tab,
          inputText: '',
          inputFile: null,
          result: null
        }));
      }

      const closingIndex = prevTabs.findIndex(tab => tab.id === tabId);
      const nextTabs = prevTabs.filter(tab => tab.id !== tabId);

      if (tabId === activeTabId) {
        const fallbackIndex = Math.max(0, closingIndex - 1);
        const fallbackTabId = nextTabs[fallbackIndex]?.id || nextTabs[0].id;
        setActiveTabId(fallbackTabId);
      }

      return nextTabs;
    });
  };

  const handlePrevTab = () => {
    const currentIndex = tabs.findIndex(tab => tab.id === activeTabId);
    if (currentIndex > 0) {
      setActiveTabId(tabs[currentIndex - 1].id);
    }
  };

  const handleNextTab = () => {
    const currentIndex = tabs.findIndex(tab => tab.id === activeTabId);
    if (currentIndex < tabs.length - 1) {
      setActiveTabId(tabs[currentIndex + 1].id);
    }
  };

  const TabBar = () => (
    <div className="flex items-center space-x-2 bg-gray-50 border border-gray-200 rounded-lg px-2 py-1">
      <button
        onClick={handlePrevTab}
        className="p-1 text-gray-500 hover:text-gray-700 disabled:opacity-40"
        disabled={tabs.length <= 1 || tabs[0]?.id === activeTabId}
        title="Previous tab"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
        </svg>
      </button>
      {tabs.map(tab => (
        <div
          key={tab.id}
          className={`flex items-center rounded-md border px-3 py-1 text-xs font-medium transition-colors ${tab.id === activeTabId ? 'bg-white border-blue-300 text-blue-700 shadow-sm' : 'bg-gray-100 border-gray-200 text-gray-600 hover:border-gray-300'}`}
        >
          <button
            onClick={() => setActiveTabId(tab.id)}
            className="focus:outline-none"
            title={`Switch to ${tab.name}`}
          >
            {tab.name}
          </button>
          {tabs.length > 1 && (
            <button
              onClick={() => handleCloseTab(tab.id)}
              className="ml-2 text-gray-400 hover:text-gray-600 focus:outline-none"
              title="Close tab"
            >
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>
      ))}
      <button
        onClick={handleNextTab}
        className="p-1 text-gray-500 hover:text-gray-700 disabled:opacity-40"
        disabled={tabs.length <= 1 || tabs[tabs.length - 1]?.id === activeTabId}
        title="Next tab"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>
      </button>
      <button
        onClick={handleAddTab}
        className="p-1 text-gray-600 hover:text-gray-800 border border-gray-300 rounded-full"
        title="Add tab"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v12m6-6H6" />
        </svg>
      </button>
    </div>
  );

  // Reset mode and key size when algorithm changes
  useEffect(() => {
    // Reset mode for algorithms that don't support CTR/GCM
    if ((selectedAlgorithm === '3DES' || selectedAlgorithm === 'BLOWFISH') && ['CTR', 'GCM'].includes(selectedMode)) {
      setSelectedMode('CBC'); // Reset to a supported mode for 3DES and Blowfish
    }
    if (!(selectedAlgorithm === 'SALSA20' || selectedAlgorithm === 'CHACHA20') && selectedMode === 'STREAM') {
      setSelectedMode('CBC');
    }
    
    // RC2 only supports CBC and ECB modes
    if (selectedAlgorithm === 'RC2' && !['CBC', 'ECB'].includes(selectedMode)) {
      setSelectedMode('CBC'); // Reset to CBC for RC2
    }
    
    // Set default key sizes based on algorithm
    if (selectedAlgorithm === 'AES') {
      setSelectedKeySize('256'); // Default to AES-256
    } else if (selectedAlgorithm === '3DES') {
      setSelectedKeySize('168'); // Default to 3DES 168-bit (3-key)
    } else if (selectedAlgorithm === 'BLOWFISH') {
      setSelectedKeySize('128'); // Default to 128-bit Blowfish (common usage)
    } else if (selectedAlgorithm === 'RC2') {
      setSelectedKeySize('128'); // Default to 128-bit RC2 (common usage)
    } else if (selectedAlgorithm === 'SM4') {
      setSelectedKeySize('128'); // SM4 requires exactly 128 bits
    } else if (selectedAlgorithm === 'SALSA20' || selectedAlgorithm === 'CHACHA20') {
      setSelectedKeySize('256'); // Stream ciphers default to 256-bit
    } else {
      setSelectedKeySize('');
    }
  }, [selectedAlgorithm, selectedMode]);

  useEffect(() => {
    if (selectedAlgorithm === 'SALSA20' || selectedAlgorithm === 'CHACHA20') {
      setSelectedMode('STREAM');
      setSelectedKeySize('256');
    }
  }, [selectedAlgorithm]);

  useEffect(() => {
    if (selectedAlgorithm === 'SALSA20') {
      setSelectedMode('STREAM');
      setSelectedKeySize('256');
      setSalsaRounds(20);
      setSalsaCounter(0);
    }
  }, [selectedAlgorithm]);

  // Generate random key based on selected algorithm and key size
  const generateRandomKey = () => {
    let keyLength;
    
    if (selectedAlgorithm === 'AES') {
      // AES key sizes: 128, 192, 256 bits
      const keySize = parseInt(selectedKeySize);
      keyLength = keySize / 8; // Convert bits to bytes
    } else if (selectedAlgorithm === '3DES') {
      // 3DES key sizes: 112 (16 bytes) or 168 bits (24 bytes)
      keyLength = selectedKeySize === '112' ? 16 : 24;
    } else if (selectedAlgorithm === 'BLOWFISH') {
      // Blowfish key sizes: 32-448 bits (4-56 bytes)
      const keySize = parseInt(selectedKeySize);
      keyLength = keySize / 8; // Convert bits to bytes
    } else if (selectedAlgorithm === 'RC2') {
      // RC2 key sizes: 8-1024 bits (1-128 bytes), commonly 40, 64, 128 bits
      const keySize = parseInt(selectedKeySize);
      keyLength = keySize / 8; // Convert bits to bytes
    } else if (selectedAlgorithm === 'SM4') {
      // SM4 key size: exactly 128 bits (16 bytes)
      keyLength = 16;
    } else if (selectedAlgorithm === 'CHACHA20') {
      keyLength = 32; // 256-bit
    } else {
      keyLength = 32; // Default fallback
    }
    
    const array = new Uint8Array(keyLength);
    crypto.getRandomValues(array);
    const hexKey = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    setCustomKey(hexKey);
  };

  // Generate random IV
  const generateRandomIV = () => {
    let ivLength;
    if (selectedAlgorithm === '3DES' || selectedAlgorithm === 'BLOWFISH' || selectedAlgorithm === 'RC2') {
      ivLength = 8; // 64-bit for 3DES, Blowfish, and RC2
    } else if (selectedAlgorithm === 'SALSA20') {
      ivLength = 8; // Salsa20 nonce size
    } else if (selectedAlgorithm === 'CHACHA20') {
      ivLength = 12; // ChaCha20 nonce size (IETF)
    } else {
      ivLength = 16; // 128-bit for AES
    }
    const array = new Uint8Array(ivLength);
    crypto.getRandomValues(array);
    const hexIV = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    setCustomIV(hexIV);
  };

  // Copy to clipboard function
  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (err) {
      console.error('Failed to copy to clipboard:', err);
      // Modern fallback without deprecated execCommand
      try {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        document.body.appendChild(textArea);
        textArea.select();
        textArea.setSelectionRange(0, 99999); // For mobile devices
        document.body.removeChild(textArea);
        // Note: This won't actually copy on modern browsers due to security restrictions
        // but it's better than using deprecated execCommand
      } catch (fallbackErr) {
        console.error('Fallback copy failed:', fallbackErr);
      }
    }
  };

  const handleProcess = async () => {
    if (!selectedAlgorithm || (!inputText && !inputFile)) {
      alert('Please select an algorithm and provide input data');
      return;
    }

    setIsLoading(true);
    try {
      let inputData = '';
      
      if (inputType === 'text') {
        inputData = inputText;
      } else if (inputFile) {
        inputData = await inputFile.text();
      }

      const requestData = {
        algorithm: selectedAlgorithm,
        mode: selectedMode,
        input: inputData,
        inputFormat: inputFormat,
        outputFormat: outputFormat,
        key: customKey || undefined,
        iv_or_nonce: customIV || undefined,
        keySize: selectedKeySize ? parseInt(selectedKeySize) / 8 : undefined // Convert bits to bytes
      };
      if (selectedAlgorithm === 'SALSA20') {
        requestData.rounds = parseInt(salsaRounds, 10) || 20;
        requestData.counter = parseInt(salsaCounter, 10) || 0;
      } else if (selectedAlgorithm === 'CHACHA20') {
        requestData.rounds = parseInt(chachaRounds, 10) || 20;
        requestData.counter = parseInt(chachaCounter, 10) || 0;
      }

      let response;
      if (operation === 'encrypt') {
        response = await cryptoAPI.encrypt(requestData);
      } else {
        // For decryption, we need the key and IV from a previous encryption
        if (!customKey) {
          alert('Key is required for decryption');
          return;
        }
        // Try to get IV from previous result
        if (result?.iv_or_nonce) {
          requestData.iv_or_nonce = result.iv_or_nonce;
        }
        if (result?.tag) {
          requestData.tag = result.tag;
        }
        response = await cryptoAPI.decrypt(requestData);
      }

      if (response.success) {
        setActiveResult(response);
        
        // Add to history
        const historyItem = {
          ...response,
          operation,
          timestamp: new Date().toISOString()
        };
        
        setHistory(prev => [historyItem, ...prev.slice(0, 4)]); // Keep last 5 items
      } else {
        alert(response.error || 'Operation failed');
      }
      
    } catch (error) {
      console.error('Processing error:', error);
      alert('Error processing data. Please check your input and try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      <style>{spinnerCSS}</style>
      <div className="h-screen flex flex-col bg-white overflow-hidden">
      {/* Main Content with Three Panels */}
      <div className="flex flex-1 overflow-hidden justify-start min-h-0">
        {/* Left Panel - Operations */}
        <ResizablePanel
          width={operationsWidth}
          minWidth={194}
          maxWidth={306}
          onResize={setOperationsWidth}
          className="bg-white border-r border-gray-200 overflow-y-auto flex-shrink-0 min-h-0"
        >
          <div className="p-4">
            <h2 className="text-lg font-semibold text-gray-900 mb-3">Operations</h2>
            <div className="mb-4">
              <input
                type="text"
                placeholder="Search..."
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
              />
            </div>
            
            {/* Algorithm Selector */}
            <AlgorithmSelector 
              selectedAlgorithm={selectedAlgorithm}
              onAlgorithmChange={setSelectedAlgorithm}
            />

          </div>
        </ResizablePanel>

        {/* Middle Panel - Algorithm Configuration */}
        <ResizablePanel
          width={benchmarkWidth}
          minWidth={385}
          maxWidth={660}
          onResize={setBenchmarkWidth}
          className="bg-white border-r border-gray-200 flex flex-col flex-shrink-0 min-h-0"
        >
          <div className="p-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">Algorithm</h2>
                          <div className="flex items-center space-x-2 mt-2">
                <button 
                  onClick={() => {
                    const algorithmConfig = {
                      algorithm: selectedAlgorithm,
                      keySize: selectedKeySize,
                      mode: selectedMode,
                      key: customKey,
                      iv: customIV,
                      operation: operation
                    };
                    const dataStr = JSON.stringify(algorithmConfig, null, 2);
                    const dataBlob = new Blob([dataStr], {type: 'application/json'});
                    const url = URL.createObjectURL(dataBlob);
                    const link = document.createElement('a');
                    link.href = url;
                    link.download = `algorithm-config-${selectedAlgorithm}.json`;
                    link.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="p-1 text-gray-400 hover:text-gray-600" 
                  title="Save Algorithm Config"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4" />
                  </svg>
                </button>
                <button 
                  onClick={() => {
                    const input = document.createElement('input');
                    input.type = 'file';
                    input.accept = '.json';
                    input.onchange = (e) => {
                      const file = e.target.files[0];
                      if (file) {
                        const reader = new FileReader();
                        reader.onload = (event) => {
                          try {
                            const config = JSON.parse(event.target.result);
                            setSelectedAlgorithm(config.algorithm || '');
                            setSelectedKeySize(config.keySize || '');
                            setSelectedMode(config.mode || 'CBC');
                            setCustomKey(config.key || '');
                            setCustomIV(config.iv || '');
                            setOperation(config.operation || 'encrypt');
                          } catch (error) {
                            alert('Invalid configuration file');
                          }
                        };
                        reader.readAsText(file);
                      }
                    };
                    input.click();
                  }}
                  className="p-1 text-gray-400 hover:text-gray-600" 
                  title="Load Algorithm Config"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2-2z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5a2 2 0 012-2h4a2 2 0 012 2v2H8V5z" />
                  </svg>
                </button>
                <button 
                  onClick={() => {
                    setSelectedAlgorithm('');
                    setSelectedKeySize('');
                    setCustomKey('');
                    setCustomIV('');
                    setSalsaRounds(20);
                    setSalsaCounter(0);
                    setOperation('encrypt');
                    setActiveResult(null);
                    setHistory([]);
                  }}
                  className="p-1 text-gray-400 hover:text-gray-600" 
                  title="Clear Algorithm Config"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
              </div>
          </div>
          
          <div className="flex-1 p-4 overflow-y-auto min-h-0">
            {/* Algorithm Configuration Block - Only show when algorithm is selected */}
            {selectedAlgorithm && (
              <div className="bg-white border border-gray-200 rounded-lg p-4 mb-4 shadow-sm">
                <div className="mb-3">
                  <h3 className="text-lg font-semibold text-gray-900">{selectedAlgorithm}-{selectedKeySize}-{selectedMode}</h3>
                </div>
                
                {/* Key Size Selection */}
                <div className="mb-3">
                  <label className="block text-sm font-medium text-gray-700 mb-1">Key Size</label>
                  <select 
                    value={selectedKeySize}
                    onChange={(e) => setSelectedKeySize(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
                  >
                    {selectedAlgorithm === 'AES' && (
                      <>
                        <option value="128">128 bits (16 bytes) - AES-128</option>
                        <option value="192">192 bits (24 bytes) - AES-192</option>
                        <option value="256">256 bits (32 bytes) - AES-256</option>
                      </>
                    )}
                    {selectedAlgorithm === '3DES' && (
                      <>
                        <option value="112">112 bits (16 bytes) - Two-key 3DES</option>
                        <option value="168">168 bits (24 bytes) - Three-key 3DES</option>
                      </>
                    )}
                    {selectedAlgorithm === 'BLOWFISH' && (
                      <>
                        <option value="32">32 bits (4 bytes) - Minimum</option>
                        <option value="64">64 bits (8 bytes) - Original default</option>
                        <option value="128">128 bits (16 bytes) - Common usage</option>
                        <option value="192">192 bits (24 bytes)</option>
                        <option value="256">256 bits (32 bytes)</option>
                        <option value="320">320 bits (40 bytes)</option>
                        <option value="384">384 bits (48 bytes)</option>
                        <option value="448">448 bits (56 bytes) - Maximum</option>
                      </>
                    )}
                    {selectedAlgorithm === 'RC2' && (
                      <>
                        <option value="40">40 bits (5 bytes) - Common effective key length</option>
                        <option value="64">64 bits (8 bytes) - Common effective key length</option>
                        <option value="128">128 bits (16 bytes) - Common effective key length</option>
                        <option value="256">256 bits (32 bytes)</option>
                        <option value="512">512 bits (64 bytes)</option>
                        <option value="1024">1024 bits (128 bytes) - Maximum</option>
                      </>
                    )}
                    {selectedAlgorithm === 'SM4' && (
                      <>
                        <option value="128">128 bits (16 bytes) - SM4 Standard</option>
                      </>
                    )}
                    {selectedAlgorithm === 'CHACHA20' && (
                      <>
                        <option value="256">256 bits (32 bytes) - Required</option>
                      </>
                    )}
                    {selectedAlgorithm === 'SALSA20' && (
                      <>
                        <option value="128">128 bits (16 bytes)</option>
                        <option value="256">256 bits (32 bytes) - Recommended</option>
                      </>
                    )}

                  </select>
                </div>
                
                {/* Key Input */}
                <div className="mb-3">
                  <label className="block text-sm font-medium text-gray-700 mb-1">Key</label>
                  <div className="flex space-x-2">
                    <select className="px-3 py-2 border border-gray-300 rounded text-sm bg-white">
                      <option>HEX</option>
                      <option>RAW</option>
                    </select>
                    <div className="flex-1 relative flex items-center space-x-2">
                      <input
                        type="text"
                        value={customKey}
                        onChange={(e) => setCustomKey(e.target.value)}
                        placeholder={`Enter ${selectedKeySize}-bit encryption key...`}
                        className="w-full px-3 py-2 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <button
                        onClick={() => copyToClipboard(customKey)}
                        type="button"
                        className="p-2 text-gray-400 hover:text-gray-600 transition-colors"
                        title="Copy key"
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      </button>
                      <button
                        onClick={generateRandomKey}
                        type="button"
                        className="p-2 text-gray-400 hover:text-gray-600 transition-colors"
                        title={`Generate random ${selectedKeySize}-bit key`}
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                        </svg>
                      </button>
                    </div>
                  </div>
                </div>
                
                {/* IV Input (for AES, 3DES, Blowfish modes except ECB, RC2 CBC mode, and SM4 non-ECB modes) */}
                {(selectedAlgorithm === 'SALSA20' || selectedAlgorithm === 'CHACHA20' || selectedAlgorithm === 'AES' || selectedAlgorithm === '3DES' || selectedAlgorithm === 'BLOWFISH' || selectedAlgorithm === 'RC2' || selectedAlgorithm === 'SM4') && selectedMode !== 'ECB' && (
                  <div className="mb-3">
                    <label className="block text-sm font-medium text-gray-700 mb-1">{(selectedAlgorithm === 'SALSA20' || selectedAlgorithm === 'CHACHA20') ? 'Nonce' : 'IV'}</label>
                    <div className="flex space-x-2">
                      <select className="px-3 py-2 border border-gray-300 rounded text-sm bg-white">
                        <option>HEX</option>
                        <option>RAW</option>
                      </select>
                      <div className="flex-1 relative flex items-center space-x-2">
                        <input
                          type="text"
                          value={customIV}
                          onChange={(e) => setCustomIV(e.target.value)}
                          placeholder={selectedAlgorithm === 'SALSA20' ? 'Enter 8-byte nonce...' : selectedAlgorithm === 'CHACHA20' ? 'Enter 12-byte nonce...' : 'Enter initialization vector...'}
                          className="w-full px-3 py-2 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                        <button
                          onClick={() => copyToClipboard(customIV)}
                          type="button"
                          className="p-2 text-gray-400 hover:text-gray-600 transition-colors"
                          title="Copy"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                          </svg>
                        </button>
                        <button
                          onClick={generateRandomIV}
                          type="button"
                          className="p-2 text-gray-400 hover:text-gray-600 transition-colors"
                          title={(selectedAlgorithm === 'SALSA20' || selectedAlgorithm === 'CHACHA20') ? 'Generate random nonce' : 'Generate random IV'}
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                          </svg>
                        </button>
                      </div>
                    </div>
                  </div>
                )}
                
                {/* Mode/Input/Output Options */}
                <div className="grid grid-cols-3 gap-2">
                  <div className="bg-white border border-gray-200 rounded p-2">
                    <div className="text-xs text-gray-500 mb-1">Mode</div>
                    {selectedAlgorithm === 'SALSA20' || selectedAlgorithm === 'CHACHA20' ? (
                      <div className="w-full text-sm font-medium text-gray-900 bg-transparent border-none">
                        STREAM
                      </div>
                    ) : (
                      <select
                        value={selectedMode}
                        onChange={(e) => setSelectedMode(e.target.value)}
                        className="w-full text-sm font-medium text-gray-900 bg-transparent border-none focus:outline-none focus:ring-0"
                      >
                        <option value="CBC">CBC</option>
                        {selectedAlgorithm !== 'RC2' && <option value="CFB">CFB</option>}
                        {selectedAlgorithm !== 'RC2' && <option value="OFB">OFB</option>}
                        {(selectedAlgorithm === 'AES' || selectedAlgorithm === 'SM4') && (
                          <>
                            <option value="CTR">CTR</option>
                            <option value="GCM">GCM</option>
                          </>
                        )}
                        <option value="ECB">ECB</option>
                      </select>
                    )}
                  </div>
                  <div className="bg-white border border-gray-200 rounded p-2">
                    <div className="text-xs text-gray-500 mb-1">Input</div>
                    <select 
                      value={inputFormat}
                      onChange={(e) => setInputFormat(e.target.value)}
                      className="w-full text-sm font-medium text-gray-900 bg-transparent border-none focus:outline-none focus:ring-0"
                    >
                      <option value="RAW">RAW</option>
                      <option value="HEX">HEX</option>
                    </select>
                  </div>
                <div className="bg-white border border-gray-200 rounded p-2">
                  <div className="text-xs text-gray-500 mb-1">Output</div>
                  <select 
                    value={outputFormat}
                    onChange={(e) => setOutputFormat(e.target.value)}
                      className="w-full text-sm font-medium text-gray-900 bg-transparent border-none focus:outline-none focus:ring-0"
                    >
                      <option value="HEX">HEX</option>
                      <option value="RAW">RAW</option>
                  </select>
                </div>
              </div>

              {(selectedAlgorithm === 'SALSA20' || selectedAlgorithm === 'CHACHA20') && (
                <div className="grid grid-cols-2 gap-2 mt-2">
                  <div className="bg-white border border-gray-200 rounded p-2">
                    <div className="text-xs text-gray-500 mb-1">Counter</div>
                    <input
                      type="number"
                      min="0"
                      value={selectedAlgorithm === 'SALSA20' ? salsaCounter : chachaCounter}
                      onChange={(e) => selectedAlgorithm === 'SALSA20' ? setSalsaCounter(e.target.value) : setChachaCounter(e.target.value)}
                      className="w-full text-sm font-medium text-gray-900 bg-transparent border-none focus:outline-none focus:ring-0"
                    />
                  </div>
                  <div className="bg-white border border-gray-200 rounded p-2">
                    <div className="text-xs text-gray-500 mb-1">Rounds</div>
                    <select
                      value={selectedAlgorithm === 'SALSA20' ? salsaRounds : chachaRounds}
                      onChange={(e) => selectedAlgorithm === 'SALSA20' ? setSalsaRounds(e.target.value) : setChachaRounds(e.target.value)}
                      className="w-full text-sm font-medium text-gray-900 bg-transparent border-none focus:outline-none focus:ring-0"
                    >
                      <option value="8">8 (not recommended)</option>
                      <option value="12">12 (acceptable)</option>
                      <option value="20">20 (recommended)</option>
                    </select>
                  </div>
                </div>
              )}
            </div>
          )}
            
            {/* Encrypt/Decrypt Buttons */}
            {selectedAlgorithm && (
              <div className="flex items-center space-x-4 mt-4">
                <label className="relative inline-flex items-center cursor-pointer scale-90">
                  <input
                    type="checkbox"
                    className="sr-only peer"
                    checked={operation === 'encrypt'}
                    onChange={() => setOperation(operation === 'encrypt' ? 'decrypt' : 'encrypt')}
                    aria-label="Toggle encrypt/decrypt"
                  />
                  <div className="group peer ring-0 bg-rose-400 rounded-full outline-none duration-300 after:duration-300 w-20 h-10 shadow-md peer-checked:bg-emerald-500 peer-focus:outline-none after:content-[''] after:rounded-full after:absolute after:bg-gray-50 after:outline-none after:h-8 after:w-8 after:top-1 after:left-1 after:flex after:justify-center after:items-center peer-checked:after:translate-x-10 peer-hover:after:scale-95">
                    <svg className="absolute top-1 left-11 stroke-gray-900 w-8 h-8" viewBox="0 0 100 100">
                      <path d="M50,18A19.9,19.9,0,0,0,30,38v8a8,8,0,0,0-8,8V74a8,8,0,0,0,8,8H70a8,8,0,0,0,8-8V54a8,8,0,0,0-8-8H38V38a12,12,0,0,1,23.6-3,4,4,0,1,0,7.8-2A20.1,20.1,0,0,0,50,18Z" />
                    </svg>
                    <svg className="absolute top-1 left-1 stroke-gray-900 w-8 h-8" viewBox="0 0 100 100">
                      <path d="M30,46V38a20,20,0,0,1,40,0v8a8,8,0,0,1,8,8V74a8,8,0,0,1-8,8H30a8,8,0,0,1-8-8V54A8,8,0,0,1,30,46Zm32-8v8H38V38a12,12,0,0,1,24,0Z" fillRule="evenodd" />
                    </svg>
                  </div>
                </label>
                <button
                  onClick={handleProcess}
                  disabled={isLoading || (!inputText && !inputFile)}
                  className="flex-1 bg-gradient-to-r from-gray-800 to-gray-900 hover:from-gray-900 hover:to-black disabled:opacity-50 disabled:cursor-not-allowed text-white px-5 py-2.5 rounded-lg font-semibold shadow-lg hover:shadow-xl transition-all duration-200 transform hover:scale-105 disabled:hover:scale-100"
                >
                  {isLoading ? (
                    <span className="flex items-center justify-center">
                      <svg className="spinner" viewBox="25 25 50 50" aria-label="Loading">
                        <circle r="20" cy="50" cx="50"></circle>
                      </svg>
                    </span>
                  ) : (
                    operation === 'encrypt' ? 'Encrypt' : 'Decrypt'
                  )}
                </button>
              </div>
            )}

            {/* Encryption Details */}
            
            {/* Empty state when no algorithm is selected */}
            {!selectedAlgorithm && (
              <div className="flex flex-col items-center justify-center h-full text-gray-400">
                <svg className="w-16 h-16 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <p className="text-lg font-medium">No Algorithm Selected</p>
                <p className="text-sm">Select an algorithm from the left panel to configure it</p>
              </div>
            )}
          </div>
          

        </ResizablePanel>

        {/* Right Panel - Input/Output */}
        <div className="flex-1 bg-white flex flex-col overflow-hidden min-h-0">
          {/* Input Section */}
          <VerticalResizablePanel
            height={inputHeight}
            minHeight={250}
            maxHeight={700}
            onResize={setInputHeight}
            className="border-b border-gray-200 flex flex-col relative min-h-0"
          >
            <div className="p-4 border-b border-gray-200 flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <h2 className="text-lg font-semibold text-gray-900">Input</h2>
                <TabBar />
              </div>
              <div className="flex items-center space-x-4">
                <div className="flex flex-col items-end space-y-1 text-xs text-gray-500">
                  <span>length: {inputText.length}</span>
                  <span>lines: {inputText.split(/\r?\n/).length}</span>
                </div>
                <div className="flex items-center space-x-1">
                <button 
                  onClick={() => {
                    const input = document.createElement('input');
                    input.type = 'file';
                    input.accept = '.txt,.json,.xml,.csv,.md';
                    input.onchange = (e) => {
                      const file = e.target.files[0];
                      if (file) {
                        const reader = new FileReader();
                        reader.onload = (event) => {
                          setActiveInputText(event.target.result);
                          setActiveInputFile(file);
                        };
                        reader.readAsText(file);
                      }
                    };
                    input.click();
                  }}
                  className="p-1 text-gray-400 hover:text-gray-600" 
                  title="Open File"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2-2z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5a2 2 0 012-2h4a2 2 0 012 2v2H8V5z" />
                  </svg>
                </button>
                <button 
                  onClick={() => {
                    const input = document.createElement('input');
                    input.type = 'file';
                    input.accept = '.txt,.json,.xml,.csv,.md';
                    input.multiple = true;
                    input.onchange = (e) => {
                      const files = Array.from(e.target.files);
                      if (files.length > 0) {
                        const fileContents = files.map(file => file.name + ':\n' + file.name).join('\n\n');
                        setActiveInputText(inputText + '\n' + fileContents);
                      }
                    };
                    input.click();
                  }}
                  className="p-1 text-gray-400 hover:text-gray-600" 
                  title="Import Files"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                  </svg>
                </button>
                <button 
                  onClick={() => {
                    setActiveInputText('');
                    setActiveInputFile(null);
                  }}
                  className="p-1 text-gray-400 hover:text-gray-600" 
                  title="Clear Input"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
            <div className="flex-1 p-4 overflow-auto">
              <textarea
                value={inputText}
                onChange={(e) => setActiveInputText(e.target.value)}
                placeholder="Enter your input here..."
                className="w-full h-full resize-none border-0 focus:outline-none text-sm font-mono"
                disabled={isLoading}
              />
            </div>
          </VerticalResizablePanel>

          {/* Output Section */}
          <div className="flex-1 flex flex-col relative min-h-0">
            <div className="p-4 border-b border-gray-200 flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <h2 className="text-lg font-semibold text-gray-900">Output</h2>
                <TabBar />
              </div>
              <div className="flex items-center space-x-4">
                {result && result.output && (
                  <div className="flex flex-col items-end space-y-1 text-xs text-gray-500">
                    <span>time: {result.executionTime || 'N/A'}</span>
                    <span>length: {result.output.length}</span>
                    <span>lines: {result.output.split(/\r?\n/).length}</span>
                  </div>
                )}
                <div className="flex items-center space-x-1">
                <button 
                  onClick={() => {
                    if (result && result.output) {
                      try {
                        // Create a more descriptive filename with algorithm and operation info
                        const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
                        const algorithm = selectedAlgorithm || 'unknown';
                        const operation = result.operation || 'processed';
                        const filename = `${algorithm}-${operation}-${timestamp}.txt`;
                        
                        const dataStr = result.output;
                        const dataBlob = new Blob([dataStr], {type: 'text/plain;charset=utf-8'});
                        const url = URL.createObjectURL(dataBlob);
                        const link = document.createElement('a');
                        link.href = url;
                        link.download = filename;
                        link.style.display = 'none';
                        document.body.appendChild(link);
                        link.click();
                        document.body.removeChild(link);
                        URL.revokeObjectURL(url);
                        
                        // Show success feedback
                        const button = event.target.closest('button');
                        const originalTitle = button.title;
                        button.title = 'Saved!';
                        setTimeout(() => {
                          button.title = originalTitle;
                        }, 1000);
                      } catch (error) {
                        console.error('Failed to save output:', error);
                        alert('Failed to save output file. Please try again.');
                      }
                    } else {
                      alert('No output available to save.');
                    }
                  }}
                  disabled={!result || !result.output}
                  className="p-1 text-gray-400 hover:text-gray-600 disabled:opacity-30 disabled:cursor-not-allowed" 
                  title="Save Output as TXT"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4" />
                  </svg>
                </button>
                <button 
                  onClick={async () => {
                    if (result && result.output) {
                      try {
                        // Try modern clipboard API first
                        if (navigator.clipboard && window.isSecureContext) {
                          await navigator.clipboard.writeText(result.output);
                          // Show success feedback
                          const button = event.target.closest('button');
                          const originalTitle = button.title;
                          button.title = 'Copied!';
                          setTimeout(() => {
                            button.title = originalTitle;
                          }, 1000);
                        } else {
                          // For non-secure contexts, create a temporary textarea and select the text
                          const textArea = document.createElement('textarea');
                          textArea.value = result.output;
                          textArea.style.position = 'fixed';
                          textArea.style.left = '50%';
                          textArea.style.top = '50%';
                          textArea.style.transform = 'translate(-50%, -50%)';
                          textArea.style.zIndex = '9999';
                          textArea.style.width = '300px';
                          textArea.style.height = '200px';
                          textArea.style.border = '2px solid #3b82f6';
                          textArea.style.borderRadius = '8px';
                          textArea.style.padding = '10px';
                          textArea.style.fontFamily = 'monospace';
                          textArea.style.fontSize = '12px';
                          textArea.style.backgroundColor = 'white';
                          textArea.style.boxShadow = '0 4px 6px rgba(0, 0, 0, 0.1)';
                          
                          // Add instructions
                          const instructions = document.createElement('div');
                          instructions.style.position = 'fixed';
                          instructions.style.left = '50%';
                          instructions.style.top = 'calc(50% - 120px)';
                          instructions.style.transform = 'translate(-50%, -50%)';
                          instructions.style.zIndex = '10000';
                          instructions.style.backgroundColor = '#3b82f6';
                          instructions.style.color = 'white';
                          instructions.style.padding = '10px 15px';
                          instructions.style.borderRadius = '6px';
                          instructions.style.fontSize = '14px';
                          instructions.style.fontWeight = 'bold';
                          instructions.style.boxShadow = '0 2px 4px rgba(0, 0, 0, 0.2)';
                          instructions.textContent = 'Press Ctrl+C (or Cmd+C) to copy, then click outside to close';
                          
                          document.body.appendChild(instructions);
                          document.body.appendChild(textArea);
                          
                          textArea.focus();
                          textArea.select();
                          
                          // Remove elements when clicking outside
                          const removeElements = () => {
                            document.body.removeChild(textArea);
                            document.body.removeChild(instructions);
                            document.removeEventListener('click', removeElements);
                          };
                          
                          // Remove after 10 seconds or when clicking outside
                          setTimeout(removeElements, 10000);
                          document.addEventListener('click', removeElements);
                        }
                      } catch (error) {
                        console.error('Failed to copy to clipboard:', error);
                        // Show a more helpful message
                        const message = 'Copy failed. The output has been selected for you. Press Ctrl+C (or Cmd+C) to copy manually.';
                        alert(message);
                      }
                    } else {
                      alert('No output available to copy.');
                    }
                  }}
                  disabled={!result || !result.output}
                  className="p-1 text-gray-400 hover:text-gray-600 disabled:opacity-30 disabled:cursor-not-allowed" 
                  title="Copy Output to Clipboard"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                </button>
                <button 
                  onClick={() => {
                    // Undo functionality - could be enhanced with history
                    if (history.length > 0) {
                      const previousResult = history[0];
                      setActiveResult(previousResult);
                      setHistory(prev => prev.slice(1));
                    }
                  }}
                  className="p-1 text-gray-400 hover:text-gray-600" 
                  title="Undo"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6" />
                  </svg>
                </button>
                <button 
                  onClick={() => {
                    // Redo functionality - could be enhanced with forward history
                    // For now, just show a message
                    alert('Redo functionality coming soon!');
                  }}
                  className="p-1 text-gray-400 hover:text-gray-600" 
                  title="Redo"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 10h-10a8 8 0 00-8 8v2M21 10l-6 6m6-6l-6-6" />
                  </svg>
                </button>
                <button 
                  onClick={() => {
                    // Expand functionality - could open in new window or modal
                    if (result && result.output) {
                      const newWindow = window.open('', '_blank');
                      newWindow.document.write(`
                        <html>
                          <head>
                            <title>Output - ${selectedAlgorithm}</title>
                            <style>
                              body { font-family: monospace; padding: 20px; background: #f5f5f5; }
                              pre { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                            </style>
                          </head>
                          <body>
                            <h2>${selectedAlgorithm} Output</h2>
                            <pre>${result.output}</pre>
                          </body>
                        </html>
                      `);
                      newWindow.document.close();
                    }
                  }}
                  className="p-1 text-gray-400 hover:text-gray-600" 
                  title="Expand Output"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
                  </svg>
                </button>
              </div>
              </div>
            </div>
            <div className="flex-1 p-4 overflow-auto min-h-0">
              {result ? (
                <pre className="w-full h-full text-sm font-mono overflow-auto border-0 focus:outline-none">
                  {result.output}
                </pre>
              ) : (
                <div className="w-full h-full flex items-center justify-center text-gray-400">
                  <span className="text-sm">Output will appear here...</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
    </>
  );
};

export default CryptoLabPage; 

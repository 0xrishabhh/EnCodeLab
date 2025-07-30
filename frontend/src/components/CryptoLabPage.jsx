import React, { useState, useEffect } from 'react';
import { Shield, Zap } from 'lucide-react';
import ResizablePanel from './ResizablePanel';
import AlgorithmSelector from './AlgorithmSelector';
import { cryptoAPI } from '../services/api';

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
  const [selectedAlgorithm, setSelectedAlgorithm] = useState('');
  const [selectedMode, setSelectedMode] = useState('CBC'); // All AES modes supported
  const [inputFormat, setInputFormat] = useState('RAW');
  const [outputFormat, setOutputFormat] = useState('HEX');
  const [inputType, setInputType] = useState('text');
  const [inputText, setInputText] = useState('');
  const [inputFile, setInputFile] = useState(null);
  const [customKey, setCustomKey] = useState('');
  const [customIV, setCustomIV] = useState('');
  const [operation, setOperation] = useState('encrypt');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  
  // Panel width states - set better default widths for proper initial layout
  const [operationsWidth, setOperationsWidth] = useState(280);
  const [benchmarkWidth, setBenchmarkWidth] = useState(400);
  
  // Panel height states for input/output sections
  const [inputHeight, setInputHeight] = useState(300);

  // Reset mode when algorithm changes
  useEffect(() => {
    if ((selectedAlgorithm === '3DES' || selectedAlgorithm === 'BLOWFISH') && ['CTR', 'GCM'].includes(selectedMode)) {
      setSelectedMode('CBC'); // Reset to a supported mode for 3DES and Blowfish
    }
  }, [selectedAlgorithm, selectedMode]);

  // Generate random key
  const generateRandomKey = () => {
    let keyLength;
    if (selectedAlgorithm === '3DES') {
      keyLength = 24; // 192-bit for 3DES
    } else if (selectedAlgorithm === 'BLOWFISH') {
      keyLength = 8; // 64-bit for Blowfish (default)
    } else {
      keyLength = 32; // 256-bit for AES
    }
    const array = new Uint8Array(keyLength);
    crypto.getRandomValues(array);
    const hexKey = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    setCustomKey(hexKey);
  };

  // Generate random IV
  const generateRandomIV = () => {
    let ivLength;
    if (selectedAlgorithm === '3DES' || selectedAlgorithm === 'BLOWFISH') {
      ivLength = 8; // 64-bit for 3DES and Blowfish
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
        iv_or_nonce: customIV || undefined
      };

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
        setResult(response);
        
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
    <div className="h-screen bg-gray-50 flex flex-col">
      {/* Main Content with Three Panels */}
      <div className="flex flex-1 overflow-hidden justify-start">
        {/* Left Panel - Operations */}
        <ResizablePanel
          width={operationsWidth}
          minWidth={250}
          maxWidth={400}
          onResize={setOperationsWidth}
          className="bg-white border-r border-gray-200 overflow-y-auto flex-shrink-0"
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
          minWidth={300}
          maxWidth={500}
          onResize={setBenchmarkWidth}
          className="bg-white border-r border-gray-200 flex flex-col flex-shrink-0"
        >
          <div className="p-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">Algorithm</h2>
                          <div className="flex items-center space-x-2 mt-2">
                <button 
                  onClick={() => {
                    const algorithmConfig = {
                      algorithm: selectedAlgorithm,
                      key: customKey,
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
                            setSelectedAlgorithm(config.algorithm || 'AES-GCM');
                            setCustomKey(config.key || '');
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
                    setCustomKey('');
                    setOperation('encrypt');
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
          
          <div className="flex-1 p-4 overflow-y-auto">
            {/* Algorithm Configuration Block - Only show when algorithm is selected */}
            {selectedAlgorithm && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-4">
                <div className="mb-3">
                  <h3 className="text-lg font-semibold text-red-900">{selectedAlgorithm}-{selectedMode}</h3>
                </div>
                
                {/* Key Input */}
                <div className="mb-3">
                  <label className="block text-sm font-medium text-gray-700 mb-1">Key</label>
                  <div className="flex space-x-2">
                    <input
                      type="text"
                      value={customKey}
                      onChange={(e) => setCustomKey(e.target.value)}
                      placeholder="Enter encryption key..."
                      className="flex-1 px-3 py-2 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-red-500"
                    />
                    <select className="px-3 py-2 border border-gray-300 rounded text-sm bg-white">
                      <option>HEX</option>
                      <option>RAW</option>
                    </select>
                    <button
                      onClick={generateRandomKey}
                      type="button"
                      className="p-2 text-gray-400 hover:text-green-600 hover:bg-green-50 border border-gray-200 hover:border-green-200 rounded transition-colors"
                      title="Generate random key"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                      </svg>
                    </button>
                  </div>
                </div>
                
                {/* IV Input (for AES, 3DES, and Blowfish modes except ECB) */}
                {(selectedAlgorithm === 'AES' || selectedAlgorithm === '3DES' || selectedAlgorithm === 'BLOWFISH') && selectedMode !== 'ECB' && (
                  <div className="mb-3">
                    <label className="block text-sm font-medium text-gray-700 mb-1">IV</label>
                    <div className="flex space-x-2">
                      <input
                        type="text"
                        value={customIV}
                        onChange={(e) => setCustomIV(e.target.value)}
                        placeholder="Enter initialization vector..."
                        className="flex-1 px-3 py-2 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-red-500"
                      />
                      <select className="px-3 py-2 border border-gray-300 rounded text-sm bg-white">
                        <option>HEX</option>
                        <option>RAW</option>
                      </select>
                      <button
                        onClick={generateRandomIV}
                        type="button"
                        className="p-2 text-gray-400 hover:text-blue-600 hover:bg-blue-50 border border-gray-200 hover:border-blue-200 rounded transition-colors"
                        title="Generate random IV"
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                        </svg>
                      </button>
                    </div>
                  </div>
                )}
                
                {/* Mode/Input/Output Options */}
                <div className="grid grid-cols-3 gap-2">
                  <div className="bg-white border border-gray-200 rounded p-2">
                    <div className="text-xs text-gray-500 mb-1">Mode</div>
                                        <select
                      value={selectedMode}
                      onChange={(e) => setSelectedMode(e.target.value)}
                      className="w-full text-sm font-medium text-gray-900 bg-transparent border-none focus:outline-none focus:ring-0"
                    >
                      <option value="CBC">CBC</option>
                      <option value="CFB">CFB</option>
                      <option value="OFB">OFB</option>
                      {selectedAlgorithm === 'AES' && (
                        <>
                          <option value="CTR">CTR</option>
                          <option value="GCM">GCM</option>
                        </>
                      )}
                      <option value="ECB">ECB</option>
                    </select>
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
              </div>
            )}
            
            {/* Encrypt/Decrypt Buttons */}
            {selectedAlgorithm && (
              <div className="flex space-x-3 mt-4">
                <button
                  onClick={() => {
                    setOperation('encrypt');
                    handleProcess();
                  }}
                  disabled={isLoading || (!inputText && !inputFile)}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg font-medium transition-colors"
                >
                  Encrypt
                </button>
                <button
                  onClick={() => {
                    setOperation('decrypt');
                    handleProcess();
                  }}
                  disabled={isLoading || (!inputText && !inputFile)}
                  className="flex-1 bg-green-600 hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg font-medium transition-colors"
                >
                  Decrypt
                </button>
              </div>
            )}

            {/* Encryption Details */}
            {result && (result.key || (result.iv_or_nonce && selectedMode !== 'ECB')) && (
              <div className="mt-4 p-3 bg-gray-50 rounded border">
                <h4 className="font-semibold text-gray-800 mb-2">Encryption Details:</h4>
                {result.key && (
                  <div className="mb-2">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600 text-sm">Key:</span>
                      <button
                        onClick={() => copyToClipboard(result.key)}
                        className="p-1 text-gray-400 hover:text-gray-600 transition-colors"
                        title="Copy key to clipboard"
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      </button>
                    </div>
                    <div className="text-xs text-gray-800 break-all font-mono">{result.key}</div>
                  </div>
                )}
                {result.iv_or_nonce && selectedMode !== 'ECB' && (
                  <div className="mb-2">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600 text-sm">IV:</span>
                      <button
                        onClick={() => copyToClipboard(result.iv_or_nonce)}
                        className="p-1 text-gray-400 hover:text-gray-600 transition-colors"
                        title="Copy IV to clipboard"
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      </button>
                    </div>
                    <div className="text-xs text-gray-800 break-all font-mono">{result.iv_or_nonce}</div>
                  </div>
                )}
              </div>
            )}
            
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
          
          <div className="p-4 border-t border-gray-200">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">STEP</span>
              <button
                onClick={handleProcess}
                disabled={isLoading || (!inputText && !inputFile)}
                className="bg-green-600 hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed text-white px-6 py-2 rounded-lg font-medium flex items-center space-x-2"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                <span>BAKE!</span>
              </button>
              <label className="flex items-center space-x-2 text-sm text-gray-600">
                <input type="checkbox" className="rounded" />
                <span>Auto Bake</span>
              </label>
            </div>
          </div>
        </ResizablePanel>

        {/* Right Panel - Input/Output */}
        <div className="flex-1 bg-white flex flex-col overflow-hidden">
          {/* Input Section */}
          <VerticalResizablePanel
            height={inputHeight}
            minHeight={150}
            maxHeight={600}
            onResize={setInputHeight}
            className="border-b border-gray-200 flex flex-col relative"
          >
            <div className="p-4 border-b border-gray-200 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900">Input</h2>
              <div className="flex items-center space-x-4">
                <div className="flex flex-col items-end space-y-1 text-xs text-gray-500">
                  <span>length: {inputText.length + (inputFile ? inputFile.size : 0)}</span>
                  <span>lines: {inputText.split('\n').length}</span>
                </div>
                <div className="flex items-center space-x-1">
                <button 
                  onClick={() => setInputText(inputText + '\n')}
                  className="p-1 text-gray-400 hover:text-gray-600" 
                  title="Add New Line"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                  </svg>
                </button>
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
                          setInputText(event.target.result);
                          setInputFile(file);
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
                        setInputText(inputText + '\n' + fileContents);
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
                    setInputText('');
                    setInputFile(null);
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
                onChange={(e) => setInputText(e.target.value)}
                placeholder="Enter your input here..."
                className="w-full h-full resize-none border-0 focus:outline-none text-sm font-mono"
                disabled={isLoading}
              />
            </div>
          </VerticalResizablePanel>

          {/* Output Section */}
          <div className="flex-1 flex flex-col relative">
            <div className="p-4 border-b border-gray-200 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900">Output</h2>
              <div className="flex items-center space-x-4">
                {result && result.output && (
                  <div className="flex flex-col items-end space-y-1 text-xs text-gray-500">
                    <span>time: {result.executionTime || 'N/A'}</span>
                    <span>length: {result.output.length}</span>
                    <span>lines: {result.output.split('\n').length}</span>
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
                      setResult(previousResult);
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
            <div className="flex-1 p-4 overflow-auto">
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
  );
};

export default CryptoLabPage; 
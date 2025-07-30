import React, { useState, useRef } from 'react';
import { Upload, FileText, X, Copy, Download } from 'lucide-react';

const InputForm = ({ 
  inputType, 
  setInputType, 
  inputText, 
  setInputText, 
  inputFile, 
  setInputFile, 
  customKey, 
  setCustomKey,
  operation,
  setOperation,
  onProcess,
  isLoading,
  result
}) => {
  const fileInputRef = useRef(null);
  const [dragActive, setDragActive] = useState(false);

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setInputFile(file);
      setInputText('');
    }
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setInputFile(e.dataTransfer.files[0]);
      setInputText('');
    }
  };

  const removeFile = () => {
    setInputFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  const downloadResult = () => {
    if (!result?.output) return;
    
    const blob = new Blob([result.output], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `crypto-result-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getInputSize = () => {
    if (inputFile) {
      return (inputFile.size / 1024).toFixed(2) + ' KB';
    }
    if (inputText) {
      return (new Blob([inputText]).size / 1024).toFixed(2) + ' KB';
    }
    return '0 KB';
  };

  return (
    <div className="space-y-6">
      {/* Operation Selection */}
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Operation
        </label>
        <div className="flex space-x-4">
          <label className="flex items-center">
            <input
              type="radio"
              name="operation"
              value="encrypt"
              checked={operation === 'encrypt'}
              onChange={(e) => setOperation(e.target.value)}
              className="mr-2 text-primary-600 focus:ring-primary-500"
            />
            <span className="text-sm font-medium text-gray-700">Encrypt</span>
          </label>
          <label className="flex items-center">
            <input
              type="radio"
              name="operation"
              value="decrypt"
              checked={operation === 'decrypt'}
              onChange={(e) => setOperation(e.target.value)}
              className="mr-2 text-primary-600 focus:ring-primary-500"
            />
            <span className="text-sm font-medium text-gray-700">Decrypt</span>
          </label>
        </div>
      </div>

      {/* Input Type Selection */}
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Input Type
        </label>
        <div className="flex space-x-4">
          <label className="flex items-center">
            <input
              type="radio"
              name="inputType"
              value="text"
              checked={inputType === 'text'}
              onChange={(e) => setInputType(e.target.value)}
              className="mr-2 text-primary-600 focus:ring-primary-500"
            />
            <span className="text-sm font-medium text-gray-700">Text</span>
          </label>
          <label className="flex items-center">
            <input
              type="radio"
              name="inputType"
              value="file"
              checked={inputType === 'file'}
              onChange={(e) => setInputType(e.target.value)}
              className="mr-2 text-primary-600 focus:ring-primary-500"
            />
            <span className="text-sm font-medium text-gray-700">File</span>
          </label>
        </div>
      </div>

      {/* Input Content */}
      {inputType === 'text' ? (
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Input Text
          </label>
          <textarea
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder={`Enter text to ${operation}...`}
            className="input-field h-32 resize-none"
            disabled={isLoading}
          />
          <div className="mt-1 text-xs text-gray-500">
            Size: {getInputSize()}
          </div>
        </div>
      ) : (
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Input File
          </label>
          <div
            className={`
              border-2 border-dashed rounded-lg p-6 text-center transition-colors
              ${dragActive 
                ? 'border-primary-400 bg-primary-50' 
                : 'border-gray-300 hover:border-gray-400'
              }
            `}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            {inputFile ? (
              <div className="space-y-2">
                <div className="flex items-center justify-center space-x-2">
                  <FileText className="w-5 h-5 text-green-600" />
                  <span className="text-sm font-medium text-gray-900">
                    {inputFile.name}
                  </span>
                  <button
                    onClick={removeFile}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
                <div className="text-xs text-gray-500">
                  Size: {getInputSize()}
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                <Upload className="mx-auto h-8 w-8 text-gray-400" />
                <div className="text-sm text-gray-600">
                  <span className="font-medium text-primary-600 hover:text-primary-500">
                    Click to upload
                  </span>
                  {' '}or drag and drop
                </div>
                <p className="text-xs text-gray-500">
                  Any file type up to 10MB
                </p>
              </div>
            )}
            <input
              ref={fileInputRef}
              type="file"
              onChange={handleFileChange}
              className="hidden"
              disabled={isLoading}
            />
          </div>
          {!inputFile && (
            <button
              onClick={() => fileInputRef.current?.click()}
              className="mt-2 btn-secondary text-sm"
              disabled={isLoading}
            >
              Choose File
            </button>
          )}
        </div>
      )}

      {/* Custom Key Input */}
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Custom Key (Optional)
        </label>
        <input
          type="text"
          value={customKey}
          onChange={(e) => setCustomKey(e.target.value)}
          placeholder="Leave empty to use default key"
          className="input-field"
          disabled={isLoading}
        />
        <p className="mt-1 text-xs text-gray-500">
          For some algorithms, a custom key may be required for decryption
        </p>
      </div>

      {/* Process Button */}
      <button
        onClick={onProcess}
        disabled={isLoading || (!inputText && !inputFile)}
        className="w-full btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {isLoading ? (
          <div className="flex items-center justify-center space-x-2">
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
            <span>Processing...</span>
          </div>
        ) : (
          `${operation.charAt(0).toUpperCase() + operation.slice(1)} Data`
        )}
      </button>


    </div>
  );
};

export default InputForm; 
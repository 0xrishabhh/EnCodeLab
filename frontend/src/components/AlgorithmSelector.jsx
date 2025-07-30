import React from 'react';

const AlgorithmSelector = ({ selectedAlgorithm, onAlgorithmChange }) => {
  return (
    <div className="space-y-4">
      <div
        onClick={() => onAlgorithmChange('AES')}
        className={`p-2 rounded cursor-pointer text-xs font-medium uppercase tracking-wide transition-colors ${
          selectedAlgorithm === 'AES'
            ? 'bg-primary-100 text-primary-800' 
            : 'hover:bg-gray-100 text-gray-600'
        }`}
      >
        AES
      </div>
      <div
        onClick={() => onAlgorithmChange('3DES')}
        className={`p-2 rounded cursor-pointer text-xs font-medium uppercase tracking-wide transition-colors ${
          selectedAlgorithm === '3DES'
            ? 'bg-primary-100 text-primary-800' 
            : 'hover:bg-gray-100 text-gray-600'
        }`}
      >
        3DES
      </div>
      <div
        onClick={() => onAlgorithmChange('BLOWFISH')}
        className={`p-2 rounded cursor-pointer text-xs font-medium uppercase tracking-wide transition-colors ${
          selectedAlgorithm === 'BLOWFISH'
            ? 'bg-primary-100 text-primary-800' 
            : 'hover:bg-gray-100 text-gray-600'
        }`}
      >
        BLOWFISH
      </div>
    </div>
  );
};

export default AlgorithmSelector; 
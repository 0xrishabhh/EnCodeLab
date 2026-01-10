import React, { useState } from 'react';

const AlgorithmSelector = ({ selectedAlgorithm, onAlgorithmChange }) => {
  const [tooltipPosition, setTooltipPosition] = useState({ x: 0, y: 0 });
  const [hoveredAlgorithm, setHoveredAlgorithm] = useState(null);

  const handleMouseEnter = (algorithm, event) => {
    const rect = event.currentTarget.getBoundingClientRect();
    setTooltipPosition({
      x: rect.right + 10,
      y: rect.top
    });
    setHoveredAlgorithm(algorithm);
  };

  const handleMouseLeave = () => {
    setHoveredAlgorithm(null);
  };
  const displayNames = {
    'AES': 'AES',
    '3DES': '3DES',
    'BLOWFISH': 'Blowfish',
    'RC2': 'RC2',
    'SM4': 'SM4',
    'SALSA20': 'Salsa20',
    'CHACHA20': 'ChaCha20',
    'RAILFENCE': 'Rail Fence',
    'MORSE': 'Morse Code'
  };
  const algorithmInfo = {
    'AES': {
      name: 'Advanced Encryption Standard (AES)',
      description: 'Advanced Encryption Standard (AES) is a U.S. Federal Information Processing Standard (FIPS). It was selected after a 5-year process where 15 competing designs were evaluated.',
      keyInfo: [
        '16 bytes = AES-128',
        '24 bytes = AES-192', 
        '32 bytes = AES-256'
      ],
      keyGeneration: 'You can generate a password-based key using one of the KDF operations.',
      iv: 'The Initialization Vector should be 16 bytes long. If not entered, it will default to 16 null bytes.',
      padding: 'In CBC and ECB mode, PKCS#7 padding will be used.'
    },
    '3DES': {
      name: 'Triple Data Encryption Standard (3DES)',
      description: 'Triple Data Encryption Standard (3DES) applies the DES cipher algorithm three times to each data block. It uses either two or three 56-bit keys.',
      keyInfo: [
        '112 bits (16 bytes) - Two-key 3DES',
        '168 bits (24 bytes) - Three-key 3DES'
      ],
      keyGeneration: 'Keys are generated using secure random methods or derived from passwords.',
      iv: 'The Initialization Vector should be 8 bytes long for CBC, CFB, and OFB modes.',
      padding: 'In CBC and ECB mode, PKCS#7 padding will be used.'
    },
    'BLOWFISH': {
      name: 'Blowfish Cipher',
      description: 'Blowfish is a symmetric-key block cipher with variable-length keys and key-dependent S-boxes. Designed by Bruce Schneier in 1993.',
      keyInfo: [
        '32-448 bits (4-56 bytes) variable length',
        '128 bits (16 bytes) - Common usage',
        '256 bits (32 bytes) - High security'
      ],
      keyGeneration: 'Variable key length provides flexibility in security vs. performance trade-offs.',
      iv: 'The Initialization Vector should be 8 bytes long for CBC, CFB, and OFB modes.',
      padding: 'In CBC and ECB mode, PKCS#7 padding will be used.'
    },
    'RC2': {
      name: 'Rivest Cipher 2 (RC2/ARC2)',
      description: 'RC2 is a variable key-length block cipher designed by Ron Rivest. It has a 64-bit block size and supports variable effective key lengths.',
      keyInfo: [
        '40 bits - Common effective key length',
        '64 bits - Common effective key length',
        '128 bits - Common effective key length',
        'Up to 1024 bits - Maximum'
      ],
      keyGeneration: 'Effective key length can be different from actual key length for compatibility.',
      iv: 'The Initialization Vector should be 8 bytes long for CBC mode.',
      padding: 'In CBC and ECB mode, PKCS#7 padding will be used.'
    },
    'SM4': {
      name: 'SM4 (Chinese National Standard)',
      description: 'SM4 is a symmetric block cipher algorithm standardized by the Chinese government (GB/T 32907-2016). Widely used in Chinese commercial cryptography.',
      keyInfo: [
        '128 bits (16 bytes) - Fixed key length',
        'Block size: 128 bits (16 bytes)',
        '32 rounds with unbalanced Feistel network'
      ],
      keyGeneration: 'Uses cryptographically secure random number generators for 128-bit keys.',
      iv: 'The Initialization Vector should be 16 bytes (128 bits) for CBC, CFB, OFB, CTR modes. GCM uses 12-byte nonce.',
      padding: 'PKCS#7 padding for CBC/ECB modes. Stream modes (CFB, OFB, CTR, GCM) require no padding.'
    },
    'SALSA20': {
      name: 'Salsa20 Stream Cipher',
      description: 'Salsa20 is a fast stream cipher by Daniel J. Bernstein. It XORs a keystream with plaintext for encryption/decryption.',
      keyInfo: [
        '16 bytes (128 bits)',
        '32 bytes (256 bits) recommended',
        'Nonce: 8 bytes'
      ],
      keyGeneration: 'Use random 16- or 32-byte keys. Nonce must be unique per key.',
      iv: 'Nonce is 8 bytes; counter initializes the keystream position.',
      padding: 'No padding (stream cipher).'
    },
    'CHACHA20': {
      name: 'ChaCha20 Stream Cipher',
      description: 'ChaCha20 is a modern stream cipher (RFC 8439) with strong diffusion and great performance on CPUs; typically paired with Poly1305.',
      keyInfo: [
        '32 bytes (256 bits) only',
        'Nonce: 12 bytes (96-bit IETF standard)',
        'Counter: 32-bit block counter'
      ],
      keyGeneration: 'Use random 32-byte keys; never reuse nonce with the same key.',
      iv: 'Nonce is 12 bytes; counter sets keystream block start.',
      padding: 'No padding (stream cipher).'
    },
    'RAILFENCE': {
      name: 'Rail Fence Cipher',
      description: 'Rail Fence is a classical transposition cipher that writes text in a zigzag across rails and reads row by row.',
      keyInfo: [
        'Rails: 2-64',
        'Offset: 0+ (shift start position)',
        'Higher rails increase diffusion but remain reversible',
        'Best for learning, not modern security'
      ],
      keyGeneration: 'Set rails and an optional offset for the zigzag start.',
      iv: 'No IV or nonce required.',
      padding: 'No padding (pure transposition).'
    },
    'MORSE': {
      name: 'Morse Code',
      description: 'Morse Code encodes letters and numbers into dots and dashes separated by configurable delimiters.',
      keyInfo: [
        'Letter delimiter: space (default)',
        'Word delimiter: line feed (default)',
        'Dot symbol: .',
        'Dash symbol: -'
      ],
      keyGeneration: 'No key required. Configure delimiters and dot/dash symbols.',
      iv: 'No IV or nonce required.',
      padding: 'No padding (symbol encoding).'
    }
  };

  return (
    <div className="space-y-4 relative" style={{ zIndex: 10 }}>
      {Object.entries(algorithmInfo).map(([algorithm, info]) => (
        <div
          key={algorithm}
          onClick={() => onAlgorithmChange(algorithm)}
          onMouseEnter={(e) => handleMouseEnter(algorithm, e)}
          onMouseLeave={handleMouseLeave}
          className={`p-2 rounded cursor-pointer text-xs font-medium tracking-wide transition-colors ${
            selectedAlgorithm === algorithm
              ? 'bg-primary-100 text-primary-800' 
              : 'hover:bg-gray-100 text-gray-600'
          }`}
        >
          {displayNames[algorithm] || algorithm}
        </div>
      ))}
      
      {/* Fixed positioned tooltip */}
      {hoveredAlgorithm && (
        <div 
          className="fixed bg-white border border-gray-300 rounded-lg shadow-xl p-4 text-left normal-case tracking-normal z-[99999] max-w-xs"
          style={{
          left: `${Math.max(10, Math.min(tooltipPosition.x, window.innerWidth - 340))}px`,
          top: `${Math.max(10, Math.min(tooltipPosition.y - 130, window.innerHeight - 260))}px`, // center-ish around hover point
          pointerEvents: 'none',
          maxHeight: '70vh',
          overflowY: 'auto'
          }}
        >
          {/* Arrow pointing left */}
          <div className="absolute right-full top-4">
            <div className="w-0 h-0" style={{
              borderTop: '8px solid transparent',
              borderBottom: '8px solid transparent', 
              borderRight: '8px solid #d1d5db'
            }}></div>
            <div className="absolute top-0 right-0 w-0 h-0" style={{
              borderTop: '7px solid transparent',
              borderBottom: '7px solid transparent',
              borderRight: '7px solid white',
              marginRight: '-1px'
            }}></div>
          </div>
          
          <div className="text-sm font-bold text-gray-900 mb-2 border-b border-gray-200 pb-2">
            {algorithmInfo[hoveredAlgorithm]?.name}
          </div>
          
          <div className="text-xs text-gray-700 mb-3 leading-relaxed">
            {algorithmInfo[hoveredAlgorithm]?.description}
          </div>
          
          <div className="space-y-2">
            <div>
              <div className="text-xs font-semibold text-blue-700 mb-1">
                Key:
              </div>
              <div className="text-xs text-gray-600 pl-2">
                {algorithmInfo[hoveredAlgorithm]?.keyInfo.map((keyDetail, index) => (
                  <div key={index} className="mb-0.5">• {keyDetail}</div>
                ))}
              </div>
            </div>
            
            <div className="text-xs text-gray-600 italic bg-gray-50 p-2 rounded">
              {algorithmInfo[hoveredAlgorithm]?.keyGeneration}
            </div>
            
            <div>
              <div className="text-xs font-semibold text-blue-700 mb-1">
                IV:
              </div>
              <div className="text-xs text-gray-600 pl-2">
                {algorithmInfo[hoveredAlgorithm]?.iv}
              </div>
            </div>
            
            <div>
              <div className="text-xs font-semibold text-blue-700 mb-1">
                Padding:
              </div>
              <div className="text-xs text-gray-600 pl-2">
                {algorithmInfo[hoveredAlgorithm]?.padding}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AlgorithmSelector; 

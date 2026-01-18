import React, { useState } from 'react';

const AlgorithmSelector = ({ selectedAlgorithm, onAlgorithmChange, allowedAlgorithms }) => {
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
    'DES': 'DES',
    '3DES': '3DES',
    'BLOWFISH': 'Blowfish',
    'RC2': 'RC2',
    'SM4': 'SM4',
    'SALSA20': 'Salsa20',
    'CHACHA20': 'ChaCha20',
    'RC4': 'RC4',
    'RC4DROP': 'RC4 Drop',
    'RAILFENCE': 'Rail Fence',
    'MORSE': 'Morse Code',
    'VIGENERE': 'Vigenere'
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
    'DES': {
      name: 'Data Encryption Standard (DES)',
      description: 'DES is a 64-bit block cipher standardized as FIPS 46. It uses a 56-bit effective key and 16-round Feistel network, and is now considered insecure.',
      keyInfo: [
        '64-bit key (8 bytes) with 56-bit effective security',
        '8 parity bits (1 per byte)',
        'Weak and semi-weak keys exist; avoid known values'
      ],
      keyGeneration: 'Use a random 8-byte key; parity bits are typically ignored by modern libraries.',
      iv: 'The Initialization Vector should be 8 bytes long for CBC, CFB, OFB, and CTR modes.',
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
    'RC4': {
      name: 'RC4 (Rivest Cipher 4)',
      description: 'RC4 is a stream cipher designed by Ron Rivest in 1987. It is fast and simple but deprecated due to keystream biases. RC4-drop discards the initial keystream dwords to reduce bias.',
      keyInfo: [
        'Passphrase/key length: 1-256 bytes (8-2048 bits)',
        'Longer random keys increase security',
        'RC4-drop: discard 768 or 1024 dwords (x4 bytes) to reduce bias'
      ],
      keyGeneration: 'Use a random passphrase; RC4 has no IV or nonce.',
      iv: 'No IV or nonce required.',
      padding: 'No padding (stream cipher).'
    },
    'RC4DROP': {
      name: 'RC4 Drop (RC4-drop[N])',
      description: 'RC4-drop discards the first N dwords of the keystream to reduce early-output bias. It remains deprecated for modern security.',
      keyInfo: [
        'Passphrase/key length: 1-256 bytes (8-2048 bits)',
        'Drop values: 768 or 1024 dwords are common',
        'Same key/keystream rules as RC4'
      ],
      keyGeneration: 'Use a random passphrase; RC4-drop has no IV or nonce.',
      iv: 'No IV or nonce required.',
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
    },
    'VIGENERE': {
      name: 'Vigenere Cipher',
      description: 'Vigenere is a polyalphabetic substitution cipher that shifts each letter by a repeating keyword.',
      keyInfo: [
        'Keyword uses letters A-Z only',
        'Plaintext and key are uppercased',
        'Spaces and symbols are removed'
      ],
      keyGeneration: 'Choose a keyword; longer keys reduce repetition patterns.',
      iv: 'No IV or nonce required.',
      padding: 'No padding (letters only).'
    }
  };

  const allowedSet = allowedAlgorithms ? new Set(allowedAlgorithms) : null;
  const filteredAlgorithms = Object.entries(algorithmInfo).filter(([algorithm]) => (
    !allowedSet || allowedSet.has(algorithm)
  ));
  const tooltipLines = hoveredAlgorithm
    ? (() => {
        const info = algorithmInfo[hoveredAlgorithm];
        if (!info) return [];
        const lines = [];
        if (info.description) {
          lines.push(info.description);
        }
        if (info.keyInfo && info.keyInfo.length) {
          info.keyInfo.forEach((item) => {
            lines.push(`Key: ${item}`);
          });
        }
        if (info.keyGeneration) {
          lines.push(`Key generation: ${info.keyGeneration}`);
        }
        if (info.iv) {
          lines.push(`IV: ${info.iv}`);
        }
        if (info.padding) {
          lines.push(`Padding: ${info.padding}`);
        }
        return lines;
      })()
    : [];

  return (
    <div className="space-y-4 relative" style={{ zIndex: 10 }}>
      {filteredAlgorithms.map(([algorithm, info]) => (
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
          className="fixed z-[99999] max-w-xs"
          style={{
            left: Math.max(
              12,
              Math.min(
                tooltipPosition.x,
                (typeof window !== 'undefined' ? window.innerWidth : 1024) - 340
              )
            ),
            top: Math.max(
              12,
              Math.min(
                tooltipPosition.y - 80,
                (typeof window !== 'undefined' ? window.innerHeight : 768) - 240
              )
            ),
            pointerEvents: 'none'
          }}
        >
          <div className="relative rounded-lg border border-gray-200 bg-white p-3 text-xs text-gray-700 shadow-xl">
            <div className="absolute right-full top-6">
              <div className="w-0 h-0 border-y-[8px] border-y-transparent border-r-[8px] border-r-gray-200"></div>
              <div className="absolute top-[1px] right-0 w-0 h-0 border-y-[7px] border-y-transparent border-r-[7px] border-r-white"></div>
            </div>
            <div className="text-sm font-semibold text-gray-900 mb-2">
              {algorithmInfo[hoveredAlgorithm]?.name}
            </div>
            <div className="space-y-1">
              {tooltipLines.map((line, index) => (
                <div key={`${hoveredAlgorithm}-info-${index}`}>{line}</div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AlgorithmSelector; 

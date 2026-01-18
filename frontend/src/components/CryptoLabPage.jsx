import React, { useState, useEffect, useMemo } from 'react';
import { ChevronDown } from 'lucide-react';
import ResizablePanel from './ResizablePanel';
import AlgorithmSelector from './AlgorithmSelector';
import { HASH_ITEMS } from './HashingPage';
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

const CRYPTO_GROUPS = [
  {
    id: 'BLOCK',
    label: 'Block Ciphers',
    algorithms: ['AES', 'DES', '3DES', 'BLOWFISH', 'RC2', 'SM4']
  },
  {
    id: 'STREAM',
    label: 'Stream Ciphers',
    algorithms: ['SALSA20', 'CHACHA20', 'RC4', 'RC4DROP']
  },
  {
    id: 'CLASSICAL',
    label: 'Classical / Encoding',
    algorithms: ['RAILFENCE', 'MORSE', 'VIGENERE']
  }
];

const PUBLIC_KEY_ITEMS = [
  { id: 'PEX', label: 'PEX Files', available: false },
  { id: 'JWT', label: 'JWT', available: true },
  { id: 'PGP', label: 'PGP', available: false },
  { id: 'RSA', label: 'RSA', available: false }
];

const PUBLIC_KEY_INFO = {
  JWT: {
    title: 'JWT (JSON Web Token)',
    description: [
      'Decodes a JSON Web Token without checking whether the provided secret / private key is valid. Use "JWT Verify" to check if the signature is valid as well.',
      'Verifies that a JSON Web Token is valid and has been signed with the provided secret / private key. The key should be either the secret for HMAC algorithms or the PEM-encoded private key for RSA and ECDSA.',
      'Signs a JSON object as a JSON Web Token using a provided secret / private key. The key should be either the secret for HMAC algorithms or the PEM-encoded private key for RSA and ECDSA.'
    ]
  }
};

const JWT_ALGORITHMS = [
  'HS256',
  'HS384',
  'HS512',
  'RS256',
  'RS384',
  'RS512',
  'ES256',
  'ES384',
  'ES512'
];

const HASH_DEFAULT_INPUT_FORMAT = 'UTF-8';
const HASH_DEFAULT_OUTPUT_FORMAT = 'HEX';
const SHA1_ROUNDS = 80;
const SHA3_ROUNDS = 24;
const SM3_LENGTH = 256;
const SM3_ROUNDS = 64;
const HASH_INFO = {
  MD2: {
    title: 'MD2 (Message-Digest 2)',
    description: [
      'The MD2 (Message-Digest 2) algorithm is a cryptographic hash function developed by Ronald Rivest in 1989.',
      'The algorithm is optimized for 8-bit computers.',
      'Although MD2 is no longer considered secure, even as of 2014, it remains in use in public key infrastructures as part of certificates generated with MD2 and RSA.',
      'The message digest algorithm consists, by default, of 18 rounds.'
    ]
  },
  MD6: {
    title: 'MD6 (Message-Digest 6)',
    description: [
      'MD6 is a cryptographic hash function designed by Ron Rivest in 2008.',
      'It uses a Merkle tree-like structure to support parallel hashing for long inputs.',
      'Submitted to the NIST SHA-3 competition as a successor to MD5 and SHA-1.',
      'Supports variable output sizes from 128 to 512 bits.',
      'Hashing flow: split input into blocks, compress, combine via tree, and emit final hash.'
    ]
  }
};
const HASH_SHA2_OPTIONS = [
  { label: 'SHA-224', value: 'SHA224' },
  { label: 'SHA-256', value: 'SHA256' },
  { label: 'SHA-384', value: 'SHA384' },
  { label: 'SHA-512', value: 'SHA512' }
];
const HASH_SHA3_OPTIONS = [
  { label: 'SHA3-224', value: 'SHA3-224' },
  { label: 'SHA3-256', value: 'SHA3-256' },
  { label: 'SHA3-384', value: 'SHA3-384' },
  { label: 'SHA3-512', value: 'SHA3-512' }
];
const HASH_SHAKE_OPTIONS = [
  { label: 'SHAKE128', value: 'SHAKE128' },
  { label: 'SHAKE256', value: 'SHAKE256' }
];
const HASH_KECCAK_OPTIONS = [
  { label: '224', value: 224 },
  { label: '256', value: 256 },
  { label: '384', value: 384 },
  { label: '512', value: 512 }
];
const HASH_ALL_ALGOS = [
  'MD2',
  'MD4',
  'MD5',
  'MD6',
  'SHA1',
  'SHA224',
  'SHA256',
  'SHA384',
  'SHA512',
  'SHA3-224',
  'SHA3-256',
  'SHA3-384',
  'SHA3-512',
  'SM3',
  'KECCAK-256',
  'SHAKE128',
  'SHAKE256',
  'CRC32'
];

const analyzeHash = (value) => {
  const trimmed = value.trim();
  if (!trimmed) return [];
  const results = [];

  if (/^\$2[abyx]\$/.test(trimmed)) {
    results.push('BCRYPT ($2a/$2b/$2y/$2x)');
  }

  const hexOnly = /^[0-9a-fA-F]+$/.test(trimmed);
  if (hexOnly) {
    const length = trimmed.length;
    if (length === 8) results.push('CRC32');
    if (length === 32) results.push('MD5 / MD6-128');
    if (length === 40) results.push('SHA1');
    if (length === 56) results.push('SHA224 / MD6-224');
    if (length === 64) results.push('SHA256 / SHA3-256 / SM3 / KECCAK-256 / MD6-256');
    if (length === 96) results.push('SHA384 / SHA3-384 / MD6-384');
    if (length === 128) results.push('SHA512 / SHA3-512 / MD6-512');
  }

  if (results.length === 0) {
    results.push('Unknown or non-hex format');
  }
  return results;
};

const MORSE_DELIMITER_OPTIONS = [
  { label: 'Space', value: 'SPACE' },
  { label: 'Line feed', value: 'LINE_FEED' },
  { label: 'CRLF', value: 'CRLF' },
  { label: 'Forward slash', value: 'FORWARD_SLASH' },
  { label: 'Backslash', value: 'BACKSLASH' },
  { label: 'Comma', value: 'COMMA' },
  { label: 'Semi-colon', value: 'SEMICOLON' },
  { label: 'Colon', value: 'COLON' }
];

const MORSE_LETTER_DELIMITER_OPTIONS = MORSE_DELIMITER_OPTIONS;
const MORSE_WORD_DELIMITER_OPTIONS = MORSE_DELIMITER_OPTIONS;

const MORSE_DELIMITER_VALUES = {
  SPACE: ' ',
  LINE_FEED: '\n',
  CRLF: '\r\n',
  FORWARD_SLASH: '/',
  BACKSLASH: '\\',
  COMMA: ',',
  SEMICOLON: ';',
  COLON: ':'
};

const MORSE_FORMAT_OPTIONS = [
  { label: '-/.', value: '-/.' },
  { label: '/-.', value: '/-.' },
  { label: 'Dash/Dot', value: 'Dash/Dot' },
  { label: 'DASH/DOT', value: 'DASH/DOT' },
  { label: 'dash/dot', value: 'dash/dot' }
];

const MORSE_FORMAT_SYMBOLS = {
  '-/.': { dotSymbol: '.', dashSymbol: '-' },
  '/-.': { dotSymbol: '-', dashSymbol: '.' },
  'Dash/Dot': { dotSymbol: 'Dot', dashSymbol: 'Dash' },
  'DASH/DOT': { dotSymbol: 'DOT', dashSymbol: 'DASH' },
  'dash/dot': { dotSymbol: 'dot', dashSymbol: 'dash' }
};

const getMorseFormatSymbols = (formatOption, fallbackDot = '.', fallbackDash = '-') => {
  const match = MORSE_FORMAT_SYMBOLS[formatOption];
  if (match) {
    return match;
  }
  return { dotSymbol: fallbackDot, dashSymbol: fallbackDash };
};

const inferMorseFormatOption = (dotSymbol, dashSymbol) => {
  const match = Object.entries(MORSE_FORMAT_SYMBOLS).find(([, value]) => (
    value.dotSymbol === dotSymbol && value.dashSymbol === dashSymbol
  ));
  return match ? match[0] : '-/.';
};

const resolveMorseDelimiter = (value, isWordDelimiter) => {
  const resolved = MORSE_DELIMITER_VALUES[value];
  if (resolved !== undefined) {
    return resolved;
  }
  return isWordDelimiter ? '\n' : ' ';
};

const getMorseDelimiterLabel = (value) => {
  const match = MORSE_DELIMITER_OPTIONS.find(option => option.value === value);
  return match ? match.label : value;
};

const formatBytesToHex = (bytes) => (
  Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
);

const normalizeHexInput = (value) => (
  value.trim().replace(/^0x/i, '').replace(/\s+/g, '')
);

const normalizeSecretInput = (value, format, label) => {
  if (!value) return '';
  if (format === 'HEX') {
    const normalized = normalizeHexInput(value);
    if (normalized.length % 2 !== 0) {
      throw new Error(`${label} HEX must have an even length.`);
    }
    if (!/^[0-9a-fA-F]*$/.test(normalized)) {
      throw new Error(`${label} HEX contains invalid characters.`);
    }
    return normalized;
  }
  if (format === 'UTF8') {
    return value;
  }
  if (format === 'LATIN1') {
    for (let i = 0; i < value.length; i += 1) {
      const code = value.charCodeAt(i);
      if (code > 255) {
        throw new Error(`${label} Latin1 must use characters in the 0-255 range.`);
      }
    }
    return value;
  }
  if (format === 'BASE64') {
    try {
      let sanitized = value.replace(/\s+/g, '');
      if (sanitized.length % 4 !== 0) {
        sanitized += '='.repeat(4 - (sanitized.length % 4));
      }
      atob(sanitized);
      return sanitized;
    } catch (error) {
      throw new Error(`${label} Base64 is invalid.`);
    }
  }
  return value;
};

const decodeBase64Url = (value) => {
  if (!value) return null;
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4;
  const padded = normalized + (padding ? '='.repeat(4 - padding) : '');
  try {
    return atob(padded);
  } catch (error) {
    return null;
  }
};

const parseJwtHeader = (token) => {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;
  const decoded = decodeBase64Url(parts[0]);
  if (!decoded) return null;
  try {
    return JSON.parse(decoded);
  } catch (error) {
    return null;
  }
};

const ASCII_KEY_POOL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const ALPHA_KEY_POOL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

const buildRandomAscii = (length) => {
  if (length <= 0) return '';
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let result = '';
  for (let i = 0; i < length; i += 1) {
    result += ASCII_KEY_POOL[bytes[i] % ASCII_KEY_POOL.length];
  }
  return result;
};

const buildRandomAlpha = (length) => {
  if (length <= 0) return '';
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let result = '';
  for (let i = 0; i < length; i += 1) {
    result += ALPHA_KEY_POOL[bytes[i] % ALPHA_KEY_POOL.length];
  }
  return result;
};

const bytesToLatin1 = (bytes) => {
  let result = '';
  for (let i = 0; i < bytes.length; i += 1) {
    result += String.fromCharCode(bytes[i]);
  }
  return result;
};

const bytesToBase64 = (bytes) => {
  return btoa(bytesToLatin1(bytes));
};

const formatSecretBytes = (bytes, format) => {
  if (format === 'HEX') {
    return formatBytesToHex(bytes);
  }
  if (format === 'BASE64') {
    return bytesToBase64(bytes);
  }
  if (format === 'LATIN1') {
    return bytesToLatin1(bytes);
  }
  return formatBytesToHex(bytes);
};

const buildRailFenceGrid = (text, rails, offset = 0, placeholder = '.') => {
  if (!text) return [];
  const railCount = Number.isFinite(rails) ? rails : parseInt(rails, 10);
  if (!railCount || railCount < 2) return [];
  const length = text.length;
  if (!length) return [];

  const pattern = [];
  for (let i = 0; i < railCount; i += 1) pattern.push(i);
  for (let i = railCount - 2; i > 0; i -= 1) pattern.push(i);

  const cycle = pattern.length || 1;
  const start = ((offset || 0) % cycle + cycle) % cycle;
  const rows = Array.from({ length: railCount }, () => Array(length).fill(placeholder));

  for (let i = 0; i < length; i += 1) {
    const row = pattern[(start + i) % cycle];
    rows[row][i] = text[i];
  }

  return rows;
};

const buildRailFenceZigzagString = (grid) => {
  if (!grid || !grid.length) return '';
  return grid.map(row => row.join(' ')).join('\n');
};

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
  const [activeOperationGroup, setActiveOperationGroup] = useState('CRYPTO');
  const [selectedHashOperation, setSelectedHashOperation] = useState('BCRYPT');
  const [hashSha2Variant, setHashSha2Variant] = useState('SHA256');
  const [hashSha3Variant, setHashSha3Variant] = useState('SHA3-256');
  const [hashShakeVariant, setHashShakeVariant] = useState('SHAKE128');
  const [hashShakeLength, setHashShakeLength] = useState(32);
  const [hashKeccakSize, setHashKeccakSize] = useState(256);
  const [hashRounds, setHashRounds] = useState(12);
  const [hashMd2Rounds, setHashMd2Rounds] = useState(18);
  const [hashMd6Size, setHashMd6Size] = useState(256);
  const [hashMd6Levels, setHashMd6Levels] = useState(64);
  const [hashMd6Key, setHashMd6Key] = useState('');
  const [hashAction, setHashAction] = useState('HASH');
  const [hashVerifyValue, setHashVerifyValue] = useState('');
  const [hashTooltipId, setHashTooltipId] = useState(null);
  const [hashTooltipPosition, setHashTooltipPosition] = useState({ x: 0, y: 0 });
  const [publicKeyTooltipId, setPublicKeyTooltipId] = useState(null);
  const [publicKeyTooltipPosition, setPublicKeyTooltipPosition] = useState({ x: 0, y: 0 });
  const [selectedPublicKeyOperation, setSelectedPublicKeyOperation] = useState('JWT');
  const [jwtAction, setJwtAction] = useState('SIGN');
  const [jwtAlgorithm, setJwtAlgorithm] = useState('HS256');
  const [jwtKey, setJwtKey] = useState('');
  const [selectedAlgorithm, setSelectedAlgorithm] = useState('');
  const [selectedMode, setSelectedMode] = useState('CBC'); // All AES modes supported
  const [selectedKeySize, setSelectedKeySize] = useState(''); // AES: 128/192/256, Blowfish: 32-448
  const [inputFormat, setInputFormat] = useState('RAW');
  const [outputFormat, setOutputFormat] = useState('HEX');
  const [inputType, setInputType] = useState('text');
  const [customKey, setCustomKey] = useState('');
  const [customIV, setCustomIV] = useState('');
  const [keyFormat, setKeyFormat] = useState('HEX');
  const [ivFormat, setIvFormat] = useState('HEX');
  const [railOffset, setRailOffset] = useState('0');
  const [morseLetterDelimiter, setMorseLetterDelimiter] = useState('SPACE');
  const [morseWordDelimiter, setMorseWordDelimiter] = useState('LINE_FEED');
  const [morseFormatOption, setMorseFormatOption] = useState('-/.');
  const [morseDotSymbol, setMorseDotSymbol] = useState('.');
  const [morseDashSymbol, setMorseDashSymbol] = useState('-');
  const [salsaRounds, setSalsaRounds] = useState(20);
  const [salsaCounter, setSalsaCounter] = useState(0);
  const [chachaRounds, setChachaRounds] = useState(20);
  const [chachaCounter, setChachaCounter] = useState(0);
  const [rc4Drop, setRc4Drop] = useState('0');
  const [operation, setOperation] = useState('encrypt');
  const [isLoading, setIsLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const [isCryptoOpen, setIsCryptoOpen] = useState(true);
  const [cryptoGroupsOpen, setCryptoGroupsOpen] = useState(() => ({
    BLOCK: true,
    STREAM: true,
    CLASSICAL: true
  }));
  const [isHashingOpen, setIsHashingOpen] = useState(true);
  const [isPublicKeyOpen, setIsPublicKeyOpen] = useState(true);
  
  // Panel width states - set better default widths for proper initial layout
  const [operationsWidth, setOperationsWidth] = useState(216); // 240 - 10% = 216
  const [benchmarkWidth, setBenchmarkWidth] = useState(506); // 460 + 10% = 506
  
  // Panel height states for input/output sections
  const [inputHeight, setInputHeight] = useState(400); // Make input panel much bigger than output

  const activeTab = tabs.find(tab => tab.id === activeTabId) || tabs[0];
  const inputText = activeTab?.inputText || '';
  const inputFile = activeTab?.inputFile || null;
  const result = activeTab?.result || null;
  const isRc4Family = selectedAlgorithm === 'RC4' || selectedAlgorithm === 'RC4DROP';
  const algorithmSummary = selectedAlgorithm === 'RAILFENCE'
    ? `${selectedAlgorithm} (rails: ${customKey || '2-64'}, offset: ${railOffset || '0'})`
    : selectedAlgorithm === 'MORSE'
      ? `Morse Code (letter: ${getMorseDelimiterLabel(morseLetterDelimiter)}, word: ${getMorseDelimiterLabel(morseWordDelimiter)})`
      : selectedAlgorithm === 'VIGENERE'
        ? 'Vigenere (keyword)'
        : selectedAlgorithm === 'RC4'
          ? 'RC4'
          : selectedAlgorithm === 'RC4DROP'
            ? `RC4 Drop (drop: ${rc4Drop || 0} dwords)`
            : `${selectedAlgorithm}-${selectedKeySize}-${selectedMode}`;
  const railFenceRails = selectedAlgorithm === 'RAILFENCE'
    ? parseInt(result?.key || customKey || '', 10)
    : null;
  const railFenceOffset = selectedAlgorithm === 'RAILFENCE'
    ? (Number.isFinite(result?.offset) ? result.offset : parseInt(railOffset, 10) || 0)
    : 0;
  const railFenceInput = useMemo(() => {
    if (selectedAlgorithm !== 'RAILFENCE') return '';
    if (result?.inputData !== undefined) return result.inputData;
    return inputText ? inputText.replace(/\r?\n/g, '') : '';
  }, [selectedAlgorithm, result?.inputData, inputText]);
  const railFenceGrid = useMemo(() => {
    if (selectedAlgorithm !== 'RAILFENCE' || !railFenceInput) return [];
    if (!railFenceRails || railFenceRails < 2) return [];
    return buildRailFenceGrid(railFenceInput, railFenceRails, railFenceOffset, '.');
  }, [selectedAlgorithm, railFenceInput, railFenceRails, railFenceOffset]);
  const railFenceZigzag = useMemo(() => buildRailFenceZigzagString(railFenceGrid), [railFenceGrid]);
  const showRailFenceVisualization = selectedAlgorithm === 'RAILFENCE' && railFenceGrid.length > 0 && result?.output;
  const isHashingMode = activeOperationGroup === 'HASH';
  const isPublicKeyMode = activeOperationGroup === 'PUBLIC_KEY';
  const activeHashItem = HASH_ITEMS.find((item) => item.id === selectedHashOperation);
  const isHashAvailable = activeHashItem ? activeHashItem.available !== false : false;
  const activePublicKeyItem = PUBLIC_KEY_ITEMS.find((item) => item.id === selectedPublicKeyOperation);
  const isPublicKeyAvailable = activePublicKeyItem ? activePublicKeyItem.available !== false : false;
  const publicKeyOutputLabel = selectedPublicKeyOperation === 'JWT'
    ? `JWT-${jwtAction}`
    : (activePublicKeyItem?.label || selectedPublicKeyOperation);
  const resolvedHashAlgorithm = useMemo(() => {
    if (selectedHashOperation === 'SHA2') return hashSha2Variant;
    if (selectedHashOperation === 'SHA3') return hashSha3Variant;
    if (selectedHashOperation === 'SHAKE') return hashShakeVariant;
    if (selectedHashOperation === 'KECCAK') return `KECCAK-${hashKeccakSize}`;
    if (selectedHashOperation === 'CRC32') return 'CRC32';
    return selectedHashOperation;
  }, [selectedHashOperation, hashSha2Variant, hashSha3Variant, hashShakeVariant, hashKeccakSize]);
  const hashOutputLabel = useMemo(() => {
    if (selectedHashOperation === 'ANALYZE') return 'HASH-ANALYZE';
    if (selectedHashOperation === 'ALL') return 'HASH-ALL';
    return resolvedHashAlgorithm;
  }, [resolvedHashAlgorithm, selectedHashOperation]);
  const isHashActionSelectable = selectedHashOperation !== 'ANALYZE' && selectedHashOperation !== 'ALL';
  const isHashVerifyMode = isHashActionSelectable && hashAction === 'VERIFY';
  const outputAlgorithmLabel = isHashingMode
    ? hashOutputLabel
    : (isPublicKeyMode ? publicKeyOutputLabel : selectedAlgorithm);
  const shaRounds = useMemo(() => {
    if (selectedHashOperation === 'SHA1') return SHA1_ROUNDS;
    if (selectedHashOperation === 'SHA2') {
      return ['SHA224', 'SHA256'].includes(hashSha2Variant) ? 64 : 80;
    }
    if (selectedHashOperation === 'SHA3') return SHA3_ROUNDS;
    return null;
  }, [selectedHashOperation, hashSha2Variant]);
  const hashTooltipInfo = hashTooltipId ? HASH_INFO[hashTooltipId] : null;
  const publicKeyTooltipInfo = publicKeyTooltipId ? PUBLIC_KEY_INFO[publicKeyTooltipId] : null;
  const hashActionLabel = selectedHashOperation === 'ANALYZE'
    ? 'Analyze'
    : selectedHashOperation === 'ALL'
      ? 'Generate Hashes'
      : (isHashVerifyMode ? 'Verify' : 'Hash');
  const hashActionDisabled = isLoading
    || !isHashAvailable
    || (!inputText && !inputFile)
    || (isHashVerifyMode && !hashVerifyValue);
  const jwtActionLabel = jwtAction === 'SIGN'
    ? 'JWT Sign'
    : (jwtAction === 'VERIFY' ? 'JWT Verify' : 'JWT Decode');
  const publicKeyActionLabel = selectedPublicKeyOperation === 'JWT'
    ? jwtActionLabel
    : 'Coming Soon';
  const jwtRequiresKey = jwtAction === 'SIGN' || jwtAction === 'VERIFY';
  const publicKeyActionDisabled = isLoading
    || !isPublicKeyAvailable
    || (!inputText && !inputFile)
    || (selectedPublicKeyOperation === 'JWT' && jwtRequiresKey && !jwtKey.trim());
  const isJwtSign = jwtAction === 'SIGN';
  const isJwtVerify = jwtAction === 'VERIFY';
  const isJwtDecode = jwtAction === 'DECODE';

  const updateActiveTab = (updates) => {
    setTabs(prevTabs => prevTabs.map(tab => (
      tab.id === activeTabId ? { ...tab, ...updates } : tab
    )));
  };

  const handleAlgorithmSelect = (algorithm) => {
    setActiveOperationGroup('CRYPTO');
    setSelectedAlgorithm(algorithm);
  };

  const handleHashSelect = (hashId) => {
    setActiveOperationGroup('HASH');
    setSelectedHashOperation(hashId);
  };

  const handlePublicKeySelect = (itemId) => {
    setActiveOperationGroup('PUBLIC_KEY');
    setSelectedPublicKeyOperation(itemId);
  };

  const toggleCryptoGroup = (groupId) => {
    setCryptoGroupsOpen(prev => ({
      ...prev,
      [groupId]: !prev[groupId]
    }));
  };

  const handleHashMouseEnter = (hashId, event) => {
    if (!HASH_INFO[hashId]) return;
    const rect = event.currentTarget.getBoundingClientRect();
    setHashTooltipId(hashId);
    setHashTooltipPosition({
      x: rect.right + 12,
      y: rect.top
    });
  };

  const handleHashMouseLeave = () => {
    setHashTooltipId(null);
  };

  const handlePublicKeyMouseEnter = (itemId, event) => {
    if (!PUBLIC_KEY_INFO[itemId]) return;
    const rect = event.currentTarget.getBoundingClientRect();
    setPublicKeyTooltipId(itemId);
    setPublicKeyTooltipPosition({
      x: rect.right + 12,
      y: rect.top
    });
  };

  const handlePublicKeyMouseLeave = () => {
    setPublicKeyTooltipId(null);
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
    const isRc4Selection = selectedAlgorithm === 'RC4' || selectedAlgorithm === 'RC4DROP';
    if (selectedAlgorithm === 'RAILFENCE') {
      setSelectedMode('RAILFENCE');
      setSelectedKeySize('');
      setCustomIV('');
      setRailOffset('0');
      setCustomKey('3');
      setInputFormat('RAW');
      setOutputFormat('RAW');
      return;
    }
    if (selectedAlgorithm === 'MORSE') {
      setSelectedMode('MORSE');
      setSelectedKeySize('');
      setCustomKey('');
      setCustomIV('');
      setInputFormat('RAW');
      setOutputFormat('RAW');
      setMorseLetterDelimiter('SPACE');
      setMorseWordDelimiter('LINE_FEED');
      setMorseFormatOption('-/.');
      setMorseDotSymbol('.');
      setMorseDashSymbol('-');
      return;
    }
    if (selectedAlgorithm === 'VIGENERE') {
      setSelectedMode('VIGENERE');
      setSelectedKeySize('');
      setCustomKey('');
      setCustomIV('');
      setInputFormat('RAW');
      setOutputFormat('RAW');
      return;
    }
    if (selectedAlgorithm === 'RC4') {
      setSelectedMode('STREAM');
      setSelectedKeySize('128');
      setCustomIV('');
      setKeyFormat('UTF8');
      setInputFormat('LATIN1');
      setOutputFormat('LATIN1');
      setRc4Drop('0');
      return;
    }
    if (selectedAlgorithm === 'RC4DROP') {
      setSelectedMode('STREAM');
      setSelectedKeySize('128');
      setCustomIV('');
      setKeyFormat('UTF8');
      setInputFormat('LATIN1');
      setOutputFormat('LATIN1');
      setRc4Drop('768');
      return;
    }
    if (!isRc4Selection) {
      if (!['RAW', 'HEX'].includes(inputFormat)) {
        setInputFormat('RAW');
      }
      if (!['HEX', 'RAW'].includes(outputFormat)) {
        setOutputFormat('HEX');
      }
    }
    // Reset mode for algorithms that don't support CTR/GCM
    if ((selectedAlgorithm === '3DES' || selectedAlgorithm === 'BLOWFISH') && ['CTR', 'GCM'].includes(selectedMode)) {
      setSelectedMode('CBC'); // Reset to a supported mode for 3DES and Blowfish
    }
    if (selectedAlgorithm === 'DES' && selectedMode === 'GCM') {
      setSelectedMode('CBC'); // Reset to a supported mode for DES
    }
    if (!(selectedAlgorithm === 'SALSA20' || selectedAlgorithm === 'CHACHA20' || selectedAlgorithm === 'RC4' || selectedAlgorithm === 'RC4DROP') && selectedMode === 'STREAM') {
      setSelectedMode('CBC');
    }
    
    // RC2 only supports CBC and ECB modes
    if (selectedAlgorithm === 'RC2' && !['CBC', 'ECB'].includes(selectedMode)) {
      setSelectedMode('CBC'); // Reset to CBC for RC2
    }
    
    // Set default key sizes based on algorithm
    if (selectedAlgorithm === 'AES') {
      setSelectedKeySize('256'); // Default to AES-256
    } else if (selectedAlgorithm === 'DES') {
      setSelectedKeySize('64'); // Default to 64-bit DES key
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
    } else if (selectedAlgorithm === 'RC4' || selectedAlgorithm === 'RC4DROP') {
      setSelectedKeySize('128');
    } else {
      setSelectedKeySize('');
    }
  }, [selectedAlgorithm, selectedMode]);

  useEffect(() => {
    if (selectedAlgorithm === 'SALSA20' || selectedAlgorithm === 'CHACHA20' || selectedAlgorithm === 'RC4' || selectedAlgorithm === 'RC4DROP') {
      setSelectedMode('STREAM');
      if (selectedAlgorithm !== 'RC4' && selectedAlgorithm !== 'RC4DROP') {
        setSelectedKeySize('256');
      }
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

  useEffect(() => {
    if (selectedHashOperation === 'ANALYZE' || selectedHashOperation === 'ALL') {
      setHashAction('HASH');
    }
    setHashVerifyValue('');
  }, [selectedHashOperation]);

  // Generate random key based on selected algorithm and key size
  const generateRandomKey = () => {
    let keyLength;
    
    if (selectedAlgorithm === 'RAILFENCE') {
      const minRails = 2;
      const maxRails = 10;
      const rails = Math.floor(Math.random() * (maxRails - minRails + 1)) + minRails;
      setCustomKey(String(rails));
      return;
    }
    if (selectedAlgorithm === 'MORSE') {
      setCustomKey('');
      return;
    }
    if (selectedAlgorithm === 'VIGENERE') {
      setCustomKey(buildRandomAlpha(8));
      return;
    }

    if (selectedAlgorithm === 'AES') {
      // AES key sizes: 128, 192, 256 bits
      const keySize = parseInt(selectedKeySize);
      keyLength = keySize / 8; // Convert bits to bytes
    } else if (selectedAlgorithm === 'DES') {
      // DES key size: 64 bits (8 bytes, 56-bit effective)
      keyLength = 8;
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
    } else if (selectedAlgorithm === 'RC4' || selectedAlgorithm === 'RC4DROP') {
      const keySize = parseInt(selectedKeySize);
      keyLength = Number.isFinite(keySize) ? keySize / 8 : 16;
    } else if (selectedAlgorithm === 'CHACHA20') {
      keyLength = 32; // 256-bit
    } else {
      keyLength = 32; // Default fallback
    }
    
    const array = new Uint8Array(keyLength);
    crypto.getRandomValues(array);
    if (keyFormat === 'UTF8') {
      setCustomKey(buildRandomAscii(keyLength));
      return;
    }
    setCustomKey(formatSecretBytes(array, keyFormat));
  };

  // Generate random IV
  const generateRandomIV = () => {
    let ivLength;
    if (selectedAlgorithm === 'RAILFENCE') {
      setCustomIV('');
      return;
    }
    if (selectedAlgorithm === 'RC4' || selectedAlgorithm === 'RC4DROP') {
      setCustomIV('');
      return;
    }
    if (selectedAlgorithm === 'MORSE') {
      setCustomIV('');
      return;
    }
    if (selectedAlgorithm === 'DES' || selectedAlgorithm === '3DES' || selectedAlgorithm === 'BLOWFISH' || selectedAlgorithm === 'RC2') {
      ivLength = 8; // 64-bit for DES, 3DES, Blowfish, and RC2
    } else if (selectedAlgorithm === 'SALSA20') {
      ivLength = 8; // Salsa20 nonce size
    } else if (selectedAlgorithm === 'CHACHA20') {
      ivLength = 12; // ChaCha20 nonce size (IETF)
    } else {
      ivLength = 16; // 128-bit for AES
    }
    const array = new Uint8Array(ivLength);
    crypto.getRandomValues(array);
    if (ivFormat === 'UTF8') {
      setCustomIV(buildRandomAscii(ivLength));
      return;
    }
    setCustomIV(formatSecretBytes(array, ivFormat));
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
      if (selectedAlgorithm === 'RAILFENCE') {
        inputData = inputData.replace(/\r?\n/g, '');
      }
      if (selectedAlgorithm === 'MORSE') {
        const dotSymbol = morseDotSymbol || '.';
        const dashSymbol = morseDashSymbol || '-';
        if (!dotSymbol || !dashSymbol) {
          alert('Morse dot and dash symbols cannot be empty.');
          return;
        }
        if (dotSymbol === dashSymbol) {
          alert('Morse dot and dash symbols must be different.');
          return;
        }
      }
      if (selectedAlgorithm === 'VIGENERE' && !customKey.trim()) {
        alert('Vigenere key is required.');
        return;
      }
      let rc4DropValue = 0;
        if (selectedAlgorithm === 'RC4DROP') {
          const parsedDrop = parseInt(rc4Drop, 10);
          if (!Number.isFinite(parsedDrop) || parsedDrop < 0) {
            alert('RC4 drop must be a non-negative integer.');
            return;
          }
          rc4DropValue = parsedDrop;
        }

      let normalizedKey;
      let normalizedIV;
      if (selectedAlgorithm !== 'RAILFENCE' && selectedAlgorithm !== 'MORSE' && selectedAlgorithm !== 'VIGENERE') {
        try {
          if (customKey) {
            normalizedKey = normalizeSecretInput(customKey, keyFormat, 'Key');
          }
          if (customIV) {
            normalizedIV = normalizeSecretInput(customIV, ivFormat, 'IV/Nonce');
          }
        } catch (error) {
          alert(error.message);
          return;
        }
      }

      const isClassicAlgorithm = ['RAILFENCE', 'MORSE', 'VIGENERE'].includes(selectedAlgorithm);
      const requestData = {
        algorithm: selectedAlgorithm === 'RC4DROP' ? 'RC4' : selectedAlgorithm,
        mode: selectedMode,
        input: inputData,
        inputFormat: inputFormat,
        outputFormat: outputFormat,
        key: isClassicAlgorithm
          ? (selectedAlgorithm === 'VIGENERE' ? customKey : undefined)
          : (normalizedKey || undefined),
        iv_or_nonce: isClassicAlgorithm ? undefined : (normalizedIV || undefined),
        key_format: isClassicAlgorithm ? undefined : keyFormat,
        iv_format: isClassicAlgorithm ? undefined : ivFormat
      };
        if (selectedAlgorithm === 'RC4DROP') {
          requestData.drop = rc4DropValue;
          requestData.drop_unit = 'DWORD';
        }
      if (selectedAlgorithm === 'MORSE') {
        requestData.letter_delimiter = resolveMorseDelimiter(morseLetterDelimiter, false);
        requestData.word_delimiter = resolveMorseDelimiter(morseWordDelimiter, true);
        requestData.dot_symbol = morseDotSymbol || '.';
        requestData.dash_symbol = morseDashSymbol || '-';
      } else if (selectedAlgorithm !== 'RAILFENCE') {
        requestData.keySize = selectedKeySize ? parseInt(selectedKeySize, 10) / 8 : undefined; // Convert bits to bytes
      } else {
        if (customKey) {
          requestData.rails = parseInt(customKey, 10);
        }
        requestData.offset = parseInt(railOffset, 10) || 0;
      }
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
        if (selectedAlgorithm !== 'MORSE' && !customKey) {
          alert('Key is required for decryption');
          return;
        }
        if (selectedAlgorithm === 'MORSE' && result?.caseSequence && result?.output === inputData) {
          requestData.case_sequence = result.caseSequence;
        }
        // Try to get IV from previous result
        if (result?.iv_or_nonce) {
          requestData.iv_or_nonce = result.iv_or_nonce;
          if (result?.ivFormat) {
            requestData.iv_format = result.ivFormat;
          }
        }
        if (result?.tag) {
          requestData.tag = result.tag;
        }
        response = await cryptoAPI.decrypt(requestData);
      }

      if (response.success) {
        const enrichedResponse = { ...response, inputData, operation };
        setActiveResult(enrichedResponse);
        if (selectedAlgorithm === 'RC4DROP' && response.drop !== undefined) {
          setRc4Drop(String(response.drop));
        }
        
        // Add to history
        const historyItem = {
          ...enrichedResponse,
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

  const handleHashProcess = async () => {
    if (!selectedHashOperation) {
      alert('Please select a hash.');
      return;
    }
    if (!inputText && !inputFile) {
      alert(isHashVerifyMode ? 'Please provide a hash to verify.' : 'Please provide input data.');
      return;
    }
    if (!isHashAvailable) {
      alert('This hash is queued for integration.');
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
      if (!inputData) {
        alert(isHashVerifyMode ? 'Please provide a hash to verify.' : 'Please provide input data.');
        return;
      }

      let outputText = '';
      let operationLabel = 'hash';
      const parsedShakeLength = Number(hashShakeLength);
      const resolvedShakeLength = Number.isFinite(parsedShakeLength) && parsedShakeLength > 0
        ? parsedShakeLength
        : undefined;
      const parsedMd2Rounds = Number(hashMd2Rounds);
      const resolvedMd2Rounds = Number.isFinite(parsedMd2Rounds) && parsedMd2Rounds > 0
        ? parsedMd2Rounds
        : undefined;
      const resolvedMd6Size = selectedHashOperation === 'MD6'
        ? Number(hashMd6Size)
        : undefined;
      const resolvedMd6Levels = selectedHashOperation === 'MD6'
        ? Number(hashMd6Levels)
        : undefined;

      if (selectedHashOperation === 'MD6') {
        if (!Number.isFinite(resolvedMd6Size) || resolvedMd6Size < 128 || resolvedMd6Size > 512) {
          alert('MD6 size must be between 128 and 512 bits.');
          return;
        }
        if (!Number.isFinite(resolvedMd6Levels) || resolvedMd6Levels <= 0) {
          alert('MD6 levels must be a positive integer.');
          return;
        }
      }

      if (selectedHashOperation === 'ANALYZE') {
        const results = analyzeHash(inputData);
        outputText = results.join('\n');
        operationLabel = 'analyze';
      } else if (selectedHashOperation === 'ALL') {
        const response = await cryptoAPI.hashAll({
          input: inputData,
          inputFormat: HASH_DEFAULT_INPUT_FORMAT,
          outputFormat: HASH_DEFAULT_OUTPUT_FORMAT,
          algorithms: HASH_ALL_ALGOS,
          length: resolvedShakeLength
        });
        if (!response.success) {
          throw new Error(response.error || 'Hash-all failed');
        }
        const hashes = response.result.hashes || [];
        outputText = hashes.map((entry) => `${entry.algorithm}: ${entry.hash}`).join('\n');
        if (!outputText) {
          outputText = 'No hashes generated.';
        }
        operationLabel = 'hash_all';
      } else if (isHashVerifyMode) {
        if (!hashVerifyValue) {
          alert('Provide input data to verify.');
          return;
        }
        const hashToVerify = inputData;
        if (selectedHashOperation === 'BCRYPT') {
          const response = await cryptoAPI.verifyHash({
            algorithm: resolvedHashAlgorithm,
            input: hashVerifyValue,
            inputFormat: HASH_DEFAULT_INPUT_FORMAT,
            hash: hashToVerify,
            hashFormat: HASH_DEFAULT_OUTPUT_FORMAT
          });
          if (!response.success) {
            throw new Error(response.error || 'Verification failed');
          }
          const verified = Boolean(response.result.verified);
          outputText = verified ? 'Verified.' : 'Not verified.';
        } else {
          const response = await cryptoAPI.hash({
            algorithm: resolvedHashAlgorithm,
            input: hashVerifyValue,
            inputFormat: HASH_DEFAULT_INPUT_FORMAT,
            outputFormat: HASH_DEFAULT_OUTPUT_FORMAT,
            rounds: selectedHashOperation === 'MD2' ? resolvedMd2Rounds : undefined,
            length: selectedHashOperation === 'SHAKE' ? resolvedShakeLength : undefined,
            size: selectedHashOperation === 'MD6' ? resolvedMd6Size : undefined,
            levels: selectedHashOperation === 'MD6' ? resolvedMd6Levels : undefined,
            key: selectedHashOperation === 'MD6' ? hashMd6Key : undefined
          });
          if (!response.success) {
            throw new Error(response.error || 'Verification failed');
          }
          const expectedHash = (response.result.hash || '').trim();
          const normalizedExpected = expectedHash.replace(/\s+/g, '').toLowerCase();
          const normalizedProvided = String(hashToVerify || '').replace(/\s+/g, '').toLowerCase();
          if (!normalizedProvided || !/^[0-9a-f]+$/.test(normalizedProvided)) {
            throw new Error('Hash to verify must be HEX.');
          }
          const verified = normalizedExpected === normalizedProvided;
          outputText = verified ? 'Verified.' : 'Not verified.';
        }
        operationLabel = 'verify';
      } else {
        const response = await cryptoAPI.hash({
          algorithm: resolvedHashAlgorithm,
          input: inputData,
          inputFormat: HASH_DEFAULT_INPUT_FORMAT,
          outputFormat: HASH_DEFAULT_OUTPUT_FORMAT,
          rounds: selectedHashOperation === 'BCRYPT'
            ? Number(hashRounds)
            : (selectedHashOperation === 'MD2' ? resolvedMd2Rounds : undefined),
          length: selectedHashOperation === 'SHAKE' ? resolvedShakeLength : undefined,
          size: selectedHashOperation === 'MD6' ? resolvedMd6Size : undefined,
          levels: selectedHashOperation === 'MD6' ? resolvedMd6Levels : undefined,
          key: selectedHashOperation === 'MD6' ? hashMd6Key : undefined
        });
        if (!response.success) {
          throw new Error(response.error || 'Hashing failed');
        }
        outputText = response.result.hash || '';
      }

      const enrichedResponse = {
        output: outputText,
        inputData,
        operation: operationLabel,
        algorithm: hashOutputLabel,
        outputFormat: HASH_DEFAULT_OUTPUT_FORMAT
      };
      setActiveResult(enrichedResponse);

      const historyItem = {
        ...enrichedResponse,
        timestamp: new Date().toISOString()
      };
      setHistory(prev => [historyItem, ...prev.slice(0, 4)]);
    } catch (error) {
      console.error('Hashing error:', error);
      alert(error.message || 'Hashing failed. Please check your input and try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePublicKeyProcess = async () => {
    if (!selectedPublicKeyOperation) {
      alert('Please select a public key item.');
      return;
    }
    if (!inputText && !inputFile) {
      alert('Please provide input data.');
      return;
    }
    if (!isPublicKeyAvailable) {
      alert('This item is queued for integration.');
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
      if (!inputData) {
        alert('Please provide input data.');
        return;
      }

      let outputText = '';
      let operationLabel = jwtAction.toLowerCase();

      if (selectedPublicKeyOperation === 'JWT') {
        if (jwtAction === 'SIGN') {
          if (!jwtKey.trim()) {
            alert('Key is required for signing.');
            return;
          }
          const response = await cryptoAPI.jwtSign({
            payload: inputData,
            key: jwtKey,
            algorithm: jwtAlgorithm
          });
          if (!response.success) {
            throw new Error(response.error || 'JWT sign failed');
          }
          outputText = JSON.stringify({
            token: response.result.token,
            header: response.result.header,
            payload: response.result.payload
          }, null, 2);
        } else if (jwtAction === 'VERIFY') {
          if (!jwtKey.trim()) {
            alert('Key is required for verification.');
            return;
          }
          const tokenInput = inputData.trim();
          if (!tokenInput) {
            alert('Please provide a JWT to verify.');
            return;
          }
          const header = parseJwtHeader(tokenInput);
          const headerAlg = header?.alg;
          if (!headerAlg) {
            alert('Unable to detect JWT algorithm from token header.');
            return;
          }
          if (!JWT_ALGORITHMS.includes(headerAlg)) {
            alert(`Unsupported JWT algorithm: ${headerAlg}.`);
            return;
          }
          const response = await cryptoAPI.jwtVerify({
            token: tokenInput,
            key: jwtKey,
            algorithm: headerAlg
          });
          if (!response.success) {
            throw new Error(response.error || 'JWT verify failed');
          }
          outputText = JSON.stringify(response.result, null, 2);
        } else {
          const tokenInput = inputData.trim();
          if (!tokenInput) {
            alert('Please provide a JWT to decode.');
            return;
          }
          const response = await cryptoAPI.jwtDecode({
            token: tokenInput
          });
          if (!response.success) {
            throw new Error(response.error || 'JWT decode failed');
          }
          outputText = JSON.stringify(response.result, null, 2);
        }
      }

      const enrichedResponse = {
        output: outputText,
        inputData,
        operation: operationLabel,
        algorithm: selectedPublicKeyOperation,
        outputFormat: 'JSON'
      };
      setActiveResult(enrichedResponse);

      const historyItem = {
        ...enrichedResponse,
        timestamp: new Date().toISOString()
      };
      setHistory(prev => [historyItem, ...prev.slice(0, 4)]);
    } catch (error) {
      console.error('Public key error:', error);
      alert(error.message || 'Public key operation failed. Please check your input and try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const hashingPanel = (
    <>
      <div className="p-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900">Hashing</h2>
          <span className="text-xs text-gray-500">{activeHashItem?.label || 'Select a hash'}</span>
        </div>
      </div>
      <div className="flex-1 p-4 overflow-y-auto min-h-0">
        <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-lg font-semibold text-gray-900">
                {activeHashItem?.label || 'Hashing'}
              </div>
            </div>
            {!isHashAvailable && <span className="text-xs text-gray-500">Soon</span>}
          </div>

          {!isHashAvailable ? (
            <div className="text-sm text-gray-600">This hash is queued for integration.</div>
          ) : (
            <div className="space-y-4">
              {selectedHashOperation === 'ANALYZE' && (
                <div className="text-sm text-gray-600">
                  Paste a hash string into the input panel to analyze likely matches.
                </div>
              )}
              {selectedHashOperation === 'ALL' && (
                <div className="text-sm text-gray-600">
                  Generate a bundle of common digests for the current input.
                </div>
              )}
              {(selectedHashOperation === 'SHA1'
                || selectedHashOperation === 'SHA2'
                || selectedHashOperation === 'SHA3'
                || selectedHashOperation === 'SHAKE'
                || selectedHashOperation === 'BCRYPT'
                || selectedHashOperation === 'MD2'
                || selectedHashOperation === 'MD6'
                || selectedHashOperation === 'SM3'
                || selectedHashOperation === 'KECCAK') && (
                <div className={`grid gap-3 ${
                  (selectedHashOperation === 'MD2'
                    || selectedHashOperation === 'SHA1'
                    || selectedHashOperation === 'KECCAK') ? 'grid-cols-1' : 'grid-cols-2'
                }`}>
                  {selectedHashOperation === 'SHA2' && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Size</label>
                      <select
                        value={hashSha2Variant}
                        onChange={(e) => setHashSha2Variant(e.target.value)}
                        className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        {HASH_SHA2_OPTIONS.map((option) => (
                          <option key={option.value} value={option.value}>{option.label}</option>
                        ))}
                      </select>
                    </div>
                  )}
                  {selectedHashOperation === 'SHA2' && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Rounds</label>
                      <input
                        type="number"
                        value={shaRounds ?? ''}
                        disabled
                        className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-gray-50 text-gray-600"
                      />
                    </div>
                  )}
                  {selectedHashOperation === 'SHA3' && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Size</label>
                      <select
                        value={hashSha3Variant}
                        onChange={(e) => setHashSha3Variant(e.target.value)}
                        className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        {HASH_SHA3_OPTIONS.map((option) => (
                          <option key={option.value} value={option.value}>{option.label}</option>
                        ))}
                      </select>
                    </div>
                  )}
                  {selectedHashOperation === 'KECCAK' && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Size</label>
                      <select
                        value={hashKeccakSize}
                        onChange={(e) => setHashKeccakSize(Number(e.target.value))}
                        className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        {HASH_KECCAK_OPTIONS.map((option) => (
                          <option key={option.value} value={option.value}>{option.label}</option>
                        ))}
                      </select>
                    </div>
                  )}
                  {selectedHashOperation === 'SHA3' && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Rounds</label>
                      <input
                        type="number"
                        value={shaRounds ?? ''}
                        disabled
                        className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-gray-50 text-gray-600"
                      />
                    </div>
                  )}
                  {selectedHashOperation === 'SHA1' && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Rounds</label>
                      <input
                        type="number"
                        value={shaRounds ?? ''}
                        disabled
                        className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-gray-50 text-gray-600"
                      />
                    </div>
                  )}
                  {selectedHashOperation === 'SHAKE' && (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Variant</label>
                        <select
                          value={hashShakeVariant}
                          onChange={(e) => setHashShakeVariant(e.target.value)}
                          className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                        >
                          {HASH_SHAKE_OPTIONS.map((option) => (
                            <option key={option.value} value={option.value}>{option.label}</option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Output Length (bytes)</label>
                        <input
                          type="number"
                          min="1"
                          value={hashShakeLength}
                          onChange={(e) => setHashShakeLength(e.target.value)}
                          className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                      </div>
                    </>
                  )}
                  {selectedHashOperation === 'BCRYPT' && (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Rounds</label>
                        <input
                          type="number"
                          min="4"
                          max="31"
                          value={hashRounds}
                          onChange={(e) => setHashRounds(e.target.value)}
                          className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                      </div>
                    </>
                  )}
                  {selectedHashOperation === 'MD2' && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Rounds</label>
                      <input
                        type="number"
                        min="1"
                        value={hashMd2Rounds}
                        onChange={(e) => setHashMd2Rounds(e.target.value)}
                        className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <div className="text-xs text-gray-500 mt-1">Default: 18 rounds</div>
                    </div>
                  )}
                  {selectedHashOperation === 'MD6' && (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Size (bits)</label>
                        <input
                          type="number"
                          min="128"
                          max="512"
                          value={hashMd6Size}
                          onChange={(e) => setHashMd6Size(e.target.value)}
                          className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Levels</label>
                        <input
                          type="number"
                          min="1"
                          value={hashMd6Levels}
                          onChange={(e) => setHashMd6Levels(e.target.value)}
                          className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                      </div>
                      <div className="col-span-2">
                        <label className="block text-sm font-medium text-gray-700 mb-1">Key (optional)</label>
                        <input
                          type="text"
                          value={hashMd6Key}
                          onChange={(e) => setHashMd6Key(e.target.value)}
                          className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                          placeholder="Enter MD6 key (optional)"
                        />
                      </div>
                    </>
                  )}
                  {selectedHashOperation === 'SM3' && (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Length</label>
                        <input
                          type="number"
                          value={SM3_LENGTH}
                          disabled
                          className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-gray-50 text-gray-600"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Rounds</label>
                        <input
                          type="number"
                          value={SM3_ROUNDS}
                          disabled
                          className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-gray-50 text-gray-600"
                        />
                      </div>
                    </>
                  )}
                </div>
              )}

              {selectedHashOperation === 'ALL' && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">SHAKE Output Length (bytes)</label>
                  <input
                    type="number"
                    min="1"
                    value={hashShakeLength}
                    onChange={(e) => setHashShakeLength(e.target.value)}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              )}

              {isHashActionSelectable && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Mode</label>
                  <select
                    value={hashAction}
                    onChange={(e) => setHashAction(e.target.value)}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="HASH">Hash</option>
                    <option value="VERIFY">Verify</option>
                  </select>
                </div>
              )}

              {isHashVerifyMode && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Input to verify</label>
                  <div className="text-xs text-gray-500 mb-2">
                    {selectedHashOperation === 'BCRYPT'
                      ? 'Paste the bcrypt hash in the input panel.'
                      : 'Paste the hash in the input panel (HEX).'}
                  </div>
                  <textarea
                    value={hashVerifyValue}
                    onChange={(e) => setHashVerifyValue(e.target.value)}
                    className="w-full h-24 resize-none border border-gray-300 rounded-md px-3 py-2 text-xs font-mono bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder={
                      selectedHashOperation === 'BCRYPT'
                        ? 'Enter password to verify'
                        : 'Enter input data to verify'
                    }
                  />
                </div>
              )}
            </div>
          )}
        </div>

        <div className="mt-4">
          <button
            onClick={handleHashProcess}
            disabled={hashActionDisabled}
            className="w-full bg-gradient-to-r from-gray-800 to-gray-900 hover:from-gray-900 hover:to-black disabled:opacity-50 disabled:cursor-not-allowed text-white px-5 py-2.5 rounded-lg font-semibold shadow-lg hover:shadow-xl transition-all duration-200 transform hover:scale-105 disabled:hover:scale-100"
          >
            {isLoading ? 'Working...' : hashActionLabel}
          </button>
        </div>
      </div>
    </>
  );

  const publicKeyPanel = (
    <>
      <div className="p-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900">Public Key</h2>
          <span className="text-xs text-gray-500">{activePublicKeyItem?.label || 'Select an item'}</span>
        </div>
      </div>
      <div className="flex-1 p-4 overflow-y-auto min-h-0">
        <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <div className="text-lg font-semibold text-gray-900">
              {activePublicKeyItem?.label || 'Public Key'}
            </div>
            {!isPublicKeyAvailable && <span className="text-xs text-gray-500">Soon</span>}
          </div>

          {!isPublicKeyAvailable ? (
            <div className="text-sm text-gray-600">This item is queued for integration.</div>
          ) : (
            <div className="space-y-4">
              {selectedPublicKeyOperation === 'JWT' && (
                <>
                  <div className={`grid grid-cols-1 ${isJwtSign ? 'md:grid-cols-2' : ''} gap-3`}>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Action</label>
                      <select
                        value={jwtAction}
                        onChange={(e) => setJwtAction(e.target.value)}
                        className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        <option value="SIGN">JWT Sign</option>
                        <option value="VERIFY">JWT Verify</option>
                        <option value="DECODE">JWT Decode</option>
                      </select>
                    </div>
                    {isJwtSign && (
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Signing algorithm</label>
                        <select
                          value={jwtAlgorithm}
                          onChange={(e) => setJwtAlgorithm(e.target.value)}
                          className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                        >
                          {JWT_ALGORITHMS.map((algorithm) => (
                            <option key={algorithm} value={algorithm}>{algorithm}</option>
                          ))}
                        </select>
                      </div>
                    )}
                  </div>

                  {!isJwtDecode && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        {isJwtVerify ? 'Secret / Public Key' : 'Secret / Private Key'}
                      </label>
                      <textarea
                        value={jwtKey}
                        onChange={(e) => setJwtKey(e.target.value)}
                        className="w-full h-28 resize-none border border-gray-300 rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder={isJwtVerify
                          ? 'Enter shared secret or PEM-encoded public key...'
                          : (jwtAlgorithm.startsWith('HS')
                            ? 'Enter shared secret for HMAC...'
                            : 'Paste PEM-encoded private key...')}
                      />
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>

        <div className="mt-4">
          <button
            onClick={handlePublicKeyProcess}
            disabled={publicKeyActionDisabled}
            className="w-full bg-gradient-to-r from-gray-800 to-gray-900 hover:from-gray-900 hover:to-black disabled:opacity-50 disabled:cursor-not-allowed text-white px-5 py-2.5 rounded-lg font-semibold shadow-lg hover:shadow-xl transition-all duration-200 transform hover:scale-105 disabled:hover:scale-100"
          >
            {isLoading ? 'Working...' : publicKeyActionLabel}
          </button>
        </div>
      </div>
    </>
  );

  const inputOutputPanel = (
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
                    const algorithm = outputAlgorithmLabel || 'unknown';
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
                        <title>Output - ${outputAlgorithmLabel || 'Output'}</title>
                        <style>
                          body { font-family: monospace; padding: 20px; background: #f5f5f5; }
                          pre { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                        </style>
                      </head>
                      <body>
                        <h2>${outputAlgorithmLabel || 'Output'} Output</h2>
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
            <div className="flex flex-col gap-4">
              <pre className="w-full text-sm font-mono overflow-auto border-0 focus:outline-none">
                {result.output}
              </pre>
            </div>
          ) : (
            <div className="w-full h-full flex items-center justify-center text-gray-400">
              <span className="text-sm">Output will appear here...</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );

  return (
    <>
      <style>{spinnerCSS}</style>
      <div className="h-screen flex flex-col bg-white overflow-hidden">
        <div className="flex flex-1 overflow-hidden justify-start min-h-0">
          {/* Left Panel - Operations */}
          <ResizablePanel
            width={operationsWidth}
            minWidth={194}
            maxWidth={306}
            onResize={setOperationsWidth}
            className="bg-white border-r border-gray-200 flex-shrink-0 min-h-0"
          >
            <div className="h-full flex flex-col min-h-0">
              <div className="p-4 pb-3">
                <h2 className="text-lg font-semibold text-gray-900">Operations</h2>
                <div className="mt-3">
                  <input
                    type="text"
                    placeholder="Search..."
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
                  />
                </div>
              </div>

              <div className="flex-1 min-h-0 overflow-y-auto px-4 pb-4 space-y-6">
                <div className="space-y-4">
                  <button
                    type="button"
                    onClick={() => setIsCryptoOpen(prev => !prev)}
                    className="w-full flex items-center justify-between text-xs font-semibold text-gray-500 uppercase tracking-wide"
                    aria-expanded={isCryptoOpen}
                  >
                    <span>Encryption / Encoding</span>
                    <ChevronDown
                      className={`w-3 h-3 transition-transform ${isCryptoOpen ? 'rotate-0' : '-rotate-90'}`}
                    />
                  </button>
                  {isCryptoOpen && (
                    <div className="space-y-4">
                      {CRYPTO_GROUPS.map((group) => (
                        <div key={group.id} className="space-y-2">
                          <button
                            type="button"
                            onClick={() => toggleCryptoGroup(group.id)}
                            className="w-full flex items-center justify-between text-[11px] font-semibold text-gray-400 uppercase tracking-wide"
                            aria-expanded={cryptoGroupsOpen[group.id]}
                          >
                            <span>{group.label}</span>
                            <ChevronDown
                              className={`w-3 h-3 transition-transform ${
                                cryptoGroupsOpen[group.id] ? 'rotate-0' : '-rotate-90'
                              }`}
                            />
                          </button>
                          {cryptoGroupsOpen[group.id] && (
                            <AlgorithmSelector
                              selectedAlgorithm={selectedAlgorithm}
                              onAlgorithmChange={handleAlgorithmSelect}
                              allowedAlgorithms={group.algorithms}
                            />
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <button
                    type="button"
                    onClick={() => setIsPublicKeyOpen(prev => !prev)}
                    className="w-full flex items-center justify-between text-xs font-semibold text-gray-500 uppercase tracking-wide"
                    aria-expanded={isPublicKeyOpen}
                  >
                    <span>Public Key</span>
                    <ChevronDown
                      className={`w-3 h-3 transition-transform ${isPublicKeyOpen ? 'rotate-0' : '-rotate-90'}`}
                    />
                  </button>
                  {isPublicKeyOpen && (
                    <div className="space-y-2">
                      {PUBLIC_KEY_ITEMS.map((item) => {
                        const isActive = isPublicKeyMode && selectedPublicKeyOperation === item.id;
                        return (
                          <button
                            key={item.id}
                            type="button"
                            onClick={() => handlePublicKeySelect(item.id)}
                            onMouseEnter={(event) => handlePublicKeyMouseEnter(item.id, event)}
                            onMouseLeave={handlePublicKeyMouseLeave}
                            className={`w-full text-left p-2 rounded text-xs font-medium tracking-wide transition-colors ${
                              isActive
                                ? 'bg-primary-100 text-primary-800'
                                : 'hover:bg-gray-100 text-gray-600'
                            } ${!item.available ? 'opacity-60' : ''}`}
                          >
                            <div className="flex items-center justify-between">
                              <span>{item.label}</span>
                              {!item.available && <span className="text-[10px] text-gray-400">Soon</span>}
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <button
                    type="button"
                    onClick={() => setIsHashingOpen(prev => !prev)}
                    className="w-full flex items-center justify-between text-xs font-semibold text-gray-500 uppercase tracking-wide"
                    aria-expanded={isHashingOpen}
                  >
                    <span>Hashing</span>
                    <ChevronDown
                      className={`w-3 h-3 transition-transform ${isHashingOpen ? 'rotate-0' : '-rotate-90'}`}
                    />
                  </button>
                  {isHashingOpen && (
                    <div className="space-y-2">
                      {HASH_ITEMS.map((item) => {
                        const isActive = isHashingMode && selectedHashOperation === item.id;
                        return (
                          <button
                            key={item.id}
                            type="button"
                            onClick={() => handleHashSelect(item.id)}
                            onMouseEnter={(event) => handleHashMouseEnter(item.id, event)}
                            onMouseLeave={handleHashMouseLeave}
                            className={`w-full text-left p-2 rounded text-xs font-medium tracking-wide transition-colors ${
                              isActive
                                ? 'bg-primary-100 text-primary-800'
                                : 'hover:bg-gray-100 text-gray-600'
                            } ${!item.available ? 'opacity-60' : ''}`}
                          >
                            <div className="flex items-center justify-between">
                              <span>{item.label}</span>
                              {!item.available && <span className="text-[10px] text-gray-400">Soon</span>}
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </ResizablePanel>
        {hashTooltipInfo && (
          <div
            className="fixed z-[99999] max-w-xs"
            style={{
              left: Math.max(
                12,
                Math.min(
                  hashTooltipPosition.x,
                  (typeof window !== 'undefined' ? window.innerWidth : 1024) - 340
                )
              ),
              top: Math.max(
                12,
                Math.min(
                  hashTooltipPosition.y - 80,
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
              <div className="text-sm font-semibold text-gray-900 mb-2">{hashTooltipInfo.title}</div>
              <div className="space-y-1">
                {hashTooltipInfo.description.map((line, index) => (
                  <div key={`${hashTooltipId}-info-${index}`}>{line}</div>
                ))}
              </div>
            </div>
          </div>
        )}
        {publicKeyTooltipInfo && (
          <div
            className="fixed z-[99999] max-w-xs"
            style={{
              left: Math.max(
                12,
                Math.min(
                  publicKeyTooltipPosition.x,
                  (typeof window !== 'undefined' ? window.innerWidth : 1024) - 340
                )
              ),
              top: Math.max(
                12,
                Math.min(
                  publicKeyTooltipPosition.y - 80,
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
              <div className="text-sm font-semibold text-gray-900 mb-2">{publicKeyTooltipInfo.title}</div>
              <div className="space-y-1">
                {publicKeyTooltipInfo.description.map((line, index) => (
                  <div key={`${publicKeyTooltipId}-info-${index}`}>{line}</div>
                ))}
              </div>
            </div>
          </div>
        )}

        {isHashingMode ? (
          <>
            <ResizablePanel
              width={benchmarkWidth}
              minWidth={385}
              maxWidth={660}
              onResize={setBenchmarkWidth}
              className="bg-white border-r border-gray-200 flex flex-col flex-shrink-0 min-h-0"
            >
              {hashingPanel}
            </ResizablePanel>
            {inputOutputPanel}
          </>
        ) : isPublicKeyMode ? (
          <>
            <ResizablePanel
              width={benchmarkWidth}
              minWidth={385}
              maxWidth={660}
              onResize={setBenchmarkWidth}
              className="bg-white border-r border-gray-200 flex flex-col flex-shrink-0 min-h-0"
            >
              {publicKeyPanel}
            </ResizablePanel>
            {inputOutputPanel}
          </>
        ) : (
          <>
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
                          keyFormat: keyFormat,
                          ivFormat: ivFormat,
                          operation: operation,
                          offset: selectedAlgorithm === 'RAILFENCE' ? railOffset : undefined,
                          morseLetterDelimiter: morseLetterDelimiter,
                          morseWordDelimiter: morseWordDelimiter,
                          morseFormatOption: morseFormatOption,
                          morseDotSymbol: morseDotSymbol,
                          morseDashSymbol: morseDashSymbol
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
                            setKeyFormat(config.keyFormat || 'HEX');
                            setIvFormat(config.ivFormat || 'HEX');
                            setOperation(config.operation || 'encrypt');
                            setRailOffset(config.offset !== undefined ? String(config.offset) : '0');
                            const nextFormatOption = config.morseFormatOption
                              || inferMorseFormatOption(config.morseDotSymbol, config.morseDashSymbol);
                            const symbols = getMorseFormatSymbols(
                              nextFormatOption,
                              config.morseDotSymbol || '.',
                              config.morseDashSymbol || '-'
                            );
                            setMorseLetterDelimiter(config.morseLetterDelimiter || 'SPACE');
                            setMorseWordDelimiter(config.morseWordDelimiter || 'LINE_FEED');
                            setMorseFormatOption(nextFormatOption);
                            setMorseDotSymbol(symbols.dotSymbol);
                            setMorseDashSymbol(symbols.dashSymbol);
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
                    setKeyFormat('HEX');
                    setIvFormat('HEX');
                    setRailOffset('0');
                    setSalsaRounds(20);
                    setSalsaCounter(0);
                    setMorseLetterDelimiter('SPACE');
                    setMorseWordDelimiter('LINE_FEED');
                    setMorseFormatOption('-/.');
                    setMorseDotSymbol('.');
                    setMorseDashSymbol('-');
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
                  <h3 className="text-lg font-semibold text-gray-900">{algorithmSummary}</h3>
                </div>
                
                {/* Key Size Selection */}
                {selectedAlgorithm !== 'RAILFENCE' && selectedAlgorithm !== 'MORSE' && selectedAlgorithm !== 'VIGENERE' && selectedAlgorithm !== 'RC4' && selectedAlgorithm !== 'RC4DROP' && (
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
                      {selectedAlgorithm === 'DES' && (
                        <>
                          <option value="64">64 bits (8 bytes) - 56-bit effective key</option>
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
                      {(selectedAlgorithm === 'RC4' || selectedAlgorithm === 'RC4DROP') && (
                        <>
                          <option value="40">40 bits (5 bytes) - Legacy</option>
                          <option value="64">64 bits (8 bytes)</option>
                          <option value="128">128 bits (16 bytes) - Common</option>
                          <option value="256">256 bits (32 bytes)</option>
                          <option value="512">512 bits (64 bytes)</option>
                          <option value="1024">1024 bits (128 bytes)</option>
                          <option value="2048">2048 bits (256 bytes) - Maximum</option>
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
                )}
                
                {/* Key Input */}
                {selectedAlgorithm !== 'MORSE' && (
                  <div className="mb-3">
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      {selectedAlgorithm === 'RAILFENCE'
                        ? 'Rails'
                        : ((selectedAlgorithm === 'RC4' || selectedAlgorithm === 'RC4DROP') ? 'Passphrase' : 'Key')}
                    </label>
                    <div className="flex space-x-2">
                      {selectedAlgorithm !== 'RAILFENCE' && selectedAlgorithm !== 'VIGENERE' && (
                        <select
                          value={keyFormat}
                          onChange={(e) => setKeyFormat(e.target.value)}
                          className="px-3 py-2 border border-gray-300 rounded text-sm bg-white"
                        >
                          <option value="HEX">Hex</option>
                          <option value="UTF8">UTF8</option>
                          <option value="LATIN1">Latin1</option>
                          <option value="BASE64">Base64</option>
                        </select>
                      )}
                      <div className="flex-1 relative flex items-center space-x-2">
                        <input
                          type={selectedAlgorithm === 'RAILFENCE' ? 'number' : 'text'}
                          min={selectedAlgorithm === 'RAILFENCE' ? '2' : undefined}
                          max={selectedAlgorithm === 'RAILFENCE' ? '64' : undefined}
                          value={customKey}
                          onChange={(e) => setCustomKey(e.target.value)}
                          placeholder={
                            selectedAlgorithm === 'RAILFENCE'
                              ? 'Enter rails (2-64)...'
                              : selectedAlgorithm === 'VIGENERE'
                                ? 'Enter keyword (A-Z)...'
                                : (selectedAlgorithm === 'RC4' || selectedAlgorithm === 'RC4DROP')
                                  ? `Enter passphrase (1-256 bytes, ${keyFormat})...`
                                  : (selectedKeySize ? `Enter ${selectedKeySize}-bit ${keyFormat} key...` : `Enter ${keyFormat} key...`)
                          }
                          className="w-full px-3 py-2 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                        <button
                          onClick={() => copyToClipboard(customKey)}
                          type="button"
                          className="p-2 text-gray-400 hover:text-gray-600 transition-colors"
                          title={selectedAlgorithm === 'RAILFENCE' ? 'Copy rails' : 'Copy key'}
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                          </svg>
                        </button>
                        <button
                          onClick={generateRandomKey}
                          type="button"
                          className="p-2 text-gray-400 hover:text-gray-600 transition-colors"
                          title={
                            selectedAlgorithm === 'RAILFENCE'
                              ? 'Generate random rails'
                              : selectedAlgorithm === 'VIGENERE'
                                ? 'Generate random keyword'
                                : `Generate random ${selectedKeySize}-bit key`
                          }
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                          </svg>
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                  {selectedAlgorithm === 'RC4DROP' && (
                    <div className="mb-3">
                      <label className="block text-sm font-medium text-gray-700 mb-1">Number of dwords to drop</label>
                      <input
                        type="number"
                        min="0"
                        value={rc4Drop}
                        onChange={(e) => setRc4Drop(e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <p className="mt-1 text-xs text-gray-500">Try 768 or 1024 dwords (x4 bytes) for RC4-drop.</p>
                    </div>
                  )}

                {selectedAlgorithm === 'VIGENERE' && (
                  <p className="mt-1 text-xs text-gray-500">
                    Letters A-Z only. Input and key are uppercased and non-letters are removed.
                  </p>
                )}

                {selectedAlgorithm === 'RAILFENCE' && (
                  <div className="mb-3">
                    <label className="block text-sm font-medium text-gray-700 mb-1">Offset</label>
                    <input
                      type="number"
                      min="0"
                      value={railOffset}
                      onChange={(e) => setRailOffset(e.target.value)}
                      placeholder="0"
                      className="w-full px-3 py-2 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <p className="mt-1 text-xs text-gray-500">Shift the zigzag start position.</p>
                  </div>
                )}

                {selectedAlgorithm === 'MORSE' && (
                  <div className="mb-3 space-y-3">
                    {operation === 'encrypt' ? (
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                        <div className="bg-white border border-gray-200 rounded p-2">
                          <div className="text-xs text-gray-500 mb-1">Format options</div>
                          <select
                            value={morseFormatOption}
                            onChange={(e) => {
                              const nextOption = e.target.value;
                              const symbols = getMorseFormatSymbols(nextOption);
                              setMorseFormatOption(nextOption);
                              setMorseDotSymbol(symbols.dotSymbol);
                              setMorseDashSymbol(symbols.dashSymbol);
                            }}
                            className="w-full text-sm font-medium text-gray-900 bg-transparent border-none focus:outline-none focus:ring-0"
                          >
                            {MORSE_FORMAT_OPTIONS.map(option => (
                              <option key={option.value} value={option.value}>{option.label}</option>
                            ))}
                          </select>
                        </div>
                        <div className="bg-white border border-gray-200 rounded p-2">
                          <div className="text-xs text-gray-500 mb-1">Letter delimiter</div>
                          <select
                            value={morseLetterDelimiter}
                            onChange={(e) => setMorseLetterDelimiter(e.target.value)}
                            className="w-full text-sm font-medium text-gray-900 bg-transparent border-none focus:outline-none focus:ring-0"
                          >
                            {MORSE_LETTER_DELIMITER_OPTIONS.map(option => (
                              <option key={option.value} value={option.value}>{option.label}</option>
                            ))}
                          </select>
                        </div>
                        <div className="bg-white border border-gray-200 rounded p-2">
                          <div className="text-xs text-gray-500 mb-1">Word delimiter</div>
                          <select
                            value={morseWordDelimiter}
                            onChange={(e) => setMorseWordDelimiter(e.target.value)}
                            className="w-full text-sm font-medium text-gray-900 bg-transparent border-none focus:outline-none focus:ring-0"
                          >
                            {MORSE_WORD_DELIMITER_OPTIONS.map(option => (
                              <option key={option.value} value={option.value}>{option.label}</option>
                            ))}
                          </select>
                        </div>
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        <div className="bg-white border border-gray-200 rounded p-2">
                          <div className="text-xs text-gray-500 mb-1">Letter delimiter</div>
                          <select
                            value={morseLetterDelimiter}
                            onChange={(e) => setMorseLetterDelimiter(e.target.value)}
                            className="w-full text-sm font-medium text-gray-900 bg-transparent border-none focus:outline-none focus:ring-0"
                          >
                            {MORSE_LETTER_DELIMITER_OPTIONS.map(option => (
                              <option key={option.value} value={option.value}>{option.label}</option>
                            ))}
                          </select>
                        </div>
                        <div className="bg-white border border-gray-200 rounded p-2">
                          <div className="text-xs text-gray-500 mb-1">Word delimiter</div>
                          <select
                            value={morseWordDelimiter}
                            onChange={(e) => setMorseWordDelimiter(e.target.value)}
                            className="w-full text-sm font-medium text-gray-900 bg-transparent border-none focus:outline-none focus:ring-0"
                          >
                            {MORSE_WORD_DELIMITER_OPTIONS.map(option => (
                              <option key={option.value} value={option.value}>{option.label}</option>
                            ))}
                          </select>
                        </div>
                      </div>
                    )}
                    {operation === 'encrypt' ? (
                      <p className="text-xs text-gray-500">Format options control how dots and dashes are emitted.</p>
                    ) : (
                      <p className="text-xs text-gray-500">Letter and word delimiters control spacing in the input.</p>
                    )}
                  </div>
                )}
                
                {/* IV Input (for AES, DES, 3DES, Blowfish modes except ECB, RC2 CBC mode, and SM4 non-ECB modes) */}
                {(selectedAlgorithm === 'SALSA20' || selectedAlgorithm === 'CHACHA20' || selectedAlgorithm === 'AES' || selectedAlgorithm === 'DES' || selectedAlgorithm === '3DES' || selectedAlgorithm === 'BLOWFISH' || selectedAlgorithm === 'RC2' || selectedAlgorithm === 'SM4') && selectedMode !== 'ECB' && (
                  <div className="mb-3">
                    <label className="block text-sm font-medium text-gray-700 mb-1">{(selectedAlgorithm === 'SALSA20' || selectedAlgorithm === 'CHACHA20') ? 'Nonce' : 'IV'}</label>
                    <div className="flex space-x-2">
                      <select
                        value={ivFormat}
                        onChange={(e) => setIvFormat(e.target.value)}
                        className="px-3 py-2 border border-gray-300 rounded text-sm bg-white"
                      >
                        <option value="HEX">Hex</option>
                        <option value="UTF8">UTF8</option>
                        <option value="LATIN1">Latin1</option>
                        <option value="BASE64">Base64</option>
                      </select>
                      <div className="flex-1 relative flex items-center space-x-2">
                        <input
                          type="text"
                          value={customIV}
                          onChange={(e) => setCustomIV(e.target.value)}
                          placeholder={
                            selectedAlgorithm === 'SALSA20'
                              ? `Enter 8-byte nonce (${ivFormat})...`
                              : selectedAlgorithm === 'CHACHA20'
                                ? `Enter 12-byte nonce (${ivFormat})...`
                                : `Enter initialization vector (${ivFormat})...`
                          }
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
                {selectedAlgorithm !== 'RAILFENCE' && selectedAlgorithm !== 'MORSE' && selectedAlgorithm !== 'VIGENERE' && (
                  <div className="grid grid-cols-3 gap-2">
                    <div className="bg-white border border-gray-200 rounded p-2">
                      <div className="text-xs text-gray-500 mb-1">Mode</div>
                      {selectedAlgorithm === 'SALSA20' || selectedAlgorithm === 'CHACHA20' || selectedAlgorithm === 'RC4' || selectedAlgorithm === 'RC4DROP' ? (
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
                          {(selectedAlgorithm === 'AES' || selectedAlgorithm === 'SM4' || selectedAlgorithm === 'DES') && (
                            <option value="CTR">CTR</option>
                          )}
                          {(selectedAlgorithm === 'AES' || selectedAlgorithm === 'SM4') && (
                            <option value="GCM">GCM</option>
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
                        {isRc4Family ? (
                          <>
                            <option value="LATIN1">Latin1</option>
                            <option value="UTF8">UTF8</option>
                            <option value="UTF16">UTF16</option>
                            <option value="UTF16LE">UTF16LE</option>
                            <option value="UTF16BE">UTF16BE</option>
                            <option value="HEX">Hex</option>
                            <option value="BASE64">Base64</option>
                          </>
                        ) : (
                          <>
                            <option value="RAW">RAW</option>
                            <option value="HEX">HEX</option>
                          </>
                        )}
                      </select>
                    </div>
                  <div className="bg-white border border-gray-200 rounded p-2">
                    <div className="text-xs text-gray-500 mb-1">Output</div>
                    <select 
                      value={outputFormat}
                      onChange={(e) => setOutputFormat(e.target.value)}
                        className="w-full text-sm font-medium text-gray-900 bg-transparent border-none focus:outline-none focus:ring-0"
                      >
                        {isRc4Family ? (
                          <>
                            <option value="LATIN1">Latin1</option>
                            <option value="UTF8">UTF8</option>
                            <option value="UTF16">UTF16</option>
                            <option value="UTF16LE">UTF16LE</option>
                            <option value="UTF16BE">UTF16BE</option>
                            <option value="HEX">Hex</option>
                            <option value="BASE64">Base64</option>
                          </>
                        ) : (
                          <>
                            <option value="HEX">HEX</option>
                            <option value="RAW">RAW</option>
                          </>
                        )}
                    </select>
                  </div>
                  </div>
                )}

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

            {showRailFenceVisualization && (
              <div className="mt-4 rounded-xl border border-emerald-100 bg-gradient-to-br from-emerald-50 via-white to-emerald-50 p-4 shadow-sm">
                <div className="flex items-center justify-between mb-3">
                  <div className="text-xs font-semibold text-emerald-700 uppercase tracking-[0.2em]">ZIGZAG PATTERN</div>
                  <div className="flex items-center space-x-2 text-[11px] text-emerald-700/80">
                    <span>rails: {railFenceRails || '—'}</span>
                    <span className="text-emerald-200">|</span>
                    <span>offset: {railFenceOffset}</span>
                    <button
                      onClick={async (event) => {
                        if (!railFenceZigzag) {
                          alert('No zigzag pattern available to copy.');
                          return;
                        }
                        await copyToClipboard(railFenceZigzag);
                        const button = event.target.closest('button');
                        const originalTitle = button.title;
                        button.title = 'Copied!';
                        setTimeout(() => {
                          button.title = originalTitle;
                        }, 1000);
                      }}
                      className="p-1 text-emerald-600 hover:text-emerald-800"
                      title="Copy Zigzag Pattern"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </div>
                </div>
                <div className="overflow-auto rounded-lg border border-emerald-100 bg-white/70 p-3">
                  <div
                    className="grid gap-1 justify-start"
                    style={{ gridTemplateColumns: `repeat(${railFenceGrid[0]?.length || 0}, 24px)` }}
                  >
                    {railFenceGrid.flatMap((row, rowIndex) => (
                      row.map((cell, colIndex) => {
                        const isPlaceholder = cell === '.';
                        return (
                          <div
                            key={`rail-cell-${rowIndex}-${colIndex}`}
                            className={`h-6 w-6 rounded border text-xs font-mono flex items-center justify-center ${
                              isPlaceholder
                                ? 'border-emerald-50 text-emerald-200 bg-emerald-50/30'
                                : 'border-emerald-200 text-emerald-900 bg-white'
                            }`}
                          >
                            {cell}
                          </div>
                        );
                      })
                    ))}
                  </div>
                </div>
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

        {inputOutputPanel}
          </>
        )}
      </div>
    </div>
    </>
  );
};

export default CryptoLabPage; 

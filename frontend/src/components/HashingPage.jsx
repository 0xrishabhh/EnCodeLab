import React, { useMemo, useState } from 'react';
import { CheckCircle, AlertCircle } from 'lucide-react';
import ResizablePanel from './ResizablePanel';
import { cryptoAPI } from '../services/api';

export const HASH_ITEMS = [
  { id: 'ANALYZE', label: 'Analyze hash', available: true },
  { id: 'ALL', label: 'Generate all hashes', available: true },
  { id: 'BCRYPT', label: 'Bcrypt', available: true },
  { id: 'MD2', label: 'MD2', available: true },
  { id: 'MD4', label: 'MD4', available: true },
  { id: 'MD5', label: 'MD5', available: true },
  { id: 'MD6', label: 'MD6', available: true },
  { id: 'SHA0', label: 'SHA0', available: false },
  { id: 'SHA1', label: 'SHA1', available: true },
  { id: 'SHA2', label: 'SHA2', available: true },
  { id: 'SHA3', label: 'SHA3', available: true },
  { id: 'SM3', label: 'SM3', available: true },
  { id: 'KECCAK', label: 'Keccak', available: true },
  { id: 'SHAKE', label: 'Shake', available: true },
  { id: 'RIPEMD', label: 'RIPEMD', available: false },
  { id: 'HAS-160', label: 'HAS-160', available: false },
  { id: 'CRC32', label: 'CRC32', available: true }
];
const SIDEBAR_ITEMS = HASH_ITEMS;

const SHA2_OPTIONS = [
  { label: 'SHA-224', value: 'SHA224' },
  { label: 'SHA-256', value: 'SHA256' },
  { label: 'SHA-384', value: 'SHA384' },
  { label: 'SHA-512', value: 'SHA512' }
];

const SHA3_OPTIONS = [
  { label: 'SHA3-224', value: 'SHA3-224' },
  { label: 'SHA3-256', value: 'SHA3-256' },
  { label: 'SHA3-384', value: 'SHA3-384' },
  { label: 'SHA3-512', value: 'SHA3-512' }
];

const SHAKE_OPTIONS = [
  { label: 'SHAKE128', value: 'SHAKE128' },
  { label: 'SHAKE256', value: 'SHAKE256' }
];

const ALL_HASH_ALGOS = [
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

const INPUT_FORMATS = ['UTF-8', 'HEX', 'BASE64', 'RAW'];
const OUTPUT_FORMATS = ['HEX', 'BASE64', 'RAW'];

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

const HashingPage = ({
  embedded = false,
  showSidebar = true,
  activeSection: controlledSection,
  onSectionChange
}) => {
  const [sidebarWidth, setSidebarWidth] = useState(240);
  const [internalSection, setInternalSection] = useState('BCRYPT');
  const activeSection = controlledSection ?? internalSection;
  const setActiveSection = onSectionChange ?? setInternalSection;

  const [genericInput, setGenericInput] = useState('');
  const [genericInputFormat, setGenericInputFormat] = useState('UTF-8');
  const [genericOutputFormat, setGenericOutputFormat] = useState('HEX');
  const [genericOutput, setGenericOutput] = useState('');
  const [genericError, setGenericError] = useState('');
  const [isHashing, setIsHashing] = useState(false);

  const [sha2Variant, setSha2Variant] = useState('SHA256');
  const [sha3Variant, setSha3Variant] = useState('SHA3-256');
  const [shakeVariant, setShakeVariant] = useState('SHAKE128');
  const [shakeLength, setShakeLength] = useState(32);
  const [md6Size, setMd6Size] = useState(256);
  const [md6Levels, setMd6Levels] = useState(64);
  const [md6Key, setMd6Key] = useState('');

  const [bcryptPassword, setBcryptPassword] = useState('');
  const [bcryptRounds, setBcryptRounds] = useState(12);
  const [bcryptHash, setBcryptHash] = useState('');
  const [bcryptError, setBcryptError] = useState('');
  const [verifyPassword, setVerifyPassword] = useState('');
  const [verifyHash, setVerifyHash] = useState('');
  const [verifyResult, setVerifyResult] = useState(null);
  const [isVerifying, setIsVerifying] = useState(false);

  const [allInput, setAllInput] = useState('');
  const [allInputFormat, setAllInputFormat] = useState('UTF-8');
  const [allOutputFormat, setAllOutputFormat] = useState('HEX');
  const [allResults, setAllResults] = useState([]);
  const [allError, setAllError] = useState('');
  const [isAllLoading, setIsAllLoading] = useState(false);
  const [allShakeLength, setAllShakeLength] = useState(32);

  const [analyzeInput, setAnalyzeInput] = useState('');
  const analysisResults = useMemo(() => analyzeHash(analyzeInput), [analyzeInput]);

  const activeItem = SIDEBAR_ITEMS.find((item) => item.id === activeSection);

  const resolveAlgorithm = () => {
    if (activeSection === 'SHA2') return sha2Variant;
    if (activeSection === 'SHA3') return sha3Variant;
    if (activeSection === 'SHAKE') return shakeVariant;
    if (activeSection === 'KECCAK') return 'KECCAK-256';
    if (activeSection === 'CRC32') return 'CRC32';
    return activeSection;
  };

  const handleGenericHash = async () => {
    setGenericError('');
    setGenericOutput('');
    if (!genericInput) {
      setGenericError('Enter input to hash.');
      return;
    }
    if (activeSection === 'MD6') {
      const sizeValue = Number(md6Size);
      if (!Number.isFinite(sizeValue) || sizeValue < 128 || sizeValue > 512) {
        setGenericError('MD6 size must be between 128 and 512 bits.');
        return;
      }
      const levelsValue = Number(md6Levels);
      if (!Number.isFinite(levelsValue) || levelsValue <= 0) {
        setGenericError('MD6 levels must be a positive integer.');
        return;
      }
    }
    setIsHashing(true);
    try {
      const algorithm = resolveAlgorithm();
      const parsedLength = Number(shakeLength);
      const length = activeSection === 'SHAKE' && Number.isFinite(parsedLength) && parsedLength > 0
        ? parsedLength
        : undefined;
      const md6Payload = activeSection === 'MD6'
        ? {
            size: Number(md6Size),
            levels: Number(md6Levels),
            key: md6Key
          }
        : {};
      const response = await cryptoAPI.hash({
        algorithm,
        input: genericInput,
        inputFormat: genericInputFormat,
        outputFormat: genericOutputFormat,
        length,
        ...md6Payload
      });
      if (!response.success) {
        throw new Error(response.error || 'Hashing failed');
      }
      setGenericOutput(response.result.hash || '');
    } catch (error) {
      setGenericError(error.message || 'Hashing failed');
    } finally {
      setIsHashing(false);
    }
  };

  const handleBcryptHash = async () => {
    setBcryptError('');
    setBcryptHash('');
    setVerifyResult(null);
    if (!bcryptPassword) {
      setBcryptError('Enter a password to hash.');
      return;
    }
    setIsHashing(true);
    try {
      const response = await cryptoAPI.hash({
        algorithm: 'BCRYPT',
        input: bcryptPassword,
        inputFormat: 'UTF-8',
        rounds: Number(bcryptRounds)
      });
      if (!response.success) {
        throw new Error(response.error || 'bcrypt hash failed');
      }
      const hashValue = response.result.hash || '';
      setBcryptHash(hashValue);
      if (!verifyHash) {
        setVerifyHash(hashValue);
      }
    } catch (error) {
      setBcryptError(error.message || 'bcrypt hash failed');
    } finally {
      setIsHashing(false);
    }
  };

  const handleBcryptVerify = async () => {
    setBcryptError('');
    setVerifyResult(null);
    if (!verifyPassword || !verifyHash) {
      setBcryptError('Provide both password and hash to verify.');
      return;
    }
    setIsVerifying(true);
    try {
      const response = await cryptoAPI.verifyHash({
        algorithm: 'BCRYPT',
        input: verifyPassword,
        inputFormat: 'UTF-8',
        hash: verifyHash
      });
      if (!response.success) {
        throw new Error(response.error || 'Verification failed');
      }
      setVerifyResult(Boolean(response.result.verified));
    } catch (error) {
      setBcryptError(error.message || 'Verification failed');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleHashAll = async () => {
    setAllError('');
    setAllResults([]);
    if (!allInput) {
      setAllError('Enter input to hash.');
      return;
    }
    setIsAllLoading(true);
    try {
      const parsedLength = Number(allShakeLength);
      const length = Number.isFinite(parsedLength) && parsedLength > 0 ? parsedLength : undefined;
      const response = await cryptoAPI.hashAll({
        input: allInput,
        inputFormat: allInputFormat,
        outputFormat: allOutputFormat,
        algorithms: ALL_HASH_ALGOS,
        length
      });
      if (!response.success) {
        throw new Error(response.error || 'Hash-all failed');
      }
      setAllResults(response.result.hashes || []);
    } catch (error) {
      setAllError(error.message || 'Hash-all failed');
    } finally {
      setIsAllLoading(false);
    }
  };

  const renderPanel = () => {
    if (activeSection === 'ANALYZE') {
      return (
        <div className="card space-y-4">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">Analyze Hash</h2>
            <p className="text-sm text-gray-600">Paste a hash and get likely algorithm matches.</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Hash Value</label>
            <textarea
              value={analyzeInput}
              onChange={(e) => setAnalyzeInput(e.target.value)}
              className="w-full h-32 resize-none border border-gray-300 rounded-lg p-3 font-mono text-sm"
              placeholder="Enter a hash string..."
            />
          </div>
          <div className="bg-gray-50 border border-gray-200 rounded-lg p-3">
            <div className="text-xs font-semibold text-gray-600 mb-2">Likely Algorithms</div>
            <ul className="space-y-1 text-sm text-gray-700">
              {analysisResults.map((item, index) => (
                <li key={`${item}-${index}`}>{item}</li>
              ))}
            </ul>
          </div>
        </div>
      );
    }

    if (activeSection === 'ALL') {
      return (
        <div className="card space-y-4">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">Generate All Hashes</h2>
            <p className="text-sm text-gray-600">Compute a bundle of common hashes for one input.</p>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Input Format</label>
              <select
                value={allInputFormat}
                onChange={(e) => setAllInputFormat(e.target.value)}
                className="w-full border border-gray-300 rounded-md px-2 py-1 text-sm"
              >
                {INPUT_FORMATS.map((format) => (
                  <option key={format} value={format}>{format}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Output Format</label>
              <select
                value={allOutputFormat}
                onChange={(e) => setAllOutputFormat(e.target.value)}
                className="w-full border border-gray-300 rounded-md px-2 py-1 text-sm"
              >
                {OUTPUT_FORMATS.map((format) => (
                  <option key={format} value={format}>{format}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">SHAKE Length (bytes)</label>
              <input
                type="number"
                min="1"
                value={allShakeLength}
                onChange={(e) => setAllShakeLength(e.target.value)}
                className="w-full border border-gray-300 rounded-md px-2 py-1 text-sm"
              />
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Input</label>
            <textarea
              value={allInput}
              onChange={(e) => setAllInput(e.target.value)}
              className="w-full h-28 resize-none border border-gray-300 rounded-lg p-3 font-mono text-sm"
              placeholder="Enter input for batch hashing..."
            />
          </div>
          {allError && <div className="text-sm text-red-600">{allError}</div>}
          <button
            onClick={handleHashAll}
            className="btn-primary"
            disabled={isAllLoading}
          >
            {isAllLoading ? 'Hashing...' : 'Generate Hashes'}
          </button>
          <div className="border border-gray-200 rounded-lg overflow-hidden">
            <div className="bg-gray-50 px-3 py-2 text-xs font-semibold text-gray-600">Results</div>
            <div className="max-h-64 overflow-auto divide-y divide-gray-200">
              {allResults.length === 0 && (
                <div className="px-3 py-3 text-sm text-gray-500">No hashes yet.</div>
              )}
              {allResults.map((entry) => (
                <div key={`${entry.algorithm}-${entry.hash.slice(0, 8)}`} className="px-3 py-2 text-xs font-mono text-gray-700">
                  <div className="text-gray-500">{entry.algorithm}</div>
                  <div className="break-all">{entry.hash}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      );
    }

    if (activeSection === 'BCRYPT') {
      return (
        <div className="space-y-4">
          <div className="rounded-lg border border-emerald-100 bg-emerald-50 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-emerald-800">Bcrypt</h2>
              <span className="text-xs text-emerald-700">Password hashing</span>
            </div>
            <div>
              <label className="block text-sm font-medium text-emerald-700 mb-1">Password</label>
              <input
                type="text"
                value={bcryptPassword}
                onChange={(e) => setBcryptPassword(e.target.value)}
                className="w-full border border-emerald-200 rounded-md px-3 py-2 text-sm"
                placeholder="Enter password"
              />
            </div>
            <div className="grid grid-cols-2 gap-3 items-end">
              <div>
                <label className="block text-sm font-medium text-emerald-700 mb-1">Rounds</label>
                <input
                  type="number"
                  min="4"
                  max="31"
                  value={bcryptRounds}
                  onChange={(e) => setBcryptRounds(e.target.value)}
                  className="w-full border border-emerald-200 rounded-md px-3 py-2 text-sm"
                />
                <div className="text-xs text-emerald-700 mt-1">Typical: 10-14</div>
              </div>
              <button
                onClick={handleBcryptHash}
                className="btn-primary w-full"
                disabled={isHashing}
              >
                {isHashing ? 'Hashing...' : 'Generate Hash'}
              </button>
            </div>
            {bcryptError && <div className="text-sm text-red-600">{bcryptError}</div>}
            <div className="bg-white border border-emerald-100 rounded-md p-3">
              <div className="text-xs font-semibold text-emerald-700 mb-2">Hash Output</div>
              <div className="font-mono text-xs break-all text-gray-700">{bcryptHash || '—'}</div>
            </div>
          </div>

          <div className="card space-y-3">
            <div>
              <h3 className="text-base font-semibold text-gray-900">Verify Password</h3>
              <p className="text-sm text-gray-600">bcrypt verifies by re-hashing with the embedded salt.</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
              <input
                type="text"
                value={verifyPassword}
                onChange={(e) => setVerifyPassword(e.target.value)}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
                placeholder="Password to verify"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Hash</label>
              <textarea
                value={verifyHash}
                onChange={(e) => setVerifyHash(e.target.value)}
                className="w-full h-24 resize-none border border-gray-300 rounded-md px-3 py-2 text-xs font-mono"
                placeholder="Paste bcrypt hash"
              />
            </div>
            <button
              onClick={handleBcryptVerify}
              className="btn-secondary w-full"
              disabled={isVerifying}
            >
              {isVerifying ? 'Verifying...' : 'Verify'}
            </button>
            {verifyResult !== null && (
              <div className={`flex items-center space-x-2 text-sm ${verifyResult ? 'text-emerald-700' : 'text-red-600'}`}>
                {verifyResult ? <CheckCircle className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
                <span>{verifyResult ? 'Password matches hash.' : 'Password does not match.'}</span>
              </div>
            )}
          </div>
        </div>
      );
    }

    if (activeItem && !activeItem.available) {
      return (
        <div className="card">
          <h2 className="text-lg font-semibold text-gray-900">{activeItem.label}</h2>
          <p className="text-sm text-gray-600 mt-2">This algorithm is queued for integration.</p>
        </div>
      );
    }

    return (
      <div className="card space-y-4">
        <div>
          <h2 className="text-lg font-semibold text-gray-900">{activeItem?.label}</h2>
          <p className="text-sm text-gray-600">Generate message digests for integrity checks.</p>
        </div>
        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Input Format</label>
            <select
              value={genericInputFormat}
              onChange={(e) => setGenericInputFormat(e.target.value)}
              className="w-full border border-gray-300 rounded-md px-2 py-1 text-sm"
            >
              {INPUT_FORMATS.map((format) => (
                <option key={format} value={format}>{format}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Output Format</label>
            <select
              value={genericOutputFormat}
              onChange={(e) => setGenericOutputFormat(e.target.value)}
              className="w-full border border-gray-300 rounded-md px-2 py-1 text-sm"
            >
              {OUTPUT_FORMATS.map((format) => (
                <option key={format} value={format}>{format}</option>
              ))}
            </select>
          </div>
          <div>
            {activeSection === 'SHA2' && (
              <>
                <label className="block text-xs font-medium text-gray-600 mb-1">SHA2 Variant</label>
                <select
                  value={sha2Variant}
                  onChange={(e) => setSha2Variant(e.target.value)}
                  className="w-full border border-gray-300 rounded-md px-2 py-1 text-sm"
                >
                  {SHA2_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </>
            )}
            {activeSection === 'SHA3' && (
              <>
                <label className="block text-xs font-medium text-gray-600 mb-1">SHA3 Variant</label>
                <select
                  value={sha3Variant}
                  onChange={(e) => setSha3Variant(e.target.value)}
                  className="w-full border border-gray-300 rounded-md px-2 py-1 text-sm"
                >
                  {SHA3_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </>
            )}
            {activeSection === 'SHAKE' && (
              <>
                <label className="block text-xs font-medium text-gray-600 mb-1">SHAKE Variant</label>
                <select
                  value={shakeVariant}
                  onChange={(e) => setShakeVariant(e.target.value)}
                  className="w-full border border-gray-300 rounded-md px-2 py-1 text-sm"
                >
                  {SHAKE_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
                <label className="block text-xs font-medium text-gray-600 mt-2 mb-1">Output Length (bytes)</label>
                <input
                  type="number"
                  min="1"
                  value={shakeLength}
                  onChange={(e) => setShakeLength(e.target.value)}
                  className="w-full border border-gray-300 rounded-md px-2 py-1 text-sm"
                />
              </>
            )}
            {activeSection === 'KECCAK' && (
              <>
                <label className="block text-xs font-medium text-gray-600 mb-1">Keccak Variant</label>
                <div className="text-sm text-gray-700 px-2 py-1 border border-gray-200 rounded-md bg-gray-50">KECCAK-256</div>
              </>
            )}
          </div>
        </div>
        {activeSection === 'MD6' && (
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Size (bits)</label>
              <input
                type="number"
                min="128"
                max="512"
                value={md6Size}
                onChange={(e) => setMd6Size(e.target.value)}
                className="w-full border border-gray-300 rounded-md px-2 py-1 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Levels</label>
              <input
                type="number"
                min="1"
                value={md6Levels}
                onChange={(e) => setMd6Levels(e.target.value)}
                className="w-full border border-gray-300 rounded-md px-2 py-1 text-sm"
              />
            </div>
            <div className="col-span-3">
              <label className="block text-xs font-medium text-gray-600 mb-1">Key (optional)</label>
              <input
                type="text"
                value={md6Key}
                onChange={(e) => setMd6Key(e.target.value)}
                className="w-full border border-gray-300 rounded-md px-2 py-1 text-sm"
                placeholder="Enter key for MD6 (optional)"
              />
            </div>
          </div>
        )}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Input</label>
          <textarea
            value={genericInput}
            onChange={(e) => setGenericInput(e.target.value)}
            className="w-full h-28 resize-none border border-gray-300 rounded-lg p-3 font-mono text-sm"
            placeholder="Enter input to hash..."
          />
        </div>
        {genericError && <div className="text-sm text-red-600">{genericError}</div>}
        <button onClick={handleGenericHash} className="btn-primary" disabled={isHashing}>
          {isHashing ? 'Hashing...' : 'Generate Hash'}
        </button>
        <div className="border border-gray-200 rounded-lg overflow-hidden">
          <div className="bg-gray-50 px-3 py-2 text-xs font-semibold text-gray-600">Output</div>
          <div className="px-3 py-3 font-mono text-xs text-gray-700 break-all">
            {genericOutput || '—'}
          </div>
        </div>
      </div>
    );
  };

  const containerClass = embedded ? 'flex flex-1 min-h-0' : 'flex flex-1 min-h-[calc(100vh-4rem)]';

  return (
    <div className={containerClass}>
      {showSidebar && (
        <ResizablePanel
          width={sidebarWidth}
          minWidth={200}
          maxWidth={360}
          onResize={setSidebarWidth}
          className="bg-white border-r border-gray-200"
        >
          <div className="h-full flex flex-col">
            <div className="px-4 py-3 text-sm font-semibold text-blue-700 border-b border-gray-200">
              Hashing
            </div>
            <div className="flex-1 overflow-auto">
              {SIDEBAR_ITEMS.map((item) => {
                const isActive = activeSection === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveSection(item.id)}
                    className={`w-full text-left px-4 py-3 text-sm font-medium border-b border-gray-100 transition-colors ${
                      isActive
                        ? 'bg-blue-50 text-blue-700'
                        : 'text-gray-600 hover:bg-blue-50/60 hover:text-blue-700'
                    } ${!item.available ? 'opacity-60' : ''}`}
                  >
                    <div className="flex items-center justify-between">
                      <span>{item.label}</span>
                      {!item.available && <span className="text-xs text-gray-400">Soon</span>}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </ResizablePanel>
      )}

      <div className="flex-1 p-6 overflow-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-semibold text-gray-900">Hashing Lab</h1>
          <p className="text-sm text-gray-600">
            Explore bcrypt and common hash families with configurable formats and variants.
          </p>
        </div>
        {renderPanel()}
      </div>
    </div>
  );
};

export default HashingPage;

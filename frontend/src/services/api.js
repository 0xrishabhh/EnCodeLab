const API_BASE_URL = 'http://localhost:5000';

export const cryptoAPI = {
  async encrypt(data) {
    try {
      const response = await fetch(`${API_BASE_URL}/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          algorithm: data.algorithm,
          mode: data.mode,
          data: data.input,
          inputFormat: data.inputFormat || 'RAW',
          outputFormat: data.outputFormat || 'HEX',
          key: data.key || undefined,
          iv_or_nonce: data.iv_or_nonce,
          key_format: data.key_format,
          iv_format: data.iv_format,
          keySize: data.keySize,
          rails: data.rails,
          offset: data.offset,
          letter_delimiter: data.letter_delimiter,
          word_delimiter: data.word_delimiter,
          dot_symbol: data.dot_symbol,
          dash_symbol: data.dash_symbol,
          rounds: data.rounds,
          counter: data.counter,
          drop: data.drop,
          drop_unit: data.drop_unit
        })
      });

      const result = await response.json();
      
      if (result.status !== 'success') {
        throw new Error(result.error || 'Encryption failed');
      }

      return {
        success: true,
        output: result.result.ciphertext,
        key: result.result.key,
        offset: result.result.offset,
        iv_or_nonce: result.result.iv_or_nonce,
        tag: result.result.tag,
        keyGenerated: result.result.key_generated,
        keyFormat: result.result.key_format,
        ivFormat: result.result.iv_format,
        drop: result.result.drop,
        caseSequence: result.result.case_sequence,
        algorithm: result.result.algorithm,
        mode: result.result.mode,
        executionTime: result.result.executionTime
      };
    } catch (error) {
      console.error('Encryption error:', error);
      return {
        success: false,
        error: error.message || 'Network error occurred'
      };
    }
  },

  async decrypt(data) {
    try {
      const response = await fetch(`${API_BASE_URL}/decrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          algorithm: data.algorithm,
          mode: data.mode,
          data: data.input,
          encoding: data.inputFormat || 'HEX',
          output_encoding: data.outputFormat || 'HEX',
          key: data.key,
          iv_or_nonce: data.iv_or_nonce,
          key_format: data.key_format,
          iv_format: data.iv_format,
          tag: data.tag,
          rails: data.rails,
          offset: data.offset,
          letter_delimiter: data.letter_delimiter,
          word_delimiter: data.word_delimiter,
          dot_symbol: data.dot_symbol,
          dash_symbol: data.dash_symbol,
          case_sequence: data.case_sequence,
          rounds: data.rounds,
          counter: data.counter,
          drop: data.drop,
          drop_unit: data.drop_unit
        })
      });

      const result = await response.json();
      
      if (result.status !== 'success') {
        throw new Error(result.error || 'Decryption failed');
      }

      return {
        success: true,
        output: result.result.plaintext,
        key: result.result.key,
        offset: result.result.offset,
        caseSequence: result.result.case_sequence,
        keyFormat: result.result.key_format,
        ivFormat: result.result.iv_format,
        drop: result.result.drop,
        algorithm: result.result.algorithm,
        mode: result.result.mode,
        executionTime: result.result.executionTime
      };
    } catch (error) {
      console.error('Decryption error:', error);
      return {
        success: false,
        error: error.message || 'Network error occurred'
      };
    }
  },

  async hash(data) {
    try {
      const response = await fetch(`${API_BASE_URL}/hash`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          algorithm: data.algorithm,
          data: data.input,
          inputFormat: data.inputFormat || 'UTF-8',
          outputFormat: data.outputFormat || 'HEX',
          rounds: data.rounds,
          cost: data.cost,
          length: data.length,
          size: data.size,
          levels: data.levels,
          key: data.key
        })
      });

      const result = await response.json();
      if (result.status !== 'success') {
        throw new Error(result.error || 'Hashing failed');
      }

      return {
        success: true,
        result: result.result
      };
    } catch (error) {
      console.error('Hashing error:', error);
      return {
        success: false,
        error: error.message || 'Network error occurred'
      };
    }
  },

  async verifyHash(data) {
    try {
      const response = await fetch(`${API_BASE_URL}/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          algorithm: data.algorithm,
          data: data.input,
          hash: data.hash,
          inputFormat: data.inputFormat || 'UTF-8',
          hashFormat: data.hashFormat || 'HEX',
          rounds: data.rounds,
          cost: data.cost,
          length: data.length,
          size: data.size,
          levels: data.levels,
          key: data.key
        })
      });

      const result = await response.json();
      if (result.status !== 'success') {
        throw new Error(result.error || 'Verification failed');
      }

      return {
        success: true,
        result: result.result
      };
    } catch (error) {
      console.error('Verify hash error:', error);
      return {
        success: false,
        error: error.message || 'Network error occurred'
      };
    }
  },

  async jwtSign(data) {
    try {
      const response = await fetch(`${API_BASE_URL}/jwt/sign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          payload: data.payload,
          key: data.key,
          algorithm: data.algorithm,
          headers: data.headers
        })
      });

      const result = await response.json();
      if (result.status !== 'success') {
        throw new Error(result.error || 'JWT sign failed');
      }

      return {
        success: true,
        result: result.result
      };
    } catch (error) {
      console.error('JWT sign error:', error);
      return {
        success: false,
        error: error.message || 'Network error occurred'
      };
    }
  },

  async jwtVerify(data) {
    try {
      const response = await fetch(`${API_BASE_URL}/jwt/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          token: data.token,
          key: data.key,
          algorithm: data.algorithm,
          audience: data.audience,
          issuer: data.issuer,
          leeway: data.leeway,
          verify_exp: data.verify_exp,
          verify_nbf: data.verify_nbf,
          verify_iat: data.verify_iat
        })
      });

      const result = await response.json();
      if (result.status !== 'success') {
        throw new Error(result.error || 'JWT verify failed');
      }

      return {
        success: true,
        result: result.result
      };
    } catch (error) {
      console.error('JWT verify error:', error);
      return {
        success: false,
        error: error.message || 'Network error occurred'
      };
    }
  },

  async jwtDecode(data) {
    try {
      const response = await fetch(`${API_BASE_URL}/jwt/decode`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          token: data.token
        })
      });

      const result = await response.json();
      if (result.status !== 'success') {
        throw new Error(result.error || 'JWT decode failed');
      }

      return {
        success: true,
        result: result.result
      };
    } catch (error) {
      console.error('JWT decode error:', error);
      return {
        success: false,
        error: error.message || 'Network error occurred'
      };
    }
  },

  async hashAll(data) {
    try {
      const response = await fetch(`${API_BASE_URL}/hash/all`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          data: data.input,
          inputFormat: data.inputFormat || 'UTF-8',
          outputFormat: data.outputFormat || 'HEX',
          algorithms: data.algorithms,
          include_bcrypt: data.includeBcrypt,
          length: data.length,
          md6_size: data.md6Size ?? data.size,
          md6_levels: data.md6Levels ?? data.levels,
          md6_key: data.md6Key ?? data.key
        })
      });

      const result = await response.json();
      if (result.status !== 'success') {
        throw new Error(result.error || 'Hash-all failed');
      }

      return {
        success: true,
        result: result.result
      };
    } catch (error) {
      console.error('Hash-all error:', error);
      return {
        success: false,
        error: error.message || 'Network error occurred'
      };
    }
  },

  async getAlgorithms() {
    try {
      const response = await fetch(`${API_BASE_URL}/`);
      const result = await response.json();
      
      return {
        success: true,
        algorithms: result.supported_modes || []
      };
    } catch (error) {
      console.error('Get algorithms error:', error);
      return {
        success: false,
        error: error.message || 'Network error occurred'
      };
    }
  },

  async healthCheck() {
    try {
      const response = await fetch(`${API_BASE_URL}/`);
      const result = await response.json();
      return {
        success: true,
        status: result.status,
        message: result.message
      };
    } catch (error) {
      return {
        success: false,
        error: error.message || 'Backend unavailable'
      };
    }
  },

  // Get operation history (placeholder)
  getHistory: async () => {
    return { success: true, data: [] };
  },

  // Benchmark function
  async benchmark(data) {
    try {
      const response = await fetch(`${API_BASE_URL}/benchmark`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          algorithm: data.algorithm,
          mode: data.mode,
          testData: data.testData,
          iterations: data.iterations || 10,
          scoringModel: data.scoringModel || 'general',
          powerConsumption: data.powerConsumption,
          ...(data.rails !== undefined ? { rails: data.rails } : {}),
          ...(data.offset !== undefined ? { offset: data.offset } : {}),
          ...(data.letter_delimiter !== undefined ? { letter_delimiter: data.letter_delimiter } : {}),
          ...(data.word_delimiter !== undefined ? { word_delimiter: data.word_delimiter } : {}),
          ...(data.dot_symbol !== undefined ? { dot_symbol: data.dot_symbol } : {}),
          ...(data.dash_symbol !== undefined ? { dash_symbol: data.dash_symbol } : {}),
            ...(data.rounds ? { rounds: data.rounds } : {}),
            ...(data.drop !== undefined ? { drop: data.drop } : {}),
            ...(data.drop_unit !== undefined ? { drop_unit: data.drop_unit } : {}),
            ...(data.md6Size !== undefined ? { md6_size: data.md6Size } : {}),
          ...(data.md6Levels !== undefined ? { md6_levels: data.md6Levels } : {}),
          ...(data.md6Key !== undefined ? { md6_key: data.md6Key } : {})
        })
      });

      const result = await response.json();
      
      if (result.status !== 'success') {
        throw new Error(result.error || 'Benchmark failed');
      }

      return {
        success: true,
        result: result.result
      };
    } catch (error) {
      console.error('Benchmark error:', error);
      return {
        success: false,
        error: error.message || 'Network error occurred'
      };
    }
  },

  // Get performance benchmarks (placeholder)
  getBenchmarks: async () => {
    return { success: true, data: [] };
  },
};

export default cryptoAPI; 

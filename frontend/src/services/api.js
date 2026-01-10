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
          counter: data.counter
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
          counter: data.counter
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
          ...(data.rounds ? { rounds: data.rounds } : {})
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

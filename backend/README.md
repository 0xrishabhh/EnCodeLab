# EnCodeLab Crypto Backend

A secure Flask backend providing symmetric encryption/decryption with multiple algorithms, including AES, 3DES, Blowfish, RC2, SM4, and the Salsa20 stream cipher.

## Features

### Supported Algorithms
- **AES** with modes CBC, CFB, OFB, CTR, GCM, ECB
- **3DES** with modes CBC, CFB, OFB, ECB
- **Blowfish** with modes CBC, CFB, OFB, ECB
- **RC2** with modes CBC, ECB
- **SM4** with modes CBC, CFB, OFB, CTR, GCM, ECB
- **Salsa20** (stream cipher) with selectable rounds (8/12/20), nonce, and counter

### Supported AES Modes
- **CBC** (Cipher Block Chaining)
- **CFB** (Cipher Feedback)
- **OFB** (Output Feedback)
- **CTR** (Counter)
- **GCM** (Galois/Counter Mode) - with authentication
- **ECB** (Electronic Codebook) - not recommended for production

### Supported Encodings
- **HEX** - Hexadecimal encoding
- **Base64** - Base64 encoding
- **UTF-8** - UTF-8 text encoding

### Key Management
- **Key Validation**: Accepts 16, 24, or 32-byte keys (AES-128, AES-192, AES-256)
- **Auto-generation**: Securely generates random keys if none provided
- **Multiple Formats**: Accepts keys in hex or UTF-8 format

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Start the server:
```bash
python run.py
```

The server will be available at `http://localhost:5000`

## API Endpoints

### Health Check
```
GET /
```

Returns server status and supported features.

### Encrypt Data
```
POST /encrypt
```

**Request Body:**
```json
{
  "mode": "CBC|CFB|OFB|CTR|GCM|ECB",
  "data": "plaintext data",
  "encoding": "HEX|Base64|UTF-8",
  "key": "optional_key_in_hex_or_utf8"
}
```

**Response:**
```json
{
  "status": "success",
  "result": {
    "ciphertext": "encrypted_data",
    "key": "hex_encoded_key",
    "mode": "ENCRYPTION_MODE",
    "iv_or_nonce": "hex_encoded_iv_or_nonce",
    "tag": "hex_encoded_tag_for_gcm",
    "key_generated": true
  }
}
```

### Decrypt Data
```
POST /decrypt
```

**Request Body:**
```json
{
  "mode": "CBC|CFB|OFB|CTR|GCM|ECB",
  "data": "ciphertext data",
  "encoding": "HEX|Base64|UTF-8",
  "key": "hex_encoded_key",
  "iv_or_nonce": "hex_encoded_iv_or_nonce",
  "tag": "hex_encoded_tag_for_gcm"
}
```

**Response:**
```json
{
  "status": "success",
  "result": {
    "plaintext": "decrypted_data",
    "key": "hex_encoded_key",
    "mode": "DECRYPTION_MODE",
    "iv_or_nonce": "hex_encoded_iv_or_nonce"
  }
}
```

## Usage Examples

### Example 1: Basic Encryption (Auto-generated Key)
```bash
curl -X POST http://localhost:5000/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "CBC",
    "data": "Hello, World!",
    "encoding": "UTF-8"
  }'
```

### Example 2: Encryption with Custom Key
```bash
curl -X POST http://localhost:5000/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "GCM",
    "data": "Secret message",
    "encoding": "UTF-8",
    "key": "0123456789abcdef0123456789abcdef"
  }'
```

### Example 3: Decryption
```bash
curl -X POST http://localhost:5000/decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "CBC",
    "data": "encrypted_ciphertext_here",
    "encoding": "UTF-8",
    "key": "0123456789abcdef0123456789abcdef",
    "iv_or_nonce": "iv_from_encryption_here"
  }'
```

## Security Features

- **Secure Random Generation**: Uses `secrets` module for cryptographically secure randomness
- **Input Validation**: Comprehensive validation of all inputs
- **Error Handling**: Graceful error handling without exposing sensitive information
- **CORS Support**: Enabled for frontend communication
- **Memory Safety**: Uses the `cryptography` library for secure implementations

## Testing

Run the test suite to verify functionality:

```bash
python test_crypto.py
```

This will test all supported modes and encodings to ensure the backend is working correctly.

## Environment Variables

- `FLASK_ENV`: Set to `production` or `development` (default: `development`)
- `SECRET_KEY`: Flask secret key (auto-generated if not provided)

## Production Deployment

For production deployment, consider:

1. Use a production WSGI server like Gunicorn:
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

2. Set environment variables:
```bash
export FLASK_ENV=production
export SECRET_KEY=your-secure-secret-key
```

3. Use HTTPS in production
4. Implement rate limiting
5. Add authentication if needed

## Error Responses

All errors return JSON with descriptive messages:

```json
{
  "error": "Description of the error"
}
```

Common error scenarios:
- Invalid or missing required fields
- Unsupported encryption modes or encodings
- Invalid key lengths
- Missing IV/nonce for modes that require them
- Invalid input data encoding

## Architecture

The backend is built with:
- **Flask**: Lightweight web framework
- **cryptography**: Secure cryptographic library
- **flask-cors**: CORS support for frontend integration
- **gunicorn**: Production WSGI server

The code is organized into:
- `app.py`: Main Flask application and endpoints
- `config.py`: Configuration management
- `run.py`: Development server runner
- `test_crypto.py`: Test suite 

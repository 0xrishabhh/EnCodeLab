#!/usr/bin/env python3
"""
Test script for EnCodeLab Crypto Backend
Run this to test encryption/decryption functionality
"""

import requests
import sys

BASE_URL = 'http://localhost:5000'


def test_health_check():
    """Test the health check endpoint"""
    try:
        response = requests.get(f'{BASE_URL}/')
        print(f"[OK] Health check: {response.status_code}")
        print(f"   Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"[ERR] Health check failed: {e}")
        return False


def test_encryption_decryption(algorithm, mode, encoding, plaintext, key=None, extra=None):
    """Test encryption and decryption for a specific algorithm, mode and encoding"""
    print(f"\n[TEST] {algorithm}-{mode} with {encoding} encoding...")

    encrypt_data = {
        'algorithm': algorithm,
        'mode': mode,
        'data': plaintext,
        'inputFormat': encoding,
        'outputFormat': encoding
    }

    if key:
        encrypt_data['key'] = key
    if extra:
        encrypt_data.update(extra)

    try:
        encrypt_response = requests.post(f'{BASE_URL}/encrypt', json=encrypt_data)

        if encrypt_response.status_code != 200:
            print(f"[ERR] Encryption failed: {encrypt_response.json()}")
            return False

        encrypt_result = encrypt_response.json()['result']
        print(f"   [ENC] Encrypted: {encrypt_result['ciphertext'][:50]}...")
        print(f"   [KEY] Key: {encrypt_result['key']}")

        # Test decryption
        decrypt_input_encoding = encoding
        if encoding == 'UTF-8' and not encrypt_result['ciphertext'].startswith('['):
            if all(c in '0123456789abcdefABCDEF' for c in encrypt_result['ciphertext']):
                decrypt_input_encoding = 'HEX'

        decrypt_data = {
            'algorithm': algorithm,
            'mode': mode,
            'data': encrypt_result['ciphertext'],
            'encoding': decrypt_input_encoding,
            'output_encoding': encoding,
            'key': encrypt_result['key']
        }

        if 'iv_or_nonce' in encrypt_result:
            decrypt_data['iv_or_nonce'] = encrypt_result['iv_or_nonce']

        if 'tag' in encrypt_result:
            decrypt_data['tag'] = encrypt_result['tag']

        if extra:
            if 'rounds' in extra:
                decrypt_data['rounds'] = extra['rounds']
            if 'counter' in extra:
                decrypt_data['counter'] = extra['counter']
            if 'drop' in extra:
                decrypt_data['drop'] = extra['drop']
            if 'offset' in extra:
                decrypt_data['offset'] = extra['offset']
            if 'letter_delimiter' in extra:
                decrypt_data['letter_delimiter'] = extra['letter_delimiter']
            if 'word_delimiter' in extra:
                decrypt_data['word_delimiter'] = extra['word_delimiter']
            if 'dot_symbol' in extra:
                decrypt_data['dot_symbol'] = extra['dot_symbol']
            if 'dash_symbol' in extra:
                decrypt_data['dash_symbol'] = extra['dash_symbol']

        decrypt_response = requests.post(f'{BASE_URL}/decrypt', json=decrypt_data)

        if decrypt_response.status_code != 200:
            print(f"[ERR] Decryption failed: {decrypt_response.json()}")
            return False

        decrypt_result = decrypt_response.json()['result']
        decrypted_plaintext = decrypt_result['plaintext']

        if decrypted_plaintext == plaintext:
            print("   [OK] Round-trip successful!")
            return True
        else:
            print(f"[ERR] Round-trip failed! Original: {plaintext}, Decrypted: {decrypted_plaintext}")
            return False

    except Exception as e:
        print(f"[ERR] Test failed with exception: {e}")
        return False


def test_bcrypt_hashing(password, rounds=10):
    """Test bcrypt hashing and verification"""
    print(f"\n[TEST] BCRYPT hashing with cost {rounds}...")
    try:
        hash_response = requests.post(f'{BASE_URL}/hash', json={
            'algorithm': 'BCRYPT',
            'data': password,
            'inputFormat': 'UTF-8',
            'rounds': rounds
        })

        if hash_response.status_code != 200:
            print(f"[ERR] Hashing failed: {hash_response.json()}")
            return False

        hash_result = hash_response.json()['result']
        hashed_value = hash_result['hash']
        print(f"   [HASH] {hashed_value[:20]}... (truncated)")

        verify_response = requests.post(f'{BASE_URL}/verify', json={
            'algorithm': 'BCRYPT',
            'data': password,
            'hash': hashed_value,
            'inputFormat': 'UTF-8'
        })

        if verify_response.status_code != 200:
            print(f"[ERR] Verify failed: {verify_response.json()}")
            return False

        verified = verify_response.json()['result']['verified']
        if verified:
            print("   [OK] bcrypt verification successful!")
            return True
        print("   [ERR] bcrypt verification failed!")
        return False
    except Exception as e:
        print(f"[ERR] bcrypt test failed with exception: {e}")
        return False


def main():
    """Run all tests"""
    print("[START] EnCodeLab Crypto Backend Tests...")

    if not test_health_check():
        print("[ERR] Backend is not running. Please start it with: python run.py")
        sys.exit(1)

    test_cases = [
        # DES modes
        {'algorithm': 'DES', 'mode': 'ECB', 'encoding': 'RAW', 'plaintext': 'Hello, DES!'},
        {'algorithm': 'DES', 'mode': 'CBC', 'encoding': 'RAW', 'plaintext': 'Hello, DES!'},
        {'algorithm': 'DES', 'mode': 'CTR', 'encoding': 'RAW', 'plaintext': 'Hello, DES!'},
        # SM4 modes
        {'algorithm': 'SM4', 'mode': 'CBC', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': 'SM4', 'mode': 'CBC', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
        {'algorithm': 'SM4', 'mode': 'CFB', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': 'SM4', 'mode': 'CFB', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
        {'algorithm': 'SM4', 'mode': 'OFB', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': 'SM4', 'mode': 'OFB', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
        {'algorithm': 'SM4', 'mode': 'CTR', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': 'SM4', 'mode': 'CTR', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
        {'algorithm': 'SM4', 'mode': 'GCM', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': 'SM4', 'mode': 'GCM', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
        {'algorithm': 'SM4', 'mode': 'ECB', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': 'SM4', 'mode': 'ECB', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
        # Salsa20 stream cipher
        {'algorithm': 'SALSA20', 'mode': 'STREAM', 'encoding': 'RAW', 'plaintext': 'Hello, Salsa20!', 'extra': {'rounds': 20, 'counter': 1}},
        {'algorithm': 'SALSA20', 'mode': 'STREAM', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c2053616c7361323021', 'extra': {'rounds': 12, 'counter': 0}},
        # ChaCha20 stream cipher
        {'algorithm': 'CHACHA20', 'mode': 'STREAM', 'encoding': 'RAW', 'plaintext': 'Hello, ChaCha20!', 'extra': {'rounds': 20, 'counter': 1}},
        {'algorithm': 'CHACHA20', 'mode': 'STREAM', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20436861436861323021', 'extra': {'rounds': 12, 'counter': 0}},
        # RC4 stream cipher
        {'algorithm': 'RC4', 'mode': 'STREAM', 'encoding': 'RAW', 'plaintext': 'Hello, RC4!', 'key': 'secret', 'extra': {'drop': 0}},
        {'algorithm': 'RC4', 'mode': 'STREAM', 'encoding': 'RAW', 'plaintext': 'Hello, RC4 Drop!', 'key': 'secret', 'extra': {'drop': 768}},
        # Rail Fence cipher
        {'algorithm': 'RAILFENCE', 'mode': 'RAILFENCE', 'encoding': 'RAW', 'plaintext': 'HELLO RAILFENCE', 'extra': {'offset': 2}},
        # Morse Code
        {'algorithm': 'MORSE', 'mode': 'MORSE', 'encoding': 'RAW', 'plaintext': 'HELLO WORLD', 'extra': {'letter_delimiter': ' ', 'word_delimiter': '\n', 'dot_symbol': '.', 'dash_symbol': '-'}},
        # Vigenere Cipher
        {'algorithm': 'VIGENERE', 'mode': 'VIGENERE', 'encoding': 'RAW', 'plaintext': 'ATTACKATDAWN', 'key': 'LEMON'},
    ]

    passed = 0
    total = len(test_cases) + 1

    for case in test_cases:
        if test_encryption_decryption(
            case['algorithm'],
            case['mode'],
            case['encoding'],
            case['plaintext'],
            case.get('key'),
            case.get('extra')
        ):
            passed += 1

    if test_bcrypt_hashing("CorrectHorseBatteryStaple", rounds=10):
        passed += 1

    print(f"\n[SUMMARY] Results: {passed}/{total} tests passed")

    if passed == total:
        print("[OK] All tests passed! Backend is working correctly.")
        sys.exit(0)
    else:
        print("[ERR] Some tests failed. Please check the backend implementation.")
        sys.exit(1)


if __name__ == '__main__':
    main()

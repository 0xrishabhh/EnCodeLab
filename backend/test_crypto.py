#!/usr/bin/env python3
"""
Test script for EnCodeLab Crypto Backend
Run this to test encryption/decryption functionality
"""

import requests
import json
import sys

BASE_URL = 'http://localhost:5000'

def test_health_check():
    """Test the health check endpoint"""
    try:
        response = requests.get(f'{BASE_URL}/')
        print(f"✅ Health check: {response.status_code}")
        print(f"   Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False

def test_encryption_decryption(algorithm, mode, encoding, plaintext, key=None):
    """Test encryption and decryption for a specific algorithm, mode and encoding"""
    print(f"\n🔐 Testing {algorithm}-{mode} mode with {encoding} encoding...")
    
    # Test encryption
    encrypt_data = {
        'algorithm': algorithm,
        'mode': mode,
        'data': plaintext,
        'inputFormat': encoding,
        'outputFormat': encoding
    }
    
    if key:
        encrypt_data['key'] = key
    
    try:
        encrypt_response = requests.post(f'{BASE_URL}/encrypt', json=encrypt_data)
        
        if encrypt_response.status_code != 200:
            print(f"❌ Encryption failed: {encrypt_response.json()}")
            return False
        
        encrypt_result = encrypt_response.json()['result']
        print(f"   🔒 Encrypted: {encrypt_result['ciphertext'][:50]}...")
        print(f"   🔑 Key: {encrypt_result['key']}")
        
        # Test decryption
        # For UTF-8 encoding, if the encrypted output is actually HEX (due to fallback),
        # we need to use HEX as the input encoding for decryption
        decrypt_input_encoding = encoding
        if encoding == 'UTF-8' and encrypt_result['ciphertext'].startswith('[') == False:
            # If the output doesn't start with '[' (meaning it's not the fallback format),
            # and it looks like HEX, use HEX for decryption
            if all(c in '0123456789abcdefABCDEF' for c in encrypt_result['ciphertext']):
                decrypt_input_encoding = 'HEX'
        
        decrypt_data = {
            'algorithm': algorithm,
            'mode': mode,
            'data': encrypt_result['ciphertext'],
            'encoding': decrypt_input_encoding,
            'output_encoding': encoding,  # Use original encoding for output
            'key': encrypt_result['key']
        }
        
        if 'iv_or_nonce' in encrypt_result:
            decrypt_data['iv_or_nonce'] = encrypt_result['iv_or_nonce']
        
        if 'tag' in encrypt_result:
            decrypt_data['tag'] = encrypt_result['tag']
        
        decrypt_response = requests.post(f'{BASE_URL}/decrypt', json=decrypt_data)
        
        if decrypt_response.status_code != 200:
            print(f"❌ Decryption failed: {decrypt_response.json()}")
            return False
        
        decrypt_result = decrypt_response.json()['result']
        decrypted_plaintext = decrypt_result['plaintext']
        
        if decrypted_plaintext == plaintext:
            print(f"   ✅ Round-trip successful!")
            return True
        else:
            print(f"❌ Round-trip failed! Original: {plaintext}, Decrypted: {decrypted_plaintext}")
            return False
            
    except Exception as e:
        print(f"❌ Test failed with exception: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 Starting EnCodeLab Crypto Backend Tests...")
    
    # Test health check first
    if not test_health_check():
        print("❌ Backend is not running. Please start it with: python run.py")
        sys.exit(1)
    
    # Test data - All AES and 3DES modes with HEX and RAW encodings
    test_cases = [
        # AES modes
        {'algorithm': 'AES', 'mode': 'CBC', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': 'AES', 'mode': 'CBC', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
        {'algorithm': 'AES', 'mode': 'CFB', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': 'AES', 'mode': 'CFB', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
        {'algorithm': 'AES', 'mode': 'OFB', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': 'AES', 'mode': 'OFB', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
        {'algorithm': 'AES', 'mode': 'CTR', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': 'AES', 'mode': 'CTR', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
        {'algorithm': 'AES', 'mode': 'GCM', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': 'AES', 'mode': 'GCM', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
        {'algorithm': 'AES', 'mode': 'ECB', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': 'AES', 'mode': 'ECB', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
        # 3DES modes (excluding CTR and GCM which are not supported)
        {'algorithm': '3DES', 'mode': 'CBC', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': '3DES', 'mode': 'CBC', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
        {'algorithm': '3DES', 'mode': 'CFB', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': '3DES', 'mode': 'CFB', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
        {'algorithm': '3DES', 'mode': 'OFB', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': '3DES', 'mode': 'OFB', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
        {'algorithm': '3DES', 'mode': 'ECB', 'encoding': 'HEX', 'plaintext': '48656c6c6f2c20576f726c6421'},
        {'algorithm': '3DES', 'mode': 'ECB', 'encoding': 'RAW', 'plaintext': 'Hello, World!'},
    ]
    
    passed = 0
    total = len(test_cases)
    
    for case in test_cases:
        if test_encryption_decryption(case['algorithm'], case['mode'], case['encoding'], case['plaintext']):
            passed += 1
    
    print(f"\n📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Backend is working correctly.")
        sys.exit(0)
    else:
        print("⚠️  Some tests failed. Please check the backend implementation.")
        sys.exit(1)

if __name__ == '__main__':
    main() 
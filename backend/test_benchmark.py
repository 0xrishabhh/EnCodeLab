#!/usr/bin/env python3
"""
Test script for the benchmark endpoint
"""

import requests
import json
import time

def test_benchmark():
    """Test the benchmark endpoint with different configurations"""
    
    base_url = "http://localhost:5000"
    
    # Test configurations
    test_configs = [
        {
            "name": "AES-CBC Small Data",
            "algorithm": "AES",
            "mode": "CBC",
            "testData": "Hello World! This is a test message.",
            "iterations": 5
        },
        {
            "name": "3DES-CBC Small Data",
            "algorithm": "3DES",
            "mode": "CBC",
            "testData": "Hello World! This is a test message.",
            "iterations": 5
        },
        {
            "name": "AES-ECB Large Data",
            "algorithm": "AES",
            "mode": "ECB",
            "testData": "A" * 1024,  # 1KB of data
            "iterations": 3
        }
    ]
    
    print("🧪 Starting Benchmark Endpoint Tests...")
    
    for config in test_configs:
        print(f"\n🔬 Testing: {config['name']}")
        
        try:
            # Make benchmark request
            response = requests.post(
                f"{base_url}/benchmark",
                json={
                    "algorithm": config["algorithm"],
                    "mode": config["mode"],
                    "testData": config["testData"],
                    "iterations": config["iterations"]
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("status") == "success":
                    benchmark_result = result["result"]
                    
                    print(f"   ✅ Success!")
                    print(f"   📊 Algorithm: {benchmark_result['algorithm']}")
                    print(f"   🔧 Mode: {benchmark_result['mode']}")
                    print(f"   📏 Data Size: {benchmark_result['dataSize']} bytes")
                    print(f"   🔄 Iterations: {benchmark_result['iterations']}")
                    print(f"   ⏱️  Encryption: {benchmark_result['encryption']['avgTimeMs']}ms avg")
                    print(f"   ⏱️  Decryption: {benchmark_result['decryption']['avgTimeMs']}ms avg")
                    print(f"   🚀 Encryption Throughput: {benchmark_result['encryption']['throughputMBps']} MB/s")
                    print(f"   🚀 Decryption Throughput: {benchmark_result['decryption']['throughputMBps']} MB/s")
                    print(f"   💾 Memory Usage: {benchmark_result['memory']['avgUsageMB']} MB avg")
                    
                else:
                    print(f"   ❌ API Error: {result.get('error', 'Unknown error')}")
            else:
                print(f"   ❌ HTTP Error: {response.status_code}")
                print(f"   Response: {response.text}")
                
        except requests.exceptions.RequestException as e:
            print(f"   ❌ Request Error: {e}")
        except Exception as e:
            print(f"   ❌ Unexpected Error: {e}")
    
    print("\n🎉 Benchmark tests completed!")

if __name__ == "__main__":
    test_benchmark() 
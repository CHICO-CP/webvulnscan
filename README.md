# 🌐 WebVulnScan - Web Security Assessment Tool

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)

A comprehensive, automated web vulnerability scanner designed for security professionals and developers to identify and remediate security issues in web applications.

## 🚀 Features

### 🔍 Security Testing Capabilities
- **SQL Injection** - Detects database manipulation vulnerabilities
- **Cross-Site Scripting (XSS)** - Identifies client-side script injection points
- **Directory Traversal** - Tests for unauthorized file system access
- **Command Injection** - Checks for OS command execution vulnerabilities
- **Sensitive File Exposure** - Scans for publicly accessible sensitive files
- **Security Headers Analysis** - Validates HTTP security headers implementation
- **SSL/TLS Configuration** - Assesses HTTPS and certificate security
- **Server Information Disclosure** - Detects information leakage in headers

### 📊 Risk Assessment
- **CRITICAL** - Immediate action required (SQLi, Command Injection)
- **HIGH** - Address within 48 hours (XSS, No HTTPS)
- **MEDIUM** - Plan for next update (Missing headers, File exposure)
- **LOW** - Monitor and document (Information disclosure)
- **INFO** - Security best practices confirmation

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Quick Setup

# Clone the repository
```bash
git clone https://github.com/CHICO-CP/webvulnscan.git
cd webvulnscan
```
# Install dependencies
```
pip install -r requirements.txt
```

🎯 Usage

Basic Usage

```bash
python webvulnscan.py
```

Interactive Mode

When you run the script, it will prompt you for the target URL:

```
Enter the target URL to scan:
Example: https://example.com or example.com
> example.com
```

Supported URL Formats

· https://example.com

· http://example.com

· example.com (auto-prefixes with http://)
· subdomain.example.com/path

📋 What Gets Tested

1. SQL Injection Testing

· Boolean-based SQL injection

· Union-based SQL injection

· Error-based SQL injection

· Time-based blind SQLi

2. XSS Testing

· Reflected XSS vectors

· HTML tag injection

· JavaScript execution tests

· Event handler injection

3. Directory Traversal

· Unix/Linux path traversal

· Windows path traversal

· Encoded traversal attempts

· File inclusion tests

4. Command Injection

· Unix command execution

· Windows command execution

· Pipeline command injection

· Substitution-based injection

5. Sensitive Files Check

· Configuration files (.env, config.php)

· Version control files (.git/config)

· Backup files (backup.zip, dump.sql)

· Administrative interfaces (/admin, /phpmyadmin)

· Debug files (phpinfo.php, test.php)

6. Security Headers

· Content-Security-Policy

· X-Frame-Options

· X-Content-Type-Options

· Strict-Transport-Security

· X-XSS-Protection

7. SSL/TLS Security

· HTTPS enforcement

· Certificate validation

· Secure protocol detection

8. Server Information

· Server software disclosure
· Framework information leakage
· Version number exposure

📊 Sample Output

```
🔍 SECURITY ASSESSMENT REPORT
================================================================================

Total Security Issues Found: 3

🔴 CRITICAL ISSUES (1)
--------------------------------------------------
1. SQL Injection
   📝 Potential SQL injection vulnerability detected
   🌐 URL: http://example.com?id=' OR '1'='1'--
   ⚡ Payload: ' OR '1'='1'--
   🛠️  Solution: Use parameterized queries and input validation

🟣 HIGH ISSUES (1)
--------------------------------------------------
1. No HTTPS
   📝 Website not using HTTPS
   🛠️  Solution: Implement SSL/TLS certificate and redirect HTTP to HTTPS

🟡 MEDIUM ISSUES (1)
--------------------------------------------------
1. Missing Security Header
   📝 Security header Content-Security-Policy is missing
   🏷️  Header: Content-Security-Policy
   🛠️  Solution: Implement Content-Security-Policy security header
```

⚙️ Configuration

Customizing Tests

You can modify the payloads and tests by editing the corresponding methods in the WebVulnScan class:

```python
# Example: Adding custom SQL injection payloads
payloads = [
    "' OR '1'='1'--",
    "' UNION SELECT 1,2,3--",
    # Add your custom payloads here
]
```

Request Headers

The tool uses a standard browser User-Agent by default:

```python
self.session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
})
```

🛡️ Ethical Usage

✅ Permitted Usage

· Testing your own web applications

· Authorized penetration testing with explicit permission

· Educational purposes in controlled environments

· Security research with proper authorization

· Bug bounty programs where allowed

❌ Prohibited Usage

· Scanning websites without explicit permission

· Testing production systems without authorization

· Malicious hacking attempts

· Any illegal activities

Legal Disclaimer

This tool is provided for educational and authorized security testing purposes only. The developers are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before scanning any website.

🐛 Troubleshooting

Common Issues

Module Not Found Error:

```bash
# Ensure all dependencies are installed
pip install requests colorama
```

SSL Certificate Errors:

· The tool will report SSL issues in the security report

· This is expected behavior for misconfigured certificates

Connection Timeouts:

· Check your internet connection

· Verify the target website is accessible

· Some websites may block automated scanning

False Positives:

· Review findings carefully

· Some security headers may be intentionally omitted

· Verify vulnerabilities manually when possible

🤝 Contributing

We welcome contributions from the security community! Here's how you can help:

1. Report Bugs - Open an issue with detailed information
2. Suggest Features - Propose new security tests or improvements
3. Submit Pull Requests - Contribute code enhancements
4. Improve Documentation - Help make the tool more accessible

Development Setup

```bash
git clone https://github.com/CHICO-CP/webvulnscan.git
cd webvulnscan
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

👨‍💻 Developer

· Profile: [Ghost Developer](t.me/Gh0stDeveloper)

· GitHub: @CHICO-CP

· Telegram: [Group](https://t.me/CodeBreakersHub)

🙏 Acknowledgments

· Security researchers and the open-source community

· OWASP for vulnerability classification standards

· Contributors who help improve web security

📞 Support

If you need help or have questions:

1. Check the troubleshooting section above
2. Open an issue on GitHub
3. Contact through Telegram channel



Remember: With great power comes great responsibility. Always scan ethically and with proper authorization.

⭐ If you find this tool useful, please give it a star on GitHub!

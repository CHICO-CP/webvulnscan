#!/usr/bin/env python3
"""
🌐 WebVulnScan - Web Security Assessment Tool
🔍 Comprehensive Web Vulnerability Scanner
Developer: @CHICO-CP
Telegram Channel: @SecurityResearchUpdates
"""

import requests
import time
import json
import sys
import os
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init
import threading
from concurrent.futures import ThreadPoolExecutor

# Initialize colorama
init(autoreset=True)

class WebVulnScan:
    def __init__(self):
        self.banner = f"""
{Fore.CYAN}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║    🌐 {Fore.YELLOW}WebVulnScan - Web Security Assessment Tool{Fore.CYAN}        ║
║                 {Fore.WHITE}Comprehensive Vulnerability Scanner{Fore.CYAN}       ║
║                                                                ║
║    {Fore.GREEN}Developer: @Gh0stDeveloper{Fore.CYAN}                                  ║
║    {Fore.GREEN}Telegram: https://t.me/CodeBreakersHub{Fore.CYAN}                    ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
        """
        self.results = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def print_banner(self):
        print(self.banner)

    def check_sql_injection(self, url):
        """Test for SQL Injection vulnerabilities"""
        print(f"{Fore.BLUE}[*] Testing SQL Injection...{Style.RESET_ALL}")
        
        payloads = [
            "' OR '1'='1'--",
            "' UNION SELECT 1,2,3--",
            "'; DROP TABLE users--",
            "' AND 1=1--",
            "' AND 1=2--"
        ]
        
        vulnerable = False
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            try:
                response = self.session.get(test_url, timeout=10)
                if any(indicator in response.text.lower() for indicator in ['sql', 'syntax', 'mysql', 'oracle', 'database']):
                    self.results["critical"].append({
                        "type": "SQL Injection",
                        "url": test_url,
                        "payload": payload,
                        "description": "Potential SQL injection vulnerability detected",
                        "solution": "Use parameterized queries and input validation"
                    })
                    vulnerable = True
                    break
            except:
                continue
                
        if not vulnerable:
            self.results["info"].append("SQL Injection: No vulnerabilities detected")

    def check_xss(self, url):
        """Test for Cross-Site Scripting vulnerabilities"""
        print(f"{Fore.BLUE}[*] Testing XSS...{Style.RESET_ALL}")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>"
        ]
        
        vulnerable = False
        for payload in payloads:
            test_url = f"{url}?search={payload}"
            try:
                response = self.session.get(test_url, timeout=10)
                if payload in response.text:
                    self.results["high"].append({
                        "type": "Cross-Site Scripting (XSS)",
                        "url": test_url,
                        "payload": payload,
                        "description": "XSS vulnerability detected - user input not properly sanitized",
                        "solution": "Implement proper input sanitization and output encoding"
                    })
                    vulnerable = True
                    break
            except:
                continue
                
        if not vulnerable:
            self.results["info"].append("XSS: No vulnerabilities detected")

    def check_directory_traversal(self, url):
        """Test for Directory Traversal vulnerabilities"""
        print(f"{Fore.BLUE}[*] Testing Directory Traversal...{Style.RESET_ALL}")
        
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd"
        ]
        
        vulnerable = False
        for payload in payloads:
            test_url = f"{url}?file={payload}"
            try:
                response = self.session.get(test_url, timeout=10)
                if any(indicator in response.text.lower() for indicator in ['root:', 'administrator:', 'password:']):
                    self.results["critical"].append({
                        "type": "Directory Traversal",
                        "url": test_url,
                        "payload": payload,
                        "description": "Directory traversal vulnerability allows file system access",
                        "solution": "Validate and sanitize file path inputs"
                    })
                    vulnerable = True
                    break
            except:
                continue
                
        if not vulnerable:
            self.results["info"].append("Directory Traversal: No vulnerabilities detected")

    def check_command_injection(self, url):
        """Test for Command Injection vulnerabilities"""
        print(f"{Fore.BLUE}[*] Testing Command Injection...{Style.RESET_ALL}")
        
        payloads = [
            "; ls -la",
            "| whoami",
            "&& cat /etc/passwd",
            "$(whoami)"
        ]
        
        vulnerable = False
        for payload in payloads:
            test_url = f"{url}?cmd={payload}"
            try:
                response = self.session.get(test_url, timeout=10)
                if any(indicator in response.text.lower() for indicator in ['root', 'admin', 'microsoft', 'linux']):
                    self.results["critical"].append({
                        "type": "Command Injection",
                        "url": test_url,
                        "payload": payload,
                        "description": "Command injection vulnerability allows OS command execution",
                        "solution": "Use whitelist input validation and avoid shell command execution"
                    })
                    vulnerable = True
                    break
            except:
                continue
                
        if not vulnerable:
            self.results["info"].append("Command Injection: No vulnerabilities detected")

    def check_sensitive_files(self, base_url):
        """Check for exposed sensitive files"""
        print(f"{Fore.BLUE}[*] Checking for sensitive files...{Style.RESET_ALL}")
        
        sensitive_files = [
            "/.env", "/config.php", "/.git/config", "/backup.zip",
            "/phpinfo.php", "/admin.php", "/test.php", "/debug.php",
            "/.htaccess", "/web.config", "/robots.txt", "/admin",
            "/phpmyadmin", "/database", "/backup", "/logs"
        ]
        
        found_files = []
        for file_path in sensitive_files:
            test_url = urljoin(base_url, file_path)
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    found_files.append(test_url)
                    self.results["medium"].append({
                        "type": "Exposed Sensitive File",
                        "url": test_url,
                        "description": "Sensitive file exposed to public access",
                        "solution": "Restrict access to sensitive files and directories"
                    })
            except:
                continue
                
        if not found_files:
            self.results["info"].append("Sensitive Files: No exposed files detected")

    def check_security_headers(self, url):
        """Check for security headers"""
        print(f"{Fore.BLUE}[*] Checking security headers...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            security_headers = {
                "Content-Security-Policy": "MEDIUM",
                "X-Frame-Options": "MEDIUM", 
                "X-Content-Type-Options": "LOW",
                "Strict-Transport-Security": "HIGH",
                "X-XSS-Protection": "LOW"
            }
            
            missing_headers = []
            for header, severity in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
                    self.results[severity.lower()].append({
                        "type": "Missing Security Header",
                        "header": header,
                        "description": f"Security header {header} is missing",
                        "solution": f"Implement {header} security header"
                    })
            
            if not missing_headers:
                self.results["info"].append("Security Headers: All major security headers present")
                
        except Exception as e:
            self.results["info"].append(f"Security Headers: Check failed - {str(e)}")

    def check_ssl_tls(self, url):
        """Check SSL/TLS configuration"""
        print(f"{Fore.BLUE}[*] Checking SSL/TLS configuration...{Style.RESET_ALL}")
        
        try:
            if not url.startswith('https://'):
                self.results["high"].append({
                    "type": "No HTTPS",
                    "description": "Website not using HTTPS",
                    "solution": "Implement SSL/TLS certificate and redirect HTTP to HTTPS"
                })
                return
                
            response = self.session.get(url, timeout=10, verify=True)
            self.results["info"].append("SSL/TLS: HTTPS is properly configured")
            
        except requests.exceptions.SSLError:
            self.results["medium"].append({
                "type": "SSL/TLS Issue",
                "description": "SSL certificate validation failed",
                "solution": "Fix SSL certificate configuration"
            })
        except:
            self.results["info"].append("SSL/TLS: Could not verify SSL configuration")

    def check_server_info(self, url):
        """Check for server information disclosure"""
        print(f"{Fore.BLUE}[*] Checking server information...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            disclosed_info = []
            
            for header in info_headers:
                if header in headers:
                    disclosed_info.append(f"{header}: {headers[header]}")
            
            if disclosed_info:
                self.results["low"].append({
                    "type": "Server Information Disclosure",
                    "description": f"Server information exposed: {', '.join(disclosed_info)}",
                    "solution": "Remove or obscure server version information from headers"
                })
            else:
                self.results["info"].append("Server Info: No sensitive information disclosed")
                
        except Exception as e:
            self.results["info"].append(f"Server Info: Check failed - {str(e)}")

    def generate_report(self):
        """Generate comprehensive security report"""
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📊 SECURITY ASSESSMENT REPORT{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        
        total_issues = sum(len(issues) for severity, issues in self.results.items() if severity != 'info')
        
        print(f"{Fore.WHITE}Total Security Issues Found: {total_issues}{Style.RESET_ALL}\n")
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            issues = self.results[severity]
            if issues:
                color = {
                    "critical": Fore.RED,
                    "high": Fore.MAGENTA,
                    "medium": Fore.YELLOW,
                    "low": Fore.BLUE,
                    "info": Fore.GREEN
                }[severity]
                
                print(f"\n{color}🔍 {severity.upper()} ISSUES ({len(issues)}){Style.RESET_ALL}")
                print(f"{color}{'-'*50}{Style.RESET_ALL}")
                
                for i, issue in enumerate(issues, 1):
                    print(f"{color}{i}. {issue['type']}{Style.RESET_ALL}")
                    print(f"   📝 {issue['description']}")
                    if 'url' in issue:
                        print(f"   🌐 URL: {issue['url']}")
                    if 'payload' in issue:
                        print(f"   ⚡ Payload: {issue['payload']}")
                    if 'header' in issue:
                        print(f"   🏷️  Header: {issue['header']}")
                    print(f"   🛠️  Solution: {issue['solution']}")
                    print()

    def scan_website(self, url):
        """Perform comprehensive security scan"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        print(f"{Fore.GREEN}[+] Starting security scan for: {url}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Scan initiated at: {time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}\n")
        
        # Perform all security checks
        checks = [
            self.check_sql_injection,
            self.check_xss,
            self.check_directory_traversal,
            self.check_command_injection,
            self.check_sensitive_files,
            self.check_security_headers,
            self.check_ssl_tls,
            self.check_server_info
        ]
        
        for check in checks:
            try:
                check(url)
                time.sleep(0.5)  
            except Exception as e:
                print(f"{Fore.RED}[-] Check failed: {str(e)}{Style.RESET_ALL}")
        
        # Generate final report
        self.generate_report()

def main():
    scanner = WebVulnScan()
    scanner.print_banner()
    
    print(f"{Fore.YELLOW}[?] Enter the target URL to scan:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Example: https://example.com or example.com{Style.RESET_ALL}")
    print(f"{Fore.WHITE}> {Style.RESET_ALL}", end='')
    
    url = input().strip()
    
    if not url:
        print(f"{Fore.RED}[-] No URL provided. Exiting.{Style.RESET_ALL}")
        sys.exit(1)
    
    try:
        scanner.scan_website(url)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Scan failed: {str(e)}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}🎯 Scan completed! Check the report above for security issues.{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
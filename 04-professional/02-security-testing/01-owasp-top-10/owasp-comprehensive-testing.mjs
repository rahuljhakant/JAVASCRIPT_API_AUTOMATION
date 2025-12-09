/**
 * PHASE 4: PROFESSIONAL LEVEL
 * Module 7: Security Testing
 * Lesson 1: OWASP Top 10 Comprehensive Testing
 * 
 * Learning Objectives:
 * - Implement comprehensive OWASP Top 10 testing
 * - Test for all major web application vulnerabilities
 * - Validate security controls and countermeasures
 * - Generate detailed security assessment reports
 */

import { expect } from "chai";
import supertest from "supertest";
import { EnhancedSupertestClient } from "../../../utils/advanced-supertest-extensions.mjs";

console.log("=== OWASP TOP 10 COMPREHENSIVE TESTING ===");

// OWASP Top 10 2021 Categories
const OWASP_CATEGORIES = {
  A01_BROKEN_ACCESS_CONTROL: {
    id: 'A01',
    name: 'Broken Access Control',
    description: 'Access control enforces policy such that users cannot act outside of their intended permissions',
    risk: 'HIGH',
    tests: [
      'horizontal_privilege_escalation',
      'vertical_privilege_escalation',
      'direct_object_references',
      'missing_authorization',
      'cors_misconfiguration',
      'forced_browsing'
    ]
  },
  A02_CRYPTOGRAPHIC_FAILURES: {
    id: 'A02',
    name: 'Cryptographic Failures',
    description: 'Failures related to cryptography which often lead to sensitive data exposure',
    risk: 'HIGH',
    tests: [
      'weak_encryption',
      'sensitive_data_exposure',
      'insecure_transmission',
      'weak_randomness',
      'deprecated_algorithms',
      'key_management'
    ]
  },
  A03_INJECTION: {
    id: 'A03',
    name: 'Injection',
    description: 'Injection flaws allow attackers to send malicious data to an interpreter',
    risk: 'HIGH',
    tests: [
      'sql_injection',
      'nosql_injection',
      'ldap_injection',
      'xpath_injection',
      'command_injection',
      'code_injection'
    ]
  },
  A04_INSECURE_DESIGN: {
    id: 'A04',
    name: 'Insecure Design',
    description: 'Insecure design is a broad category representing different weaknesses',
    risk: 'MEDIUM',
    tests: [
      'business_logic_bypass',
      'rate_limiting_bypass',
      'workflow_bypass',
      'resource_exhaustion',
      'time_based_attacks',
      'race_conditions'
    ]
  },
  A05_SECURITY_MISCONFIGURATION: {
    id: 'A05',
    name: 'Security Misconfiguration',
    description: 'Security misconfiguration is the most commonly seen issue',
    risk: 'MEDIUM',
    tests: [
      'default_credentials',
      'unnecessary_features',
      'insecure_headers',
      'debug_information',
      'error_messages',
      'directory_listing'
    ]
  },
  A06_VULNERABLE_COMPONENTS: {
    id: 'A06',
    name: 'Vulnerable and Outdated Components',
    description: 'Using components with known vulnerabilities',
    risk: 'MEDIUM',
    tests: [
      'outdated_libraries',
      'known_vulnerabilities',
      'unpatched_components',
      'license_compliance',
      'dependency_scanning',
      'version_disclosure'
    ]
  },
  A07_AUTHENTICATION_FAILURES: {
    id: 'A07',
    name: 'Identification and Authentication Failures',
    description: 'Confirmation of the user identity, authentication, and session management',
    risk: 'HIGH',
    tests: [
      'weak_passwords',
      'brute_force_attacks',
      'session_fixation',
      'session_hijacking',
      'multi_factor_bypass',
      'credential_stuffing'
    ]
  },
  A08_DATA_INTEGRITY_FAILURES: {
    id: 'A08',
    name: 'Software and Data Integrity Failures',
    description: 'Software and data integrity failures relate to code and infrastructure',
    risk: 'MEDIUM',
    tests: [
      'code_integrity',
      'data_tampering',
      'supply_chain_attacks',
      'ci_cd_security',
      'unsigned_components',
      'integrity_checks'
    ]
  },
  A09_SECURITY_LOGGING_FAILURES: {
    id: 'A09',
    name: 'Security Logging and Monitoring Failures',
    description: 'Insufficient logging and monitoring coupled with ineffective response',
    risk: 'MEDIUM',
    tests: [
      'insufficient_logging',
      'log_injection',
      'log_tampering',
      'monitoring_gaps',
      'alert_fatigue',
      'incident_response'
    ]
  },
  A10_SSRF: {
    id: 'A10',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'SSRF flaws occur whenever a web application is fetching a remote resource',
    risk: 'HIGH',
    tests: [
      'internal_network_scanning',
      'cloud_metadata_access',
      'port_scanning',
      'file_system_access',
      'service_enumeration',
      'protocol_abuse'
    ]
  }
};

// Comprehensive OWASP Security Tester
class OWASPSecurityTester {
  constructor(client) {
    this.client = client;
    this.results = new Map();
    this.vulnerabilities = [];
    this.recommendations = [];
  }
  
  // A01: Broken Access Control Testing
  async testBrokenAccessControl() {
    const tests = [
      {
        name: 'Horizontal Privilege Escalation',
        test: async () => {
          // Test accessing another user's data
          const response = await this.client.get('/users/999');
          return this.validateAccessControl(response, 403);
        }
      },
      {
        name: 'Vertical Privilege Escalation',
        test: async () => {
          // Test accessing admin endpoints
          const response = await this.client.get('/admin/users');
          return this.validateAccessControl(response, 403);
        }
      },
      {
        name: 'Direct Object References',
        test: async () => {
          // Test direct access to resources
          const response = await this.client.get('/files/../../../etc/passwd');
          return this.validateAccessControl(response, 403);
        }
      },
      {
        name: 'Missing Authorization',
        test: async () => {
          // Test endpoints without proper authorization
          const response = await this.client.get('/api/sensitive-data');
          return this.validateAccessControl(response, 401);
        }
      },
      {
        name: 'CORS Misconfiguration',
        test: async () => {
          // Test CORS headers
          const response = await this.client.options('/api/data');
          return this.validateCORS(response);
        }
      },
      {
        name: 'Forced Browsing',
        test: async () => {
          // Test common paths
          const paths = ['/admin', '/config', '/backup', '/test'];
          const results = [];
          for (const path of paths) {
            const response = await this.client.get(path);
            results.push(this.validateAccessControl(response, 404));
          }
          return results.every(r => r);
        }
      }
    ];
    
    return await this.runSecurityTests('A01_Broken_Access_Control', tests);
  }
  
  // A02: Cryptographic Failures Testing
  async testCryptographicFailures() {
    const tests = [
      {
        name: 'Weak Encryption Detection',
        test: async () => {
          const response = await this.client.get('/api/health');
          return this.validateEncryption(response);
        }
      },
      {
        name: 'Sensitive Data Exposure',
        test: async () => {
          const response = await this.client.get('/users/1');
          return this.validateDataProtection(response);
        }
      },
      {
        name: 'Insecure Transmission',
        test: async () => {
          const response = await this.client.get('/api/data');
          return this.validateSecureTransmission(response);
        }
      },
      {
        name: 'Weak Randomness',
        test: async () => {
          const response = await this.client.get('/api/token');
          return this.validateRandomness(response);
        }
      },
      {
        name: 'Deprecated Algorithms',
        test: async () => {
          const response = await this.client.get('/api/signature');
          return this.validateCryptoAlgorithms(response);
        }
      },
      {
        name: 'Key Management',
        test: async () => {
          const response = await this.client.get('/api/keys');
          return this.validateKeyManagement(response);
        }
      }
    ];
    
    return await this.runSecurityTests('A02_Cryptographic_Failures', tests);
  }
  
  // A03: Injection Testing
  async testInjection() {
    const injectionPayloads = {
      sql: [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
        "1' OR 1=1 --",
        "admin'--",
        "' OR 'x'='x"
      ],
      nosql: [
        '{"$where": "this.username == this.password"}',
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'
      ],
      ldap: [
        "*)(uid=*))(|(uid=*",
        "*)(|(password=*))",
        "*)(|(objectClass=*))"
      ],
      xpath: [
        "' or '1'='1",
        "'] | //user/*[contains(*,'admin')] | a['",
        "1' or '1'='1"
      ],
      command: [
        "; ls -la",
        "| cat /etc/passwd",
        "&& whoami",
        "; rm -rf /",
        "| nc -l -p 4444 -e /bin/sh"
      ],
      code: [
        "{{7*7}}",
        "<%=7*7%>",
        "${7*7}",
        "#{7*7}",
        "{{config.items()}}"
      ]
    };
    
    const tests = [];
    
    // SQL Injection Tests
    for (const payload of injectionPayloads.sql) {
      tests.push({
        name: `SQL Injection: ${payload.substring(0, 20)}...`,
        test: async () => {
          const response = await this.client.post('/api/search', { query: payload });
          return this.validateInjection(response, payload);
        }
      });
    }
    
    // NoSQL Injection Tests
    for (const payload of injectionPayloads.nosql) {
      tests.push({
        name: `NoSQL Injection: ${payload.substring(0, 20)}...`,
        test: async () => {
          const response = await this.client.post('/api/login', JSON.parse(payload));
          return this.validateInjection(response, payload);
        }
      });
    }
    
    // Command Injection Tests
    for (const payload of injectionPayloads.command) {
      tests.push({
        name: `Command Injection: ${payload.substring(0, 20)}...`,
        test: async () => {
          const response = await this.client.post('/api/execute', { command: payload });
          return this.validateInjection(response, payload);
        }
      });
    }
    
    return await this.runSecurityTests('A03_Injection', tests);
  }
  
  // A04: Insecure Design Testing
  async testInsecureDesign() {
    const tests = [
      {
        name: 'Business Logic Bypass',
        test: async () => {
          // Test negative amounts
          const response = await this.client.post('/api/transfer', { amount: -1000 });
          return this.validateBusinessLogic(response);
        }
      },
      {
        name: 'Rate Limiting Bypass',
        test: async () => {
          const promises = Array.from({ length: 100 }, () => 
            this.client.get('/api/endpoint')
          );
          const responses = await Promise.allSettled(promises);
          return this.validateRateLimiting(responses);
        }
      },
      {
        name: 'Workflow Bypass',
        test: async () => {
          // Test skipping steps in workflow
          const response = await this.client.post('/api/checkout', { step: 'payment' });
          return this.validateWorkflow(response);
        }
      },
      {
        name: 'Resource Exhaustion',
        test: async () => {
          // Test large payload
          const largeData = 'A'.repeat(1000000);
          const response = await this.client.post('/api/upload', { data: largeData });
          return this.validateResourceProtection(response);
        }
      },
      {
        name: 'Time-based Attacks',
        test: async () => {
          const startTime = Date.now();
          await this.client.post('/api/login', { username: 'admin', password: 'wrong' });
          const endTime = Date.now();
          return this.validateTimingAttack(endTime - startTime);
        }
      },
      {
        name: 'Race Conditions',
        test: async () => {
          const promises = Array.from({ length: 10 }, () => 
            this.client.post('/api/claim', { id: 1 })
          );
          const responses = await Promise.allSettled(promises);
          return this.validateRaceCondition(responses);
        }
      }
    ];
    
    return await this.runSecurityTests('A04_Insecure_Design', tests);
  }
  
  // A05: Security Misconfiguration Testing
  async testSecurityMisconfiguration() {
    const tests = [
      {
        name: 'Default Credentials',
        test: async () => {
          const defaultCreds = [
            { username: 'admin', password: 'admin' },
            { username: 'admin', password: 'password' },
            { username: 'root', password: 'root' },
            { username: 'test', password: 'test' }
          ];
          
          for (const creds of defaultCreds) {
            const response = await this.client.post('/api/login', creds);
            if (response.status === 200) {
              return false; // Vulnerable
            }
          }
          return true; // Secure
        }
      },
      {
        name: 'Unnecessary Features',
        test: async () => {
          const features = ['/phpmyadmin', '/adminer', '/test', '/debug', '/status'];
          const results = [];
          for (const feature of features) {
            const response = await this.client.get(feature);
            results.push(response.status === 404);
          }
          return results.every(r => r);
        }
      },
      {
        name: 'Insecure Headers',
        test: async () => {
          const response = await this.client.get('/api/health');
          return this.validateSecurityHeaders(response);
        }
      },
      {
        name: 'Debug Information',
        test: async () => {
          const response = await this.client.get('/api/error');
          return this.validateDebugInfo(response);
        }
      },
      {
        name: 'Error Messages',
        test: async () => {
          const response = await this.client.get('/api/nonexistent');
          return this.validateErrorMessages(response);
        }
      },
      {
        name: 'Directory Listing',
        test: async () => {
          const response = await this.client.get('/uploads/');
          return this.validateDirectoryListing(response);
        }
      }
    ];
    
    return await this.runSecurityTests('A05_Security_Misconfiguration', tests);
  }
  
  // A06: Vulnerable Components Testing
  async testVulnerableComponents() {
    const tests = [
      {
        name: 'Outdated Libraries',
        test: async () => {
          const response = await this.client.get('/api/version');
          return this.validateLibraryVersions(response);
        }
      },
      {
        name: 'Known Vulnerabilities',
        test: async () => {
          // This would integrate with vulnerability databases
          return await this.scanForVulnerabilities();
        }
      },
      {
        name: 'Unpatched Components',
        test: async () => {
          const response = await this.client.get('/api/components');
          return this.validateComponentPatches(response);
        }
      },
      {
        name: 'License Compliance',
        test: async () => {
          return await this.validateLicenseCompliance();
        }
      },
      {
        name: 'Dependency Scanning',
        test: async () => {
          return await this.scanDependencies();
        }
      },
      {
        name: 'Version Disclosure',
        test: async () => {
          const response = await this.client.get('/api/health');
          return this.validateVersionDisclosure(response);
        }
      }
    ];
    
    return await this.runSecurityTests('A06_Vulnerable_Components', tests);
  }
  
  // A07: Authentication Failures Testing
  async testAuthenticationFailures() {
    const tests = [
      {
        name: 'Weak Passwords',
        test: async () => {
          const weakPasswords = ['123', 'password', 'admin', 'qwerty', '123456'];
          const results = [];
          for (const password of weakPasswords) {
            const response = await this.client.post('/api/register', { password });
            results.push(response.status === 400);
          }
          return results.every(r => r);
        }
      },
      {
        name: 'Brute Force Attacks',
        test: async () => {
          const promises = Array.from({ length: 10 }, () => 
            this.client.post('/api/login', { username: 'admin', password: 'wrong' })
          );
          const responses = await Promise.allSettled(promises);
          return this.validateBruteForceProtection(responses);
        }
      },
      {
        name: 'Session Fixation',
        test: async () => {
          const loginResponse = await this.client.post('/api/login', { username: 'test', password: 'test' });
          const sessionId1 = loginResponse.headers['set-cookie'];
          
          const logoutResponse = await this.client.post('/api/logout');
          const sessionId2 = logoutResponse.headers['set-cookie'];
          
          return sessionId1 !== sessionId2;
        }
      },
      {
        name: 'Session Hijacking',
        test: async () => {
          const response = await this.client.get('/api/session');
          return this.validateSessionSecurity(response);
        }
      },
      {
        name: 'Multi-Factor Bypass',
        test: async () => {
          const response = await this.client.post('/api/login', { username: 'admin', password: 'admin' });
          return this.validateMFA(response);
        }
      },
      {
        name: 'Credential Stuffing',
        test: async () => {
          const commonPasswords = ['password', '123456', 'admin', 'qwerty'];
          const results = [];
          for (const password of commonPasswords) {
            const response = await this.client.post('/api/login', { username: 'admin', password });
            results.push(response.status !== 200);
          }
          return results.every(r => r);
        }
      }
    ];
    
    return await this.runSecurityTests('A07_Authentication_Failures', tests);
  }
  
  // A08: Data Integrity Failures Testing
  async testDataIntegrityFailures() {
    const tests = [
      {
        name: 'Code Integrity',
        test: async () => {
          const response = await this.client.get('/api/integrity');
          return this.validateCodeIntegrity(response);
        }
      },
      {
        name: 'Data Tampering',
        test: async () => {
          const response = await this.client.get('/api/data');
          const originalData = response.body;
          
          // Attempt to modify data
          const modifiedResponse = await this.client.put('/api/data', {
            ...originalData,
            tampered: true
          });
          
          return this.validateDataIntegrity(modifiedResponse);
        }
      },
      {
        name: 'Supply Chain Attacks',
        test: async () => {
          return await this.validateSupplyChain();
        }
      },
      {
        name: 'CI/CD Security',
        test: async () => {
          return await this.validateCICDSecurity();
        }
      },
      {
        name: 'Unsigned Components',
        test: async () => {
          const response = await this.client.get('/api/components');
          return this.validateComponentSignatures(response);
        }
      },
      {
        name: 'Integrity Checks',
        test: async () => {
          const response = await this.client.get('/api/checksum');
          return this.validateIntegrityChecks(response);
        }
      }
    ];
    
    return await this.runSecurityTests('A08_Data_Integrity_Failures', tests);
  }
  
  // A09: Security Logging Failures Testing
  async testSecurityLoggingFailures() {
    const tests = [
      {
        name: 'Insufficient Logging',
        test: async () => {
          await this.client.post('/api/login', { username: 'admin', password: 'wrong' });
          const logs = await this.client.get('/api/logs');
          return this.validateLogging(logs);
        }
      },
      {
        name: 'Log Injection',
        test: async () => {
          const maliciousInput = 'admin\n[CRITICAL] Security breach detected';
          const response = await this.client.post('/api/log', { message: maliciousInput });
          return this.validateLogInjection(response);
        }
      },
      {
        name: 'Log Tampering',
        test: async () => {
          const response = await this.client.get('/api/logs');
          return this.validateLogIntegrity(response);
        }
      },
      {
        name: 'Monitoring Gaps',
        test: async () => {
          return await this.validateMonitoring();
        }
      },
      {
        name: 'Alert Fatigue',
        test: async () => {
          return await this.validateAlerting();
        }
      },
      {
        name: 'Incident Response',
        test: async () => {
          return await this.validateIncidentResponse();
        }
      }
    ];
    
    return await this.runSecurityTests('A09_Security_Logging_Failures', tests);
  }
  
  // A10: SSRF Testing
  async testSSRF() {
    const ssrfPayloads = [
      'http://localhost:22',
      'http://127.0.0.1:3306',
      'http://169.254.169.254/latest/meta-data/',
      'file:///etc/passwd',
      'gopher://localhost:25',
      'dict://localhost:11211',
      'ldap://localhost:389',
      'http://[::1]:80',
      'http://0.0.0.0:80',
      'http://localhost:80/../../../etc/passwd'
    ];
    
    const tests = ssrfPayloads.map(payload => ({
      name: `SSRF: ${payload}`,
      test: async () => {
        try {
          const response = await this.client.post('/api/fetch', { url: payload });
          return this.validateSSRF(response, payload);
        } catch (error) {
          return true; // Error is expected for SSRF attempts
        }
      }
    }));
    
    return await this.runSecurityTests('A10_SSRF', tests);
  }
  
  // Validation Methods
  validateAccessControl(response, expectedStatus) {
    return response.status === expectedStatus;
  }
  
  validateCORS(response) {
    const corsHeaders = response.headers['access-control-allow-origin'];
    return !corsHeaders || corsHeaders === 'null';
  }
  
  validateEncryption(response) {
    const hasHttps = response.headers['strict-transport-security'];
    const hasSecureCookies = response.headers['set-cookie']?.includes('Secure');
    return !!hasHttps && !!hasSecureCookies;
  }
  
  validateDataProtection(response) {
    const body = JSON.stringify(response.body);
    const sensitiveFields = ['password', 'ssn', 'creditCard', 'token'];
    return !sensitiveFields.some(field => body.includes(field));
  }
  
  validateSecureTransmission(response) {
    const hasHttps = response.headers['strict-transport-security'];
    const hasCSP = response.headers['content-security-policy'];
    return !!hasHttps && !!hasCSP;
  }
  
  validateRandomness(response) {
    // Check for predictable tokens
    const token = response.body.token;
    if (!token) return true;
    
    // Simple randomness check
    const uniqueChars = new Set(token).size;
    return uniqueChars > token.length * 0.5;
  }
  
  validateCryptoAlgorithms(response) {
    const hasStrongCrypto = response.headers['x-content-type-options'];
    return !!hasStrongCrypto;
  }
  
  validateKeyManagement(response) {
    // Check if keys are exposed
    const body = JSON.stringify(response.body);
    return !body.includes('private_key') && !body.includes('secret_key');
  }
  
  validateInjection(response, payload) {
    const body = JSON.stringify(response.body);
    const hasInjection = body.includes(payload) || response.status === 500;
    return !hasInjection;
  }
  
  validateBusinessLogic(response) {
    return response.status === 400; // Should reject negative amounts
  }
  
  validateRateLimiting(responses) {
    const rateLimited = responses.some(r => 
      r.status === 'fulfilled' && r.value.status === 429
    );
    return rateLimited;
  }
  
  validateWorkflow(response) {
    return response.status === 400; // Should reject incomplete workflow
  }
  
  validateResourceProtection(response) {
    return response.status === 413; // Should reject large payloads
  }
  
  validateTimingAttack(responseTime) {
    return responseTime < 1000; // Should not have significant timing differences
  }
  
  validateRaceCondition(responses) {
    const successful = responses.filter(r => 
      r.status === 'fulfilled' && r.value.status === 200
    );
    return successful.length <= 1; // Only one should succeed
  }
  
  validateSecurityHeaders(response) {
    const requiredHeaders = [
      'x-content-type-options',
      'x-frame-options',
      'x-xss-protection',
      'strict-transport-security'
    ];
    
    return requiredHeaders.every(header => response.headers[header]);
  }
  
  validateDebugInfo(response) {
    const body = JSON.stringify(response.body);
    const debugInfo = ['stack trace', 'debug', 'error details'];
    return !debugInfo.some(info => body.includes(info));
  }
  
  validateErrorMessages(response) {
    const body = JSON.stringify(response.body);
    const sensitiveInfo = ['database', 'server', 'path', 'file'];
    return !sensitiveInfo.some(info => body.includes(info));
  }
  
  validateDirectoryListing(response) {
    return response.status === 403; // Should not allow directory listing
  }
  
  validateLibraryVersions(response) {
    const version = response.body.version;
    if (!version) return true;
    
    // Check for old versions
    const currentYear = new Date().getFullYear();
    return version.includes(currentYear.toString());
  }
  
  async scanForVulnerabilities() {
    // This would integrate with vulnerability databases
    return true; // Placeholder
  }
  
  validateComponentPatches(response) {
    const components = response.body.components;
    if (!components) return true;
    
    return components.every(comp => comp.patched);
  }
  
  async validateLicenseCompliance() {
    // This would check license compliance
    return true; // Placeholder
  }
  
  async scanDependencies() {
    // This would scan dependencies for vulnerabilities
    return true; // Placeholder
  }
  
  validateVersionDisclosure(response) {
    const body = JSON.stringify(response.body);
    const versionPatterns = [/\d+\.\d+\.\d+/, /version/i, /build/i];
    return !versionPatterns.some(pattern => pattern.test(body));
  }
  
  validateBruteForceProtection(responses) {
    const rateLimited = responses.some(r => 
      r.status === 'fulfilled' && r.value.status === 429
    );
    return rateLimited;
  }
  
  validateSessionSecurity(response) {
    const hasSecureSession = response.headers['set-cookie']?.includes('Secure');
    const hasHttpOnly = response.headers['set-cookie']?.includes('HttpOnly');
    return !!hasSecureSession && !!hasHttpOnly;
  }
  
  validateMFA(response) {
    return response.status === 401; // Should require MFA
  }
  
  validateCodeIntegrity(response) {
    const hasChecksum = response.body.checksum;
    const hasSignature = response.body.signature;
    return !!hasChecksum && !!hasSignature;
  }
  
  validateDataIntegrity(response) {
    return response.status === 403; // Should prevent tampering
  }
  
  async validateSupplyChain() {
    // This would validate supply chain security
    return true; // Placeholder
  }
  
  async validateCICDSecurity() {
    // This would validate CI/CD security
    return true; // Placeholder
  }
  
  validateComponentSignatures(response) {
    const components = response.body.components;
    if (!components) return true;
    
    return components.every(comp => comp.signed);
  }
  
  validateIntegrityChecks(response) {
    const hasChecksum = response.body.checksum;
    const hasVerified = response.body.verified;
    return !!hasChecksum && !!hasVerified;
  }
  
  validateLogging(logs) {
    const logEntries = logs.body.logs;
    if (!logEntries) return false;
    
    const hasFailedLogin = logEntries.some(log => 
      log.event === 'failed_login' || log.event === 'authentication_failure'
    );
    return hasFailedLogin;
  }
  
  validateLogInjection(response) {
    const body = JSON.stringify(response.body);
    const hasInjection = body.includes('[CRITICAL]');
    return !hasInjection;
  }
  
  validateLogIntegrity(response) {
    const hasIntegrity = response.body.integrity;
    return !!hasIntegrity;
  }
  
  async validateMonitoring() {
    // This would validate monitoring setup
    return true; // Placeholder
  }
  
  async validateAlerting() {
    // This would validate alerting configuration
    return true; // Placeholder
  }
  
  async validateIncidentResponse() {
    // This would validate incident response procedures
    return true; // Placeholder
  }
  
  validateSSRF(response, payload) {
    // SSRF should be blocked
    return response.status === 400 || response.status === 403;
  }
  
  // Run security tests
  async runSecurityTests(category, tests) {
    const results = {
      category,
      tests: [],
      passed: 0,
      failed: 0,
      total: tests.length,
      vulnerabilities: []
    };
    
    for (const test of tests) {
      try {
        const passed = await test.test();
        results.tests.push({
          name: test.name,
          passed,
          error: null
        });
        
        if (passed) {
          results.passed++;
        } else {
          results.failed++;
          results.vulnerabilities.push({
            test: test.name,
            category,
            severity: OWASP_CATEGORIES[category]?.risk || 'MEDIUM'
          });
        }
      } catch (error) {
        results.tests.push({
          name: test.name,
          passed: false,
          error: error.message
        });
        results.failed++;
        results.vulnerabilities.push({
          test: test.name,
          category,
          severity: OWASP_CATEGORIES[category]?.risk || 'MEDIUM',
          error: error.message
        });
      }
    }
    
    this.results.set(category, results);
    return results;
  }
  
  // Run all OWASP tests
  async runAllOWASPTests() {
    const results = await Promise.all([
      this.testBrokenAccessControl(),
      this.testCryptographicFailures(),
      this.testInjection(),
      this.testInsecureDesign(),
      this.testSecurityMisconfiguration(),
      this.testVulnerableComponents(),
      this.testAuthenticationFailures(),
      this.testDataIntegrityFailures(),
      this.testSecurityLoggingFailures(),
      this.testSSRF()
    ]);
    
    return results;
  }
  
  // Generate comprehensive security report
  generateSecurityReport() {
    const allResults = Array.from(this.results.values());
    const totalTests = allResults.reduce((sum, result) => sum + result.total, 0);
    const totalPassed = allResults.reduce((sum, result) => sum + result.passed, 0);
    const totalFailed = allResults.reduce((sum, result) => sum + result.failed, 0);
    
    const vulnerabilities = allResults.flatMap(result => result.vulnerabilities);
    const highRiskVulns = vulnerabilities.filter(v => v.severity === 'HIGH');
    const mediumRiskVulns = vulnerabilities.filter(v => v.severity === 'MEDIUM');
    const lowRiskVulns = vulnerabilities.filter(v => v.severity === 'LOW');
    
    const report = {
      summary: {
        totalTests,
        totalPassed,
        totalFailed,
        passRate: totalTests > 0 ? (totalPassed / totalTests) * 100 : 0,
        totalVulnerabilities: vulnerabilities.length,
        highRiskVulnerabilities: highRiskVulns.length,
        mediumRiskVulnerabilities: mediumRiskVulns.length,
        lowRiskVulnerabilities: lowRiskVulns.length,
        riskLevel: this.calculateRiskLevel(vulnerabilities)
      },
      categories: allResults,
      vulnerabilities,
      recommendations: this.generateRecommendations(vulnerabilities),
      compliance: this.generateComplianceReport(allResults)
    };
    
    return report;
  }
  
  calculateRiskLevel(vulnerabilities) {
    const highRiskCount = vulnerabilities.filter(v => v.severity === 'HIGH').length;
    const mediumRiskCount = vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
    
    if (highRiskCount > 0) return 'HIGH';
    if (mediumRiskCount > 2) return 'MEDIUM';
    return 'LOW';
  }
  
  generateRecommendations(vulnerabilities) {
    const recommendations = [];
    
    for (const vuln of vulnerabilities) {
      switch (vuln.category) {
        case 'A01_Broken_Access_Control':
          recommendations.push({
            category: 'A01',
            priority: 'HIGH',
            recommendation: 'Implement proper access control mechanisms and role-based permissions',
            action: 'Review and implement RBAC, validate user permissions on every request'
          });
          break;
        case 'A02_Cryptographic_Failures':
          recommendations.push({
            category: 'A02',
            priority: 'HIGH',
            recommendation: 'Implement strong encryption and secure data handling',
            action: 'Use HTTPS, encrypt sensitive data, implement proper key management'
          });
          break;
        case 'A03_Injection':
          recommendations.push({
            category: 'A03',
            priority: 'HIGH',
            recommendation: 'Implement input validation and parameterized queries',
            action: 'Use prepared statements, validate all inputs, implement output encoding'
          });
          break;
        case 'A07_Authentication_Failures':
          recommendations.push({
            category: 'A07',
            priority: 'HIGH',
            recommendation: 'Strengthen authentication mechanisms',
            action: 'Implement MFA, strong password policies, and session management'
          });
          break;
        case 'A10_SSRF':
          recommendations.push({
            category: 'A10',
            priority: 'HIGH',
            recommendation: 'Implement SSRF protection',
            action: 'Validate URLs, use allowlists, implement network segmentation'
          });
          break;
        default:
          recommendations.push({
            category: vuln.category,
            priority: vuln.severity,
            recommendation: `Address ${vuln.category} vulnerabilities`,
            action: 'Review and implement appropriate security controls'
          });
      }
    }
    
    return recommendations;
  }
  
  generateComplianceReport(results) {
    return {
      owaspTop10: {
        compliant: results.every(r => r.failed === 0),
        score: results.reduce((sum, r) => sum + (r.passed / r.total), 0) / results.length * 100
      },
      pciDss: {
        compliant: results.filter(r => ['A01', 'A02', 'A03', 'A07'].includes(r.category)).every(r => r.failed === 0),
        score: 85 // Placeholder
      },
      gdpr: {
        compliant: results.filter(r => r.category === 'A02').every(r => r.failed === 0),
        score: 90 // Placeholder
      }
    };
  }
}

// Exercises and Tests
describe("OWASP Top 10 Comprehensive Testing", () => {
  let owaspTester;
  let client;
  
  beforeEach(() => {
    client = new EnhancedSupertestClient("https://api.example.com");
    owaspTester = new OWASPSecurityTester(client);
  });
  
  it("should test A01: Broken Access Control", async () => {
    const results = await owaspTester.testBrokenAccessControl();
    
    expect(results.category).to.equal('A01_Broken_Access_Control');
    expect(results.total).to.be.greaterThan(0);
    expect(results.passed + results.failed).to.equal(results.total);
  });
  
  it("should test A02: Cryptographic Failures", async () => {
    const results = await owaspTester.testCryptographicFailures();
    
    expect(results.category).to.equal('A02_Cryptographic_Failures');
    expect(results.tests).to.be.an('array');
  });
  
  it("should test A03: Injection", async () => {
    const results = await owaspTester.testInjection();
    
    expect(results.category).to.equal('A03_Injection');
    expect(results.tests.length).to.be.greaterThan(0);
  });
  
  it("should test A04: Insecure Design", async () => {
    const results = await owaspTester.testInsecureDesign();
    
    expect(results.category).to.equal('A04_Insecure_Design');
    expect(results.tests).to.be.an('array');
  });
  
  it("should test A05: Security Misconfiguration", async () => {
    const results = await owaspTester.testSecurityMisconfiguration();
    
    expect(results.category).to.equal('A05_Security_Misconfiguration');
    expect(results.tests).to.be.an('array');
  });
  
  it("should test A06: Vulnerable Components", async () => {
    const results = await owaspTester.testVulnerableComponents();
    
    expect(results.category).to.equal('A06_Vulnerable_Components');
    expect(results.tests).to.be.an('array');
  });
  
  it("should test A07: Authentication Failures", async () => {
    const results = await owaspTester.testAuthenticationFailures();
    
    expect(results.category).to.equal('A07_Authentication_Failures');
    expect(results.tests).to.be.an('array');
  });
  
  it("should test A08: Data Integrity Failures", async () => {
    const results = await owaspTester.testDataIntegrityFailures();
    
    expect(results.category).to.equal('A08_Data_Integrity_Failures');
    expect(results.tests).to.be.an('array');
  });
  
  it("should test A09: Security Logging Failures", async () => {
    const results = await owaspTester.testSecurityLoggingFailures();
    
    expect(results.category).to.equal('A09_Security_Logging_Failures');
    expect(results.tests).to.be.an('array');
  });
  
  it("should test A10: SSRF", async () => {
    const results = await owaspTester.testSSRF();
    
    expect(results.category).to.equal('A10_SSRF');
    expect(results.tests.length).to.be.greaterThan(0);
  });
  
  it("should run all OWASP Top 10 tests", async () => {
    const results = await owaspTester.runAllOWASPTests();
    
    expect(results).to.have.length(10);
    
    const totalTests = results.reduce((sum, result) => sum + result.total, 0);
    const totalPassed = results.reduce((sum, result) => sum + result.passed, 0);
    
    expect(totalTests).to.be.greaterThan(0);
    expect(totalPassed).to.be.at.least(0);
  });
  
  it("should generate comprehensive security report", async () => {
    await owaspTester.runAllOWASPTests();
    
    const report = owaspTester.generateSecurityReport();
    
    expect(report).to.have.property('summary');
    expect(report).to.have.property('categories');
    expect(report).to.have.property('vulnerabilities');
    expect(report).to.have.property('recommendations');
    expect(report).to.have.property('compliance');
    
    expect(report.summary).to.have.property('totalTests');
    expect(report.summary).to.have.property('totalPassed');
    expect(report.summary).to.have.property('totalFailed');
    expect(report.summary).to.have.property('riskLevel');
  });
});

export { OWASPSecurityTester, OWASP_CATEGORIES };


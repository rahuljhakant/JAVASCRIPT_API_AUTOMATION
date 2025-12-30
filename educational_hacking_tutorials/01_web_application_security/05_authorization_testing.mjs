/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 1: Web Application Security
 * Lesson 5: Authorization Testing
 * 
 * ⚠️ IMPORTANT: Educational Purpose Only
 * 
 * Learning Objectives:
 * - Understand authorization vulnerabilities
 * - Test for privilege escalation
 * - Identify IDOR vulnerabilities
 * - Learn defensive authorization practices
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== AUTHORIZATION TESTING ===");
console.log("⚠️  FOR EDUCATIONAL AND SECURITY TESTING PURPOSES ONLY");

// Authorization Tester
class AuthorizationTester {
  constructor(apiClient, userToken, adminToken) {
    this.apiClient = apiClient;
    this.userToken = userToken;
    this.adminToken = adminToken;
    this.testResults = [];
  }

  async testHorizontalPrivilegeEscalation(endpoint, userId1, userId2) {
    console.log(`\n🔍 Testing Horizontal Privilege Escalation: ${endpoint}`);
    
    try {
      // User 1 tries to access User 2's resources
      const response = await this.apiClient
        .get(`${endpoint}/${userId2}`)
        .set("Authorization", `Bearer ${this.userToken}`)
        .timeout(5000);
      
      if (response.status === 200 && response.body.data) {
        this.testResults.push({
          type: "Horizontal Privilege Escalation",
          severity: "high",
          description: `User ${userId1} can access User ${userId2}'s resources`,
          vulnerable: true,
          endpoint: `${endpoint}/${userId2}`
        });
        return { vulnerable: true };
      } else if (response.status === 403) {
        console.log("✅ Access properly denied");
        return { vulnerable: false };
      }
    } catch (error) {
      // Expected if authorization is properly implemented
    }
    
    return { vulnerable: false };
  }

  async testVerticalPrivilegeEscalation(adminEndpoints) {
    console.log(`\n🔍 Testing Vertical Privilege Escalation`);
    
    const vulnerableEndpoints = [];
    
    for (const endpoint of adminEndpoints) {
      try {
        const response = await this.apiClient
          .get(endpoint)
          .set("Authorization", `Bearer ${this.userToken}`)
          .timeout(5000);
        
        if (response.status === 200) {
          vulnerableEndpoints.push({
            endpoint,
            method: "GET",
            vulnerable: true
          });
        }
      } catch (error) {
        // Continue testing
      }
      
      // Test POST requests
      try {
        const response = await this.apiClient
          .post(endpoint)
          .set("Authorization", `Bearer ${this.userToken}`)
          .send({ test: "data" })
          .timeout(5000);
        
        if (response.status === 200 || response.status === 201) {
          vulnerableEndpoints.push({
            endpoint,
            method: "POST",
            vulnerable: true
          });
        }
      } catch (error) {
        // Continue testing
      }
    }
    
    if (vulnerableEndpoints.length > 0) {
      this.testResults.push({
        type: "Vertical Privilege Escalation",
        severity: "critical",
        description: `Regular user can access ${vulnerableEndpoints.length} admin endpoint(s)`,
        vulnerable: true,
        endpoints: vulnerableEndpoints
      });
    }
    
    return vulnerableEndpoints;
  }

  async testIDOR(endpoint, resourceId) {
    console.log(`\n🔍 Testing IDOR (Insecure Direct Object Reference): ${endpoint}`);
    
    try {
      // Try to access resource by manipulating ID
      const testIds = [
        resourceId + 1,
        resourceId - 1,
        1,
        999,
        "admin",
        "../",
        "../../"
      ];
      
      const vulnerable = [];
      
      for (const testId of testIds) {
        try {
          const response = await this.apiClient
            .get(`${endpoint}/${testId}`)
            .set("Authorization", `Bearer ${this.userToken}`)
            .timeout(5000);
          
          if (response.status === 200 && response.body.data) {
            vulnerable.push({
              id: testId,
              accessible: true
            });
          }
        } catch (error) {
          // Continue testing
        }
      }
      
      if (vulnerable.length > 0) {
        this.testResults.push({
          type: "IDOR",
          severity: "high",
          description: `Can access ${vulnerable.length} unauthorized resource(s) by ID manipulation`,
          vulnerable: true,
          examples: vulnerable
        });
        return { vulnerable: true, examples: vulnerable };
      }
    } catch (error) {
      // Continue testing
    }
    
    return { vulnerable: false };
  }

  async testPathTraversal(endpoint) {
    console.log(`\n🔍 Testing Path Traversal: ${endpoint}`);
    
    const traversalPayloads = [
      "../../../etc/passwd",
      "..\\..\\..\\windows\\system32\\config\\sam",
      "....//....//etc/passwd",
      "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      "..%2f..%2f..%2fetc%2fpasswd"
    ];
    
    const vulnerable = [];
    
    for (const payload of traversalPayloads) {
      try {
        const response = await this.apiClient
          .get(`${endpoint}?file=${encodeURIComponent(payload)}`)
          .set("Authorization", `Bearer ${this.userToken}`)
          .timeout(5000);
        
        const body = JSON.stringify(response.body).toLowerCase();
        
        // Check for path traversal indicators
        if (body.includes("root:") || 
            body.includes("bin/bash") || 
            body.includes("daemon:") ||
            body.includes("[boot loader]")) {
          vulnerable.push({
            payload,
            accessible: true
          });
        }
      } catch (error) {
        // Continue testing
      }
    }
    
    if (vulnerable.length > 0) {
      this.testResults.push({
        type: "Path Traversal",
        severity: "critical",
        description: `Path traversal vulnerability detected with ${vulnerable.length} payload(s)`,
        vulnerable: true,
        examples: vulnerable
      });
    }
    
    return vulnerable;
  }

  async testFunctionLevelAccessControl(endpoint, functions) {
    console.log(`\n🔍 Testing Function-Level Access Control: ${endpoint}`);
    
    const vulnerable = [];
    
    for (const func of functions) {
      try {
        const response = await this.apiClient
          .post(`${endpoint}/${func}`)
          .set("Authorization", `Bearer ${this.userToken}`)
          .send({ test: "data" })
          .timeout(5000);
        
        if (response.status === 200 || response.status === 201) {
          vulnerable.push({
            function: func,
            accessible: true
          });
        }
      } catch (error) {
        // Continue testing
      }
    }
    
    if (vulnerable.length > 0) {
      this.testResults.push({
        type: "Function-Level Access Control",
        severity: "high",
        description: `User can access ${vulnerable.length} restricted function(s)`,
        vulnerable: true,
        functions: vulnerable
      });
    }
    
    return vulnerable;
  }

  async testAPIEndpointAuthorization(endpoints) {
    console.log(`\n🔍 Testing API Endpoint Authorization`);
    
    const results = [];
    
    for (const endpoint of endpoints) {
      try {
        // Test without authentication
        const noAuthResponse = await this.apiClient[endpoint.method.toLowerCase()](endpoint.path)
          .timeout(5000);
        
        if (noAuthResponse.status === 200) {
          results.push({
            endpoint: endpoint.path,
            method: endpoint.method,
            issue: "Accessible without authentication",
            severity: "critical"
          });
        }
        
        // Test with user token (should be restricted for admin endpoints)
        if (endpoint.requiresAdmin) {
          const userResponse = await this.apiClient[endpoint.method.toLowerCase()](endpoint.path)
            .set("Authorization", `Bearer ${this.userToken}`)
            .timeout(5000);
          
          if (userResponse.status === 200) {
            results.push({
              endpoint: endpoint.path,
              method: endpoint.method,
              issue: "Admin endpoint accessible with user token",
              severity: "critical"
            });
          }
        }
      } catch (error) {
        // Continue testing
      }
    }
    
    if (results.length > 0) {
      this.testResults.push({
        type: "API Endpoint Authorization",
        severity: "critical",
        description: `${results.length} endpoint(s) have authorization issues`,
        vulnerable: true,
        endpoints: results
      });
    }
    
    return results;
  }

  generateAuthorizationReport() {
    console.log("\n📊 Authorization Test Report:");
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

// Secure Authorization Implementation
class SecureAuthorization {
  static checkResourceOwnership(userId, resourceUserId) {
    return userId === resourceUserId;
  }

  static checkRole(userRoles, requiredRoles) {
    return requiredRoles.some(role => userRoles.includes(role));
  }

  static checkPermission(userPermissions, requiredPermission) {
    return userPermissions.includes(requiredPermission);
  }

  static validateResourceAccess(user, resource, action) {
    // Check ownership
    if (resource.ownerId && resource.ownerId !== user.id) {
      return { allowed: false, reason: "Resource ownership mismatch" };
    }
    
    // Check role
    if (resource.requiredRole && !this.checkRole(user.roles, [resource.requiredRole])) {
      return { allowed: false, reason: "Insufficient role" };
    }
    
    // Check permission
    if (resource.requiredPermission && !this.checkPermission(user.permissions, resource.requiredPermission)) {
      return { allowed: false, reason: "Missing permission" };
    }
    
    return { allowed: true };
  }
}

// Test Scenarios
async function testHorizontalEscalation() {
  console.log("\n📝 Test 1: Horizontal Privilege Escalation");
  
  const tester = new AuthorizationTester(
    supertest("https://example.com"),
    "user-token",
    "admin-token"
  );
  
  const result = await tester.testHorizontalPrivilegeEscalation(
    "/api/users",
    1,
    2
  );
  
  expect(result).to.have.property("vulnerable");
  console.log("✅ Horizontal escalation test completed");
}

async function testVerticalEscalation() {
  console.log("\n📝 Test 2: Vertical Privilege Escalation");
  
  const tester = new AuthorizationTester(
    supertest("https://example.com"),
    "user-token",
    "admin-token"
  );
  
  const adminEndpoints = [
    "/api/admin/users",
    "/api/admin/settings",
    "/api/admin/logs"
  ];
  
  const results = await tester.testVerticalPrivilegeEscalation(adminEndpoints);
  expect(results).to.be.an("array");
  console.log(`✅ Tested ${adminEndpoints.length} admin endpoints`);
}

async function testIDOR() {
  console.log("\n📝 Test 3: IDOR Testing");
  
  const tester = new AuthorizationTester(
    supertest("https://example.com"),
    "user-token",
    "admin-token"
  );
  
  const result = await tester.testIDOR("/api/users", 1);
  expect(result).to.have.property("vulnerable");
  console.log("✅ IDOR test completed");
}

async function testPathTraversal() {
  console.log("\n📝 Test 4: Path Traversal Testing");
  
  const tester = new AuthorizationTester(
    supertest("https://example.com"),
    "user-token",
    "admin-token"
  );
  
  const results = await tester.testPathTraversal("/api/files");
  expect(results).to.be.an("array");
  console.log(`✅ Tested ${results.length} path traversal payloads`);
}

async function testSecureAuthorization() {
  console.log("\n📝 Test 5: Secure Authorization Implementation");
  
  // Test resource ownership
  expect(SecureAuthorization.checkResourceOwnership(1, 1)).to.be.true;
  expect(SecureAuthorization.checkResourceOwnership(1, 2)).to.be.false;
  
  // Test role checking
  expect(SecureAuthorization.checkRole(["user", "admin"], ["admin"])).to.be.true;
  expect(SecureAuthorization.checkRole(["user"], ["admin"])).to.be.false;
  
  // Test permission checking
  expect(SecureAuthorization.checkPermission(["read", "write"], "read")).to.be.true;
  expect(SecureAuthorization.checkPermission(["read"], "write")).to.be.false;
  
  console.log("✅ Secure authorization implementation test passed");
}

// Run all tests
(async () => {
  try {
    console.log("\n⚠️  REMINDER: This tutorial is for educational purposes only.");
    console.log("   Only test systems you own or have explicit permission to test.\n");
    
    await testHorizontalEscalation();
    await testVerticalEscalation();
    await testIDOR();
    await testPathTraversal();
    await testSecureAuthorization();
    
    console.log("\n✅ All authorization tests completed!");
    console.log("\n📚 Key Takeaways:");
    console.log("   - Always verify resource ownership");
    console.log("   - Implement role-based access control (RBAC)");
    console.log("   - Use permission-based access control");
    console.log("   - Validate all user inputs, especially IDs");
    console.log("   - Implement proper path validation");
    console.log("   - Test authorization at every endpoint");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
})();


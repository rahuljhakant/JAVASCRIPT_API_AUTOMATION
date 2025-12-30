/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 4: Advanced Techniques
 * Lesson 2: Privilege Escalation
 * 
 * ⚠️ IMPORTANT: Educational Purpose Only
 * 
 * Learning Objectives:
 * - Understand privilege escalation vectors
 * - Learn to identify escalation opportunities
 * - Implement safe privilege escalation testing
 * - Practice ethical privilege escalation assessment
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== PRIVILEGE ESCALATION TECHNIQUES ===");

// Privilege Escalation Tester
class PrivilegeEscalationTester {
  constructor() {
    this.escalationVectors = [];
    this.testResults = [];
  }

  async testHorizontalEscalation(url, userToken1, userToken2) {
    console.log("\n🔍 Testing Horizontal Privilege Escalation");
    
    // Test if user1 can access user2's resources
    try {
      // First, get user1's own resources
      const ownResources = await supertest(url)
        .get("/api/users/me")
        .set("Authorization", `Bearer ${userToken1}`)
        .timeout(5000);
      
      const ownUserId = ownResources.body.data?.id;
      
      // Try to access user2's resources with user1's token
      const otherResources = await supertest(url)
        .get(`/api/users/${ownUserId + 1}`)
        .set("Authorization", `Bearer ${userToken1}`)
        .timeout(5000);
      
      if (otherResources.status === 200 && otherResources.body.data) {
        this.escalationVectors.push({
          type: "Horizontal Privilege Escalation",
          severity: "high",
          description: "User can access other users' resources",
          vulnerable: true
        });
        return true;
      }
    } catch (error) {
      // Expected behavior - access should be denied
    }
    
    return false;
  }

  async testVerticalEscalation(url, userToken) {
    console.log("\n🔍 Testing Vertical Privilege Escalation");
    
    // Test if regular user can access admin endpoints
    const adminEndpoints = [
      "/api/admin/users",
      "/api/admin/settings",
      "/api/admin/logs",
      "/api/admin/config"
    ];
    
    const results = [];
    
    for (const endpoint of adminEndpoints) {
      try {
        const response = await supertest(url)
          .get(endpoint)
          .set("Authorization", `Bearer ${userToken}`)
          .timeout(5000);
        
        if (response.status === 200) {
          results.push({
            endpoint: endpoint,
            vulnerable: true,
            severity: "critical",
            description: "Regular user can access admin endpoint"
          });
        } else if (response.status === 403) {
          results.push({
            endpoint: endpoint,
            vulnerable: false,
            description: "Access properly denied"
          });
        }
      } catch (error) {
        results.push({
          endpoint: endpoint,
          vulnerable: false,
          error: error.message
        });
      }
    }
    
    const vulnerable = results.filter(r => r.vulnerable === true);
    if (vulnerable.length > 0) {
      this.escalationVectors.push({
        type: "Vertical Privilege Escalation",
        severity: "critical",
        description: `User can access ${vulnerable.length} admin endpoint(s)`,
        vulnerable: true,
        endpoints: vulnerable.map(v => v.endpoint)
      });
    }
    
    return results;
  }

  async testIDOR(url, userToken) {
    console.log("\n🔍 Testing IDOR (Insecure Direct Object Reference)");
    
    // Test if user can access resources by manipulating IDs
    try {
      // Get user's own resource
      const ownResource = await supertest(url)
        .get("/api/users/me")
        .set("Authorization", `Bearer ${userToken}`)
        .timeout(5000);
      
      const ownId = ownResource.body.data?.id;
      
      // Try to access other resources by incrementing ID
      const otherResource = await supertest(url)
        .get(`/api/users/${ownId + 1}`)
        .set("Authorization", `Bearer ${userToken}`)
        .timeout(5000);
      
      if (otherResource.status === 200) {
        this.escalationVectors.push({
          type: "IDOR",
          severity: "high",
          description: "User can access other users' resources by manipulating IDs",
          vulnerable: true
        });
        return true;
      }
    } catch (error) {
      // Expected - access should be denied
    }
    
    return false;
  }

  async testParameterPollution(url, endpoint) {
    console.log(`\n🔍 Testing Parameter Pollution on: ${endpoint}`);
    
    // Test HTTP Parameter Pollution
    try {
      // Try to override parameters
      const response = await supertest(url)
        .get(`${endpoint}?role=user&role=admin`)
        .timeout(5000);
      
      const body = JSON.stringify(response.body);
      
      // Check if admin role was applied
      if (body.includes("admin") || body.includes("role") && body.includes("admin")) {
        this.escalationVectors.push({
          type: "Parameter Pollution",
          severity: "medium",
          description: "Parameter pollution may allow privilege escalation",
          vulnerable: true
        });
        return true;
      }
    } catch (error) {
      // Continue testing
    }
    
    return false;
  }

  generateEscalationReport() {
    console.log("\n📊 Privilege Escalation Test Report:");
    console.log("=" .repeat(50));
    
    const vulnerable = this.escalationVectors.filter(v => v.vulnerable === true);
    const total = this.escalationVectors.length;
    
    console.log(`Total Vectors Tested: ${total}`);
    console.log(`Vulnerabilities Found: ${vulnerable.length}`);
    
    if (vulnerable.length > 0) {
      console.log("\nVulnerabilities:");
      vulnerable.forEach(vuln => {
        console.log(`  - ${vuln.type}: ${vuln.severity} severity`);
        if (vuln.description) {
          console.log(`    ${vuln.description}`);
        }
      });
    }
    
    console.log("=" .repeat(50));
    
    return {
      total: total,
      vulnerable: vulnerable.length,
      vectors: this.escalationVectors
    };
  }
}

// Test Scenarios
async function testHorizontalEscalation() {
  console.log("\n📝 Test 1: Horizontal Privilege Escalation");
  
  const tester = new PrivilegeEscalationTester();
  const result = await tester.testHorizontalEscalation(
    "https://example.com",
    "token1",
    "token2"
  );
  
  expect(typeof result).to.equal("boolean");
  console.log("✅ Horizontal escalation test completed");
}

async function testVerticalEscalation() {
  console.log("\n📝 Test 2: Vertical Privilege Escalation");
  
  const tester = new PrivilegeEscalationTester();
  const results = await tester.testVerticalEscalation(
    "https://example.com",
    "user-token"
  );
  
  expect(results).to.be.an("array");
  console.log(`✅ Vertical escalation test completed (${results.length} endpoints tested)`);
}

async function testIDOR() {
  console.log("\n📝 Test 3: IDOR Testing");
  
  const tester = new PrivilegeEscalationTester();
  const result = await tester.testIDOR(
    "https://example.com",
    "user-token"
  );
  
  expect(typeof result).to.equal("boolean");
  console.log("✅ IDOR test completed");
}

async function testEscalationReport() {
  console.log("\n📝 Test 4: Generate Escalation Report");
  
  const tester = new PrivilegeEscalationTester();
  await tester.testVerticalEscalation("https://example.com", "user-token");
  
  const report = tester.generateEscalationReport();
  expect(report).to.have.property("total");
  expect(report).to.have.property("vulnerable");
  
  console.log("✅ Escalation report generation test passed");
}

// Run all tests
(async () => {
  try {
    console.log("\n⚠️  REMINDER: This tutorial is for educational purposes only.");
    console.log("   Only test systems you own or have explicit permission to test.\n");
    
    await testHorizontalEscalation();
    await testVerticalEscalation();
    await testIDOR();
    await testEscalationReport();
    
    console.log("\n✅ All privilege escalation tests completed!");
    console.log("\n📚 Key Takeaways:");
    console.log("   - Privilege escalation is a critical security issue");
    console.log("   - Always implement proper access controls");
    console.log("   - Test authorization mechanisms thoroughly");
    console.log("   - Follow principle of least privilege");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
})();


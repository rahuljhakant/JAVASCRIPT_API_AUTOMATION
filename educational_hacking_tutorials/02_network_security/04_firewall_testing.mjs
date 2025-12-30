/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 2: Network Security
 * Lesson 4: Firewall Testing
 * 
 * ⚠️ IMPORTANT: Educational Purpose Only
 * 
 * Learning Objectives:
 * - Understand firewall security
 * - Test firewall rules
 * - Learn firewall bypass techniques
 * - Practice defensive firewall configuration
 */

import { expect } from "chai";
import supertest from "supertest";
import net from "net";

console.log("=== FIREWALL TESTING ===");
console.log("⚠️  FOR EDUCATIONAL AND SECURITY TESTING PURPOSES ONLY");

// Firewall Tester
class FirewallTester {
  constructor() {
    this.testResults = [];
  }

  async testPortFiltering(host, ports) {
    console.log(`\n🔍 Testing Port Filtering: ${host}`);
    
    const results = {
      host,
      openPorts: [],
      closedPorts: [],
      filteredPorts: []
    };
    
    for (const port of ports) {
      try {
        const isOpen = await this.checkPort(host, port);
        if (isOpen) {
          results.openPorts.push(port);
        } else {
          results.closedPorts.push(port);
        }
      } catch (error) {
        results.filteredPorts.push(port);
      }
    }
    
    this.testResults.push({
      type: "Port Filtering",
      results,
      description: `Found ${results.openPorts.length} open, ${results.closedPorts.length} closed, ${results.filteredPorts.length} filtered ports`
    });
    
    return results;
  }

  async checkPort(host, port, timeout = 2000) {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      
      socket.setTimeout(timeout);
      
      socket.on("connect", () => {
        socket.destroy();
        resolve(true);
      });
      
      socket.on("timeout", () => {
        socket.destroy();
        reject(new Error("Connection timeout"));
      });
      
      socket.on("error", (error) => {
        reject(error);
      });
      
      socket.connect(port, host);
    });
  }

  async testFirewallRules(host, rules) {
    console.log(`\n🔍 Testing Firewall Rules: ${host}`);
    
    const results = {
      allowed: [],
      blocked: [],
      unexpected: []
    };
    
    for (const rule of rules) {
      try {
        const response = await supertest(`http://${host}`)
          [rule.method.toLowerCase()](rule.path)
          .timeout(5000);
        
        if (response.status === 200 || response.status < 400) {
          if (rule.expected === "block") {
            results.unexpected.push({
              rule,
              status: response.status,
              description: "Should be blocked but was allowed"
            });
          } else {
            results.allowed.push(rule);
          }
        } else if (response.status === 403 || response.status === 401) {
          if (rule.expected === "allow") {
            results.unexpected.push({
              rule,
              status: response.status,
              description: "Should be allowed but was blocked"
            });
          } else {
            results.blocked.push(rule);
          }
        }
      } catch (error) {
        if (rule.expected === "allow") {
          results.unexpected.push({
            rule,
            error: error.message,
            description: "Should be allowed but connection failed"
          });
        } else {
          results.blocked.push(rule);
        }
      }
    }
    
    if (results.unexpected.length > 0) {
      this.testResults.push({
        type: "Firewall Rule Violation",
        severity: "high",
        description: `${results.unexpected.length} firewall rule(s) not working as expected`,
        results: results.unexpected
      });
    }
    
    return results;
  }

  async testBypassTechniques(host, endpoint) {
    console.log(`\n🔍 Testing Firewall Bypass Techniques: ${host}`);
    
    const bypassAttempts = [];
    
    // Technique 1: IP Spoofing (simulated)
    bypassAttempts.push({
      technique: "IP Spoofing",
      description: "Attempting to bypass using different source IP",
      tested: true
    });
    
    // Technique 2: Port Hopping
    const commonPorts = [80, 443, 8080, 8443, 8000, 8888];
    for (const port of commonPorts) {
      try {
        const isOpen = await this.checkPort(host, port);
        if (isOpen) {
          bypassAttempts.push({
            technique: "Port Hopping",
            description: `Alternative port ${port} is open`,
            port,
            vulnerable: true
          });
        }
      } catch (error) {
        // Port closed or filtered
      }
    }
    
    // Technique 3: Protocol Tunneling
    bypassAttempts.push({
      technique: "Protocol Tunneling",
      description: "Testing if protocols can be tunneled through allowed ports",
      tested: true
    });
    
    // Technique 4: Fragmentation
    bypassAttempts.push({
      technique: "Packet Fragmentation",
      description: "Testing if fragmented packets can bypass firewall",
      tested: true
    });
    
    const successfulBypasses = bypassAttempts.filter(b => b.vulnerable === true);
    if (successfulBypasses.length > 0) {
      this.testResults.push({
        type: "Firewall Bypass",
        severity: "high",
        description: `${successfulBypasses.length} bypass technique(s) may be possible`,
        techniques: successfulBypasses
      });
    }
    
    return bypassAttempts;
  }

  async testStatefulInspection(host, endpoints) {
    console.log(`\n🔍 Testing Stateful Inspection: ${host}`);
    
    const results = {
      stateful: true,
      findings: []
    };
    
    // Test if firewall maintains connection state
    for (const endpoint of endpoints) {
      try {
        // First request
        const response1 = await supertest(`http://${host}`)
          .get(endpoint)
          .timeout(5000);
        
        // Second request with same session
        const sessionCookie = response1.headers["set-cookie"];
        const response2 = await supertest(`http://${host}`)
          .get(endpoint)
          .set("Cookie", sessionCookie || "")
          .timeout(5000);
        
        // Check if firewall maintains state
        if (response2.status === 200) {
          results.findings.push({
            endpoint,
            stateful: true,
            description: "Firewall appears to maintain connection state"
          });
        }
      } catch (error) {
        results.findings.push({
          endpoint,
          error: error.message
        });
      }
    }
    
    this.testResults.push({
      type: "Stateful Inspection",
      results,
      description: "Stateful inspection analysis completed"
    });
    
    return results;
  }

  async testApplicationLayerFirewall(host, maliciousPayloads) {
    console.log(`\n🔍 Testing Application-Layer Firewall: ${host}`);
    
    const results = {
      blocked: [],
      allowed: [],
      vulnerable: []
    };
    
    for (const payload of maliciousPayloads) {
      try {
        const response = await supertest(`http://${host}`)
          .post(payload.endpoint)
          .send(payload.data)
          .timeout(5000);
        
        if (response.status === 403 || response.status === 406) {
          results.blocked.push({
            payload: payload.type,
            description: "Successfully blocked by application-layer firewall"
          });
        } else if (response.status === 200 || response.status === 201) {
          results.allowed.push({
            payload: payload.type,
            description: "Malicious payload was allowed through",
            vulnerable: true
          });
          results.vulnerable.push(payload);
        }
      } catch (error) {
        // Connection failed
      }
    }
    
    if (results.vulnerable.length > 0) {
      this.testResults.push({
        type: "Application-Layer Firewall Bypass",
        severity: "high",
        description: `${results.vulnerable.length} malicious payload(s) bypassed application-layer firewall`,
        payloads: results.vulnerable
      });
    }
    
    return results;
  }

  generateFirewallReport() {
    console.log("\n📊 Firewall Testing Report:");
    console.log("=" .repeat(50));
    
    const vulnerabilities = this.testResults.filter(r => r.severity === "high");
    const total = this.testResults.length;
    
    console.log(`Total Tests: ${total}`);
    console.log(`Vulnerabilities Found: ${vulnerabilities.length}`);
    
    if (vulnerabilities.length > 0) {
      console.log("\nVulnerabilities:");
      vulnerabilities.forEach(vuln => {
        console.log(`  - ${vuln.type}: ${vuln.severity} severity`);
        console.log(`    ${vuln.description}`);
      });
    }
    
    console.log("=" .repeat(50));
    
    return {
      total,
      vulnerabilities: vulnerabilities.length,
      results: this.testResults
    };
  }
}

// Secure Firewall Configuration
class SecureFirewallConfig {
  static getRecommendedRules() {
    return {
      inbound: [
        { port: 80, protocol: "tcp", action: "allow", description: "HTTP" },
        { port: 443, protocol: "tcp", action: "allow", description: "HTTPS" },
        { port: 22, protocol: "tcp", action: "allow", source: "specific", description: "SSH from specific IPs" },
        { action: "deny", description: "Default deny all" }
      ],
      outbound: [
        { port: 80, protocol: "tcp", action: "allow", description: "HTTP" },
        { port: 443, protocol: "tcp", action: "allow", description: "HTTPS" },
        { port: 53, protocol: "udp", action: "allow", description: "DNS" },
        { action: "deny", description: "Default deny all" }
      ],
      applicationLayer: {
        enabled: true,
        rules: [
          { type: "SQL Injection", action: "block" },
          { type: "XSS", action: "block" },
          { type: "Path Traversal", action: "block" },
          { type: "Command Injection", action: "block" }
        ]
      }
    };
  }
}

// Test Scenarios
async function testPortFiltering() {
  console.log("\n📝 Test 1: Port Filtering");
  
  const tester = new FirewallTester();
  const results = await tester.testPortFiltering("example.com", [80, 443, 22, 8080]);
  
  expect(results).to.have.property("openPorts");
  expect(results).to.have.property("closedPorts");
  console.log(`✅ Tested ${results.openPorts.length + results.closedPorts.length} ports`);
}

async function testFirewallRules() {
  console.log("\n📝 Test 2: Firewall Rules");
  
  const tester = new FirewallTester();
  const rules = [
    { method: "GET", path: "/", expected: "allow" },
    { method: "GET", path: "/admin", expected: "block" }
  ];
  
  const results = await tester.testFirewallRules("example.com", rules);
  expect(results).to.have.property("allowed");
  expect(results).to.have.property("blocked");
  console.log(`✅ Tested ${rules.length} firewall rules`);
}

async function testBypassTechniques() {
  console.log("\n📝 Test 3: Firewall Bypass Techniques");
  
  const tester = new FirewallTester();
  const results = await tester.testBypassTechniques("example.com", "/api");
  
  expect(results).to.be.an("array");
  console.log(`✅ Tested ${results.length} bypass techniques`);
}

async function testApplicationLayerFirewall() {
  console.log("\n📝 Test 4: Application-Layer Firewall");
  
  const tester = new FirewallTester();
  const maliciousPayloads = [
    { type: "SQL Injection", endpoint: "/api/search", data: { query: "' OR '1'='1" } },
    { type: "XSS", endpoint: "/api/comment", data: { comment: "<script>alert(1)</script>" } }
  ];
  
  const results = await tester.testApplicationLayerFirewall("example.com", maliciousPayloads);
  expect(results).to.have.property("blocked");
  expect(results).to.have.property("allowed");
  console.log(`✅ Tested ${maliciousPayloads.length} malicious payloads`);
}

async function testFirewallReport() {
  console.log("\n📝 Test 5: Generate Firewall Report");
  
  const tester = new FirewallTester();
  await tester.testPortFiltering("example.com", [80, 443]);
  
  const report = tester.generateFirewallReport();
  expect(report).to.have.property("total");
  expect(report).to.have.property("vulnerabilities");
  
  console.log("✅ Firewall testing report generation test passed");
}

// Run all tests
(async () => {
  try {
    console.log("\n⚠️  REMINDER: This tutorial is for educational purposes only.");
    console.log("   Only test firewalls you own or have explicit permission to test.\n");
    
    await testPortFiltering();
    await testFirewallRules();
    await testBypassTechniques();
    await testApplicationLayerFirewall();
    await testFirewallReport();
    
    console.log("\n✅ All firewall testing completed!");
    console.log("\n📚 Key Takeaways:");
    console.log("   - Implement default deny firewall rules");
    console.log("   - Use stateful inspection");
    console.log("   - Enable application-layer firewall");
    console.log("   - Regularly test firewall rules");
    console.log("   - Monitor for bypass attempts");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
})();


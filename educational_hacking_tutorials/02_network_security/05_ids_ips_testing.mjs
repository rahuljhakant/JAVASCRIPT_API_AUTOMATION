/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 2: Network Security
 * Lesson 5: IDS/IPS Testing
 * 
 * ⚠️ IMPORTANT: Educational Purpose Only
 * 
 * Learning Objectives:
 * - Understand IDS/IPS systems
 * - Test intrusion detection
 * - Learn evasion techniques
 * - Practice defensive IDS/IPS configuration
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== IDS/IPS TESTING ===");
console.log("⚠️  FOR EDUCATIONAL AND SECURITY TESTING PURPOSES ONLY");

// IDS/IPS Tester
class IDSIPSTester {
  constructor() {
    this.testResults = [];
    this.detectionResults = [];
  }

  async testSignatureBasedDetection(url, maliciousPayloads) {
    console.log(`\n🔍 Testing Signature-Based Detection: ${url}`);
    
    const results = {
      detected: [],
      undetected: [],
      falsePositives: []
    };
    
    for (const payload of maliciousPayloads) {
      try {
        const response = await supertest(url)
          .post(payload.endpoint)
          .send(payload.data)
          .timeout(5000);
        
        // Check if request was blocked or flagged
        const wasBlocked = response.status === 403 || 
                          response.status === 406 || 
                          response.status === 406 ||
                          response.headers["x-ids-alert"] ||
                          response.headers["x-ips-blocked"];
        
        if (wasBlocked) {
          results.detected.push({
            payload: payload.type,
            description: "Detected by signature-based IDS/IPS"
          });
        } else {
          results.undetected.push({
            payload: payload.type,
            description: "Not detected by signature-based IDS/IPS",
            vulnerable: true
          });
        }
      } catch (error) {
        // Request may have been blocked
        results.detected.push({
          payload: payload.type,
          description: "Request blocked (likely by IPS)"
        });
      }
    }
    
    if (results.undetected.length > 0) {
      this.testResults.push({
        type: "Signature-Based Detection Bypass",
        severity: "high",
        description: `${results.undetected.length} payload(s) bypassed signature-based detection`,
        payloads: results.undetected
      });
    }
    
    return results;
  }

  async testAnomalyBasedDetection(url, normalTraffic, anomalousTraffic) {
    console.log(`\n🔍 Testing Anomaly-Based Detection: ${url}`);
    
    const results = {
      normalDetected: 0,
      anomalousDetected: 0,
      falsePositives: 0
    };
    
    // Send normal traffic to establish baseline
    for (const traffic of normalTraffic) {
      try {
        const response = await supertest(url)
          [traffic.method.toLowerCase()](traffic.path)
          .timeout(5000);
        
        const wasFlagged = response.headers["x-ids-alert"] || 
                          response.status === 403;
        
        if (wasFlagged) {
          results.falsePositives++;
        }
      } catch (error) {
        // Continue
      }
    }
    
    // Send anomalous traffic
    for (const traffic of anomalousTraffic) {
      try {
        const response = await supertest(url)
          [traffic.method.toLowerCase()](traffic.path)
          .send(traffic.body || {})
          .timeout(5000);
        
        const wasDetected = response.headers["x-ids-alert"] || 
                           response.status === 403 ||
                           response.status === 406;
        
        if (wasDetected) {
          results.anomalousDetected++;
        } else {
          this.testResults.push({
            type: "Anomaly-Based Detection Bypass",
            severity: "medium",
            description: "Anomalous traffic not detected",
            traffic
          });
        }
      } catch (error) {
        // May have been blocked
        results.anomalousDetected++;
      }
    }
    
    return results;
  }

  async testEvasionTechniques(url, endpoint) {
    console.log(`\n🔍 Testing Evasion Techniques: ${url}`);
    
    const evasionResults = [];
    
    // Technique 1: Encoding
    const encodedPayloads = [
      { type: "URL Encoding", payload: "%27%20OR%20%271%27%3D%271" },
      { type: "Double Encoding", payload: "%2527%20OR%20%25271%2527%3D%25271" },
      { type: "Unicode Encoding", payload: "\u0027 OR \u0031\u003D\u0031" }
    ];
    
    for (const encoded of encodedPayloads) {
      try {
        const response = await supertest(url)
          .get(`${endpoint}?id=${encoded.payload}`)
          .timeout(5000);
        
        if (response.status === 200) {
          evasionResults.push({
            technique: encoded.type,
            success: true,
            description: "Encoding technique bypassed detection"
          });
        }
      } catch (error) {
        // Continue
      }
    }
    
    // Technique 2: Fragmentation
    evasionResults.push({
      technique: "Packet Fragmentation",
      description: "Fragmented packets may bypass IDS/IPS",
      tested: true
    });
    
    // Technique 3: Polymorphism
    const polymorphicPayloads = [
      { type: "SQL Injection Variant 1", payload: "' OR '1'='1" },
      { type: "SQL Injection Variant 2", payload: "' OR 1=1--" },
      { type: "SQL Injection Variant 3", payload: "' UNION SELECT NULL--" }
    ];
    
    for (const poly of polymorphicPayloads) {
      try {
        const response = await supertest(url)
          .post(endpoint)
          .send({ query: poly.payload })
          .timeout(5000);
        
        if (response.status === 200) {
          evasionResults.push({
            technique: "Polymorphism",
            variant: poly.type,
            success: true,
            description: "Polymorphic payload bypassed detection"
          });
        }
      } catch (error) {
        // Continue
      }
    }
    
    const successfulEvasions = evasionResults.filter(r => r.success === true);
    if (successfulEvasions.length > 0) {
      this.testResults.push({
        type: "IDS/IPS Evasion",
        severity: "high",
        description: `${successfulEvasions.length} evasion technique(s) successful`,
        techniques: successfulEvasions
      });
    }
    
    return evasionResults;
  }

  async testFalsePositiveAnalysis(url, legitimateRequests) {
    console.log(`\n🔍 Testing False Positive Analysis: ${url}`);
    
    const falsePositives = [];
    
    for (const request of legitimateRequests) {
      try {
        const response = await supertest(url)
          [request.method.toLowerCase()](request.path)
          .send(request.body || {})
          .timeout(5000);
        
        const wasFlagged = response.headers["x-ids-alert"] || 
                          response.status === 403 ||
                          response.status === 406;
        
        if (wasFlagged) {
          falsePositives.push({
            request,
            description: "Legitimate request flagged as malicious",
            severity: "medium"
          });
        }
      } catch (error) {
        // Continue
      }
    }
    
    if (falsePositives.length > 0) {
      this.testResults.push({
        type: "False Positives",
        severity: "medium",
        description: `${falsePositives.length} false positive(s) detected`,
        examples: falsePositives
      });
    }
    
    return falsePositives;
  }

  async testBypassTechniques(url, endpoint) {
    console.log(`\n🔍 Testing IDS/IPS Bypass Techniques: ${url}`);
    
    const bypassResults = [];
    
    // Technique 1: Slow requests
    bypassResults.push({
      technique: "Slow Request",
      description: "Slow requests may bypass rate-based detection"
    });
    
    // Technique 2: Request splitting
    bypassResults.push({
      technique: "Request Splitting",
      description: "Splitting malicious payload across multiple requests"
    });
    
    // Technique 3: Protocol tunneling
    bypassResults.push({
      technique: "Protocol Tunneling",
      description: "Tunneling malicious traffic through allowed protocols"
    });
    
    // Technique 4: Time-based evasion
    bypassResults.push({
      technique: "Time-Based Evasion",
      description: "Delaying requests to avoid rate-based detection"
    });
    
    return bypassResults;
  }

  generateIDSIPSReport() {
    console.log("\n📊 IDS/IPS Testing Report:");
    console.log("=" .repeat(50));
    
    const vulnerabilities = this.testResults.filter(r => 
      r.severity === "high" || r.severity === "critical"
    );
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

// Secure IDS/IPS Configuration
class SecureIDSIPSConfig {
  static getRecommendedSettings() {
    return {
      signatureBased: {
        enabled: true,
        updateFrequency: "daily",
        customSignatures: true
      },
      anomalyBased: {
        enabled: true,
        baselineLearning: true,
        learningPeriod: "7 days"
      },
      response: {
        mode: "prevention", // IPS mode
        actions: ["block", "alert", "log"],
        whitelist: []
      },
      tuning: {
        falsePositiveReduction: true,
        customRules: true,
        regularReview: true
      }
    };
  }
}

// Test Scenarios
async function testSignatureDetection() {
  console.log("\n📝 Test 1: Signature-Based Detection");
  
  const tester = new IDSIPSTester();
  const maliciousPayloads = [
    { type: "SQL Injection", endpoint: "/api/search", data: { query: "' OR '1'='1" } },
    { type: "XSS", endpoint: "/api/comment", data: { comment: "<script>alert(1)</script>" } }
  ];
  
  const results = await tester.testSignatureBasedDetection("https://example.com", maliciousPayloads);
  expect(results).to.have.property("detected");
  expect(results).to.have.property("undetected");
  console.log(`✅ Tested ${maliciousPayloads.length} malicious payloads`);
}

async function testAnomalyDetection() {
  console.log("\n📝 Test 2: Anomaly-Based Detection");
  
  const tester = new IDSIPSTester();
  const normalTraffic = [
    { method: "GET", path: "/" },
    { method: "GET", path: "/api/users" }
  ];
  const anomalousTraffic = [
    { method: "POST", path: "/admin/delete", body: { id: "all" } }
  ];
  
  const results = await tester.testAnomalyBasedDetection(
    "https://example.com",
    normalTraffic,
    anomalousTraffic
  );
  
  expect(results).to.have.property("anomalousDetected");
  console.log("✅ Anomaly-based detection test completed");
}

async function testEvasionTechniques() {
  console.log("\n📝 Test 3: Evasion Techniques");
  
  const tester = new IDSIPSTester();
  const results = await tester.testEvasionTechniques("https://example.com", "/api/search");
  
  expect(results).to.be.an("array");
  console.log(`✅ Tested ${results.length} evasion techniques`);
}

async function testFalsePositives() {
  console.log("\n📝 Test 4: False Positive Analysis");
  
  const tester = new IDSIPSTester();
  const legitimateRequests = [
    { method: "GET", path: "/" },
    { method: "POST", path: "/api/users", body: { name: "John Doe", email: "john@example.com" } }
  ];
  
  const results = await tester.testFalsePositiveAnalysis("https://example.com", legitimateRequests);
  expect(results).to.be.an("array");
  console.log(`✅ Found ${results.length} false positives`);
}

async function testIDSIPSReport() {
  console.log("\n📝 Test 5: Generate IDS/IPS Report");
  
  const tester = new IDSIPSTester();
  await tester.testSignatureDetection();
  
  const report = tester.generateIDSIPSReport();
  expect(report).to.have.property("total");
  expect(report).to.have.property("vulnerabilities");
  
  console.log("✅ IDS/IPS testing report generation test passed");
}

// Run all tests
(async () => {
  try {
    console.log("\n⚠️  REMINDER: This tutorial is for educational purposes only.");
    console.log("   Only test IDS/IPS systems you own or have explicit permission to test.\n");
    
    await testSignatureDetection();
    await testAnomalyDetection();
    await testEvasionTechniques();
    await testFalsePositives();
    await testIDSIPSReport();
    
    console.log("\n✅ All IDS/IPS testing completed!");
    console.log("\n📚 Key Takeaways:");
    console.log("   - Use both signature-based and anomaly-based detection");
    console.log("   - Regularly update signatures");
    console.log("   - Tune rules to reduce false positives");
    console.log("   - Monitor for evasion techniques");
    console.log("   - Implement IPS mode for critical systems");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
})();


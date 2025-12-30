/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 2: Network Security
 * Lesson 3: Traffic Analysis
 * 
 * ⚠️ IMPORTANT: Educational Purpose Only
 * 
 * Learning Objectives:
 * - Understand network traffic analysis
 * - Learn packet analysis techniques
 * - Identify network anomalies
 * - Practice network forensics
 */

import { expect } from "chai";
import supertest from "supertest";
import https from "https";
import http from "http";

console.log("=== TRAFFIC ANALYSIS ===");
console.log("⚠️  FOR EDUCATIONAL AND SECURITY TESTING PURPOSES ONLY");

// Traffic Analyzer
class TrafficAnalyzer {
  constructor() {
    this.trafficData = [];
    this.analysisResults = [];
  }

  async captureHTTPTraffic(url, requests = []) {
    console.log(`\n🔍 Capturing HTTP Traffic: ${url}`);
    
    const traffic = {
      url,
      requests: [],
      responses: []
    };
    
    for (const request of requests) {
      try {
        const startTime = Date.now();
        const response = await supertest(url)
          [request.method.toLowerCase()](request.path)
          .set(request.headers || {})
          .send(request.body || {})
          .timeout(5000);
        
        const endTime = Date.now();
        const duration = endTime - startTime;
        
        traffic.requests.push({
          method: request.method,
          path: request.path,
          headers: request.headers,
          body: request.body
        });
        
        traffic.responses.push({
          status: response.status,
          headers: response.headers,
          body: response.body,
          duration,
          size: JSON.stringify(response.body).length
        });
      } catch (error) {
        traffic.requests.push({
          method: request.method,
          path: request.path,
          error: error.message
        });
      }
    }
    
    this.trafficData.push(traffic);
    return traffic;
  }

  analyzeTrafficPatterns(traffic) {
    console.log(`\n🔍 Analyzing Traffic Patterns`);
    
    const analysis = {
      totalRequests: traffic.requests.length,
      patterns: [],
      anomalies: []
    };
    
    // Analyze response times
    const responseTimes = traffic.responses.map(r => r.duration);
    const avgResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
    const maxResponseTime = Math.max(...responseTimes);
    const minResponseTime = Math.min(...responseTimes);
    
    analysis.patterns.push({
      type: "Response Time",
      average: avgResponseTime,
      min: minResponseTime,
      max: maxResponseTime,
      description: `Average response time: ${avgResponseTime.toFixed(2)}ms`
    });
    
    // Detect anomalies in response times
    const threshold = avgResponseTime * 2;
    const slowResponses = traffic.responses.filter(r => r.duration > threshold);
    if (slowResponses.length > 0) {
      analysis.anomalies.push({
        type: "Slow Response",
        count: slowResponses.length,
        description: `${slowResponses.length} response(s) significantly slower than average`
      });
    }
    
    // Analyze status codes
    const statusCodes = {};
    traffic.responses.forEach(r => {
      statusCodes[r.status] = (statusCodes[r.status] || 0) + 1;
    });
    
    analysis.patterns.push({
      type: "Status Codes",
      distribution: statusCodes,
      description: "HTTP status code distribution"
    });
    
    // Detect error patterns
    const errorResponses = traffic.responses.filter(r => r.status >= 400);
    if (errorResponses.length > 0) {
      analysis.anomalies.push({
        type: "Error Responses",
        count: errorResponses.length,
        description: `${errorResponses.length} error response(s) detected`
      });
    }
    
    // Analyze request sizes
    const requestSizes = traffic.requests.map(r => 
      JSON.stringify(r.body || {}).length
    );
    const avgRequestSize = requestSizes.reduce((a, b) => a + b, 0) / requestSizes.length;
    
    analysis.patterns.push({
      type: "Request Size",
      average: avgRequestSize,
      description: `Average request size: ${avgRequestSize.toFixed(2)} bytes`
    });
    
    this.analysisResults.push(analysis);
    return analysis;
  }

  detectProtocolAnomalies(traffic) {
    console.log(`\n🔍 Detecting Protocol Anomalies`);
    
    const anomalies = [];
    
    // Check for mixed HTTP/HTTPS
    const hasHTTP = traffic.url.startsWith("http://");
    const hasHTTPS = traffic.url.startsWith("https://");
    
    if (hasHTTP) {
      anomalies.push({
        type: "Insecure Protocol",
        severity: "high",
        description: "Using HTTP instead of HTTPS"
      });
    }
    
    // Check for missing security headers
    traffic.responses.forEach((response, index) => {
      if (!response.headers["strict-transport-security"] && hasHTTPS) {
        anomalies.push({
          type: "Missing HSTS",
          severity: "medium",
          description: "Response missing HSTS header"
        });
      }
      
      if (!response.headers["content-security-policy"]) {
        anomalies.push({
          type: "Missing CSP",
          severity: "low",
          description: "Response missing Content Security Policy header"
        });
      }
    });
    
    // Check for information disclosure in headers
    traffic.responses.forEach(response => {
      if (response.headers.server) {
        anomalies.push({
          type: "Information Disclosure",
          severity: "low",
          description: `Server header reveals: ${response.headers.server}`
        });
      }
      
      if (response.headers["x-powered-by"]) {
        anomalies.push({
          type: "Information Disclosure",
          severity: "low",
          description: `X-Powered-By header reveals: ${response.headers["x-powered-by"]}`
        });
      }
    });
    
    return anomalies;
  }

  performNetworkForensics(traffic) {
    console.log(`\n🔍 Performing Network Forensics`);
    
    const forensics = {
      evidence: [],
      timeline: [],
      suspicious: []
    };
    
    // Build timeline
    traffic.responses.forEach((response, index) => {
      forensics.timeline.push({
        timestamp: new Date().toISOString(),
        request: traffic.requests[index],
        response: {
          status: response.status,
          size: response.size,
          duration: response.duration
        }
      });
    });
    
    // Identify suspicious patterns
    const suspiciousStatusCodes = [401, 403, 500, 502, 503];
    traffic.responses.forEach((response, index) => {
      if (suspiciousStatusCodes.includes(response.status)) {
        forensics.suspicious.push({
          type: "Suspicious Status Code",
          status: response.status,
          request: traffic.requests[index],
          description: `Unexpected status code: ${response.status}`
        });
      }
    });
    
    // Detect potential attacks
    const attackPatterns = [
      { pattern: /union.*select/i, type: "SQL Injection Attempt" },
      { pattern: /<script>/i, type: "XSS Attempt" },
      { pattern: /\.\.\/\.\.\//, type: "Path Traversal Attempt" },
      { pattern: /eval\(/i, type: "Code Injection Attempt" }
    ];
    
    traffic.requests.forEach(request => {
      const requestStr = JSON.stringify(request);
      attackPatterns.forEach(attack => {
        if (attack.pattern.test(requestStr)) {
          forensics.suspicious.push({
            type: "Potential Attack",
            attackType: attack.type,
            request,
            description: `Detected ${attack.type} pattern in request`
          });
        }
      });
    });
    
    return forensics;
  }

  analyzeEncryptedTraffic(url) {
    console.log(`\n🔍 Analyzing Encrypted Traffic: ${url}`);
    
    const analysis = {
      url,
      findings: []
    };
    
    // Check TLS version (basic check)
    analysis.findings.push({
      type: "TLS Analysis",
      description: "Encrypted traffic detected - TLS version analysis recommended"
    });
    
    // Check certificate validity
    analysis.findings.push({
      type: "Certificate Validation",
      description: "Verify certificate validity and expiration"
    });
    
    // Check for certificate pinning
    analysis.findings.push({
      type: "Certificate Pinning",
      description: "Consider implementing certificate pinning for enhanced security"
    });
    
    return analysis;
  }

  generateTrafficReport() {
    console.log("\n📊 Traffic Analysis Report:");
    console.log("=" .repeat(50));
    
    this.analysisResults.forEach((analysis, index) => {
      console.log(`\nAnalysis ${index + 1}:`);
      console.log(`  Total Requests: ${analysis.totalRequests}`);
      
      if (analysis.patterns.length > 0) {
        console.log("\n  Patterns:");
        analysis.patterns.forEach(pattern => {
          console.log(`    - ${pattern.type}: ${pattern.description}`);
        });
      }
      
      if (analysis.anomalies.length > 0) {
        console.log("\n  Anomalies:");
        analysis.anomalies.forEach(anomaly => {
          console.log(`    - ${anomaly.type}: ${anomaly.description}`);
        });
      }
    });
    
    console.log("=" .repeat(50));
    
    return {
      analyses: this.analysisResults.length,
      totalTraffic: this.trafficData.length
    };
  }
}

// Test Scenarios
async function testTrafficCapture() {
  console.log("\n📝 Test 1: Traffic Capture");
  
  const analyzer = new TrafficAnalyzer();
  const traffic = await analyzer.captureHTTPTraffic("https://example.com", [
    { method: "GET", path: "/" },
    { method: "GET", path: "/api/users" }
  ]);
  
  expect(traffic).to.have.property("requests");
  expect(traffic).to.have.property("responses");
  console.log(`✅ Captured ${traffic.requests.length} requests`);
}

async function testTrafficPatterns() {
  console.log("\n📝 Test 2: Traffic Pattern Analysis");
  
  const analyzer = new TrafficAnalyzer();
  const traffic = await analyzer.captureHTTPTraffic("https://example.com", [
    { method: "GET", path: "/" },
    { method: "GET", path: "/api/users" }
  ]);
  
  const analysis = analyzer.analyzeTrafficPatterns(traffic);
  expect(analysis).to.have.property("patterns");
  expect(analysis).to.have.property("anomalies");
  console.log(`✅ Analyzed ${analysis.patterns.length} patterns`);
}

async function testProtocolAnomalies() {
  console.log("\n📝 Test 3: Protocol Anomaly Detection");
  
  const analyzer = new TrafficAnalyzer();
  const traffic = await analyzer.captureHTTPTraffic("http://example.com", [
    { method: "GET", path: "/" }
  ]);
  
  const anomalies = analyzer.detectProtocolAnomalies(traffic);
  expect(anomalies).to.be.an("array");
  console.log(`✅ Detected ${anomalies.length} protocol anomalies`);
}

async function testNetworkForensics() {
  console.log("\n📝 Test 4: Network Forensics");
  
  const analyzer = new TrafficAnalyzer();
  const traffic = await analyzer.captureHTTPTraffic("https://example.com", [
    { method: "GET", path: "/" },
    { method: "POST", path: "/api/login", body: { username: "test", password: "test" } }
  ]);
  
  const forensics = analyzer.performNetworkForensics(traffic);
  expect(forensics).to.have.property("timeline");
  expect(forensics).to.have.property("suspicious");
  console.log(`✅ Generated forensics report with ${forensics.timeline.length} timeline entries`);
}

async function testTrafficReport() {
  console.log("\n📝 Test 5: Generate Traffic Analysis Report");
  
  const analyzer = new TrafficAnalyzer();
  await analyzer.captureHTTPTraffic("https://example.com", [
    { method: "GET", path: "/" }
  ]);
  
  const report = analyzer.generateTrafficReport();
  expect(report).to.have.property("analyses");
  expect(report).to.have.property("totalTraffic");
  
  console.log("✅ Traffic analysis report generation test passed");
}

// Run all tests
(async () => {
  try {
    console.log("\n⚠️  REMINDER: This tutorial is for educational purposes only.");
    console.log("   Only analyze traffic of systems you own or have permission to monitor.\n");
    
    await testTrafficCapture();
    await testTrafficPatterns();
    await testProtocolAnomalies();
    await testNetworkForensics();
    await testTrafficReport();
    
    console.log("\n✅ All traffic analysis tests completed!");
    console.log("\n📚 Key Takeaways:");
    console.log("   - Monitor network traffic for anomalies");
    console.log("   - Analyze response times and patterns");
    console.log("   - Detect protocol-level issues");
    console.log("   - Perform network forensics for incident response");
    console.log("   - Use encrypted protocols (HTTPS)");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
})();


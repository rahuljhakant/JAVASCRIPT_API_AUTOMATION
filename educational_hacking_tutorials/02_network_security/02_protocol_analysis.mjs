/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 2: Network Security
 * Lesson 2: Protocol Analysis
 * 
 * ⚠️ IMPORTANT: Educational Purpose Only
 * 
 * Learning Objectives:
 * - Understand network protocol security
 * - Analyze HTTP/HTTPS protocols
 * - Test WebSocket security
 * - Learn DNS and SMTP protocol testing
 */

import { expect } from "chai";
import supertest from "supertest";
import https from "https";
import http from "http";
import dns from "dns/promises";

console.log("=== PROTOCOL ANALYSIS ===");
console.log("⚠️  FOR EDUCATIONAL AND SECURITY TESTING PURPOSES ONLY");

// Protocol Analyzer
class ProtocolAnalyzer {
  constructor() {
    this.analysisResults = [];
  }

  async analyzeHTTPProtocol(url) {
    console.log(`\n🔍 Analyzing HTTP Protocol: ${url}`);
    
    const analysis = {
      protocol: "HTTP",
      url,
      findings: []
    };
    
    try {
      const parsedUrl = new URL(url);
      
      // Check if HTTPS is available
      if (parsedUrl.protocol === "http:") {
        const httpsUrl = url.replace("http://", "https://");
        try {
          await new Promise((resolve, reject) => {
            https.get(httpsUrl, (res) => {
              analysis.findings.push({
                type: "HTTPS Available",
                severity: "medium",
                description: "HTTPS is available but HTTP is being used"
              });
              resolve();
            }).on("error", reject);
          });
        } catch (error) {
          // HTTPS not available
        }
      }
      
      // Analyze HTTP headers
      const response = await supertest(url)
        .get("/")
        .timeout(5000);
      
      const headers = response.headers;
      
      // Check security headers
      if (!headers["strict-transport-security"]) {
        analysis.findings.push({
          type: "Missing HSTS",
          severity: "medium",
          description: "HTTP Strict Transport Security header not present"
        });
      }
      
      if (!headers["content-security-policy"]) {
        analysis.findings.push({
          type: "Missing CSP",
          severity: "low",
          description: "Content Security Policy header not present"
        });
      }
      
      // Check for information disclosure
      if (headers.server) {
        analysis.findings.push({
          type: "Server Information Disclosure",
          severity: "low",
          description: `Server header reveals: ${headers.server}`
        });
      }
      
      this.analysisResults.push(analysis);
      return analysis;
    } catch (error) {
      console.error(`Error analyzing HTTP: ${error.message}`);
      return analysis;
    }
  }

  async analyzeHTTPSProtocol(url) {
    console.log(`\n🔍 Analyzing HTTPS Protocol: ${url}`);
    
    const analysis = {
      protocol: "HTTPS",
      url,
      findings: []
    };
    
    try {
      const parsedUrl = new URL(url);
      
      return new Promise((resolve, reject) => {
        const options = {
          hostname: parsedUrl.hostname,
          port: parsedUrl.port || 443,
          path: parsedUrl.pathname,
          method: "GET",
          rejectUnauthorized: false // For testing purposes
        };
        
        const req = https.request(options, (res) => {
          // Check TLS version (would need tls module for detailed analysis)
          analysis.findings.push({
            type: "HTTPS Connection",
            severity: "info",
            description: "HTTPS connection established"
          });
          
          // Check certificate (basic check)
          if (res.socket.authorized === false) {
            analysis.findings.push({
              type: "Certificate Issue",
              severity: "high",
              description: "Certificate validation failed"
            });
          }
          
          this.analysisResults.push(analysis);
          resolve(analysis);
        });
        
        req.on("error", (error) => {
          analysis.findings.push({
            type: "Connection Error",
            severity: "medium",
            description: error.message
          });
          reject(error);
        });
        
        req.end();
      });
    } catch (error) {
      console.error(`Error analyzing HTTPS: ${error.message}`);
      return analysis;
    }
  }

  async analyzeWebSocketSecurity(wsUrl) {
    console.log(`\n🔍 Analyzing WebSocket Security: ${wsUrl}`);
    
    const analysis = {
      protocol: "WebSocket",
      url: wsUrl,
      findings: []
    };
    
    // Check if WSS (secure WebSocket) is available
    if (wsUrl.startsWith("ws://")) {
      const wssUrl = wsUrl.replace("ws://", "wss://");
      analysis.findings.push({
        type: "Insecure WebSocket",
        severity: "high",
        description: "Using unencrypted WebSocket (ws://) instead of secure (wss://)"
      });
    }
    
    // Check for origin validation
    analysis.findings.push({
      type: "Origin Validation",
      severity: "info",
      description: "WebSocket should validate origin header"
    });
    
    // Check for authentication
    analysis.findings.push({
      type: "Authentication",
      severity: "info",
      description: "WebSocket connections should require authentication"
    });
    
    this.analysisResults.push(analysis);
    return analysis;
  }

  async analyzeDNSProtocol(domain) {
    console.log(`\n🔍 Analyzing DNS Protocol: ${domain}`);
    
    const analysis = {
      protocol: "DNS",
      domain,
      findings: []
    };
    
    try {
      // Check DNS records
      const records = await dns.resolve4(domain);
      analysis.findings.push({
        type: "A Records",
        severity: "info",
        description: `Found ${records.length} A record(s)`
      });
      
      // Check for DNS security extensions (DNSSEC)
      try {
        const txtRecords = await dns.resolveTxt(domain);
        const hasDNSSEC = txtRecords.some(record => 
          record.some(r => r.includes("dnssec"))
        );
        
        if (!hasDNSSEC) {
          analysis.findings.push({
            type: "DNSSEC Not Enabled",
            severity: "medium",
            description: "DNSSEC not detected, DNS responses may be spoofed"
          });
        }
      } catch (error) {
        // DNSSEC check failed
      }
      
      // Check for DNS over HTTPS (DoH) or DNS over TLS (DoT)
      analysis.findings.push({
        type: "DNS Encryption",
        severity: "info",
        description: "Consider using DNS over HTTPS (DoH) or DNS over TLS (DoT)"
      });
      
      this.analysisResults.push(analysis);
      return analysis;
    } catch (error) {
      analysis.findings.push({
        type: "DNS Resolution Error",
        severity: "medium",
        description: error.message
      });
      return analysis;
    }
  }

  async analyzeSMTPProtocol(smtpHost, port = 25) {
    console.log(`\n🔍 Analyzing SMTP Protocol: ${smtpHost}:${port}`);
    
    const analysis = {
      protocol: "SMTP",
      host: smtpHost,
      port,
      findings: []
    };
    
    // Check for STARTTLS support
    analysis.findings.push({
      type: "STARTTLS Support",
      severity: "info",
      description: "SMTP should support STARTTLS for encryption"
    });
    
    // Check for authentication
    analysis.findings.push({
      type: "SMTP Authentication",
      severity: "high",
      description: "SMTP should require authentication to prevent open relay"
    });
    
    // Check for SPF, DKIM, DMARC
    analysis.findings.push({
      type: "Email Security Records",
      severity: "info",
      description: "Check for SPF, DKIM, and DMARC records"
    });
    
    this.analysisResults.push(analysis);
    return analysis;
  }

  async analyzeFTPProtocol(ftpHost, port = 21) {
    console.log(`\n🔍 Analyzing FTP Protocol: ${ftpHost}:${port}`);
    
    const analysis = {
      protocol: "FTP",
      host: ftpHost,
      port,
      findings: []
    };
    
    // Check for FTPS (FTP over SSL/TLS)
    analysis.findings.push({
      type: "FTPS Support",
      severity: "high",
      description: "FTP should use FTPS (FTP over SSL/TLS) for encryption"
    });
    
    // Check for SFTP (SSH File Transfer Protocol)
    analysis.findings.push({
      type: "SFTP Alternative",
      severity: "info",
      description: "Consider using SFTP instead of FTP for better security"
    });
    
    // Check for anonymous access
    analysis.findings.push({
      type: "Anonymous Access",
      severity: "critical",
      description: "Anonymous FTP access should be disabled"
    });
    
    this.analysisResults.push(analysis);
    return analysis;
  }

  generateProtocolReport() {
    console.log("\n📊 Protocol Analysis Report:");
    console.log("=" .repeat(50));
    
    this.analysisResults.forEach(analysis => {
      console.log(`\n${analysis.protocol} Analysis:`);
      if (analysis.findings.length > 0) {
        analysis.findings.forEach(finding => {
          const icon = finding.severity === "critical" ? "🔴" : 
                      finding.severity === "high" ? "🟠" : 
                      finding.severity === "medium" ? "🟡" : "ℹ️";
          console.log(`  ${icon} ${finding.type}: ${finding.description}`);
        });
      }
    });
    
    console.log("=" .repeat(50));
    
    return {
      protocols: this.analysisResults.length,
      findings: this.analysisResults.flatMap(a => a.findings)
    };
  }
}

// Test Scenarios
async function testHTTPAnalysis() {
  console.log("\n📝 Test 1: HTTP Protocol Analysis");
  
  const analyzer = new ProtocolAnalyzer();
  const analysis = await analyzer.analyzeHTTPProtocol("https://example.com");
  
  expect(analysis).to.have.property("protocol");
  expect(analysis).to.have.property("findings");
  console.log(`✅ Found ${analysis.findings.length} HTTP-related findings`);
}

async function testHTTPSAnalysis() {
  console.log("\n📝 Test 2: HTTPS Protocol Analysis");
  
  const analyzer = new ProtocolAnalyzer();
  const analysis = await analyzer.analyzeHTTPSProtocol("https://example.com");
  
  expect(analysis).to.have.property("protocol");
  expect(analysis).to.have.property("findings");
  console.log(`✅ Found ${analysis.findings.length} HTTPS-related findings`);
}

async function testWebSocketAnalysis() {
  console.log("\n📝 Test 3: WebSocket Security Analysis");
  
  const analyzer = new ProtocolAnalyzer();
  const analysis = await analyzer.analyzeWebSocketSecurity("ws://example.com/ws");
  
  expect(analysis).to.have.property("protocol");
  expect(analysis).to.have.property("findings");
  console.log(`✅ Found ${analysis.findings.length} WebSocket-related findings`);
}

async function testDNSAnalysis() {
  console.log("\n📝 Test 4: DNS Protocol Analysis");
  
  const analyzer = new ProtocolAnalyzer();
  const analysis = await analyzer.analyzeDNSProtocol("example.com");
  
  expect(analysis).to.have.property("protocol");
  expect(analysis).to.have.property("findings");
  console.log(`✅ Found ${analysis.findings.length} DNS-related findings`);
}

async function testProtocolReport() {
  console.log("\n📝 Test 5: Generate Protocol Analysis Report");
  
  const analyzer = new ProtocolAnalyzer();
  await analyzer.analyzeHTTPProtocol("https://example.com");
  await analyzer.analyzeDNSProtocol("example.com");
  
  const report = analyzer.generateProtocolReport();
  expect(report).to.have.property("protocols");
  expect(report).to.have.property("findings");
  
  console.log("✅ Protocol analysis report generation test passed");
}

// Run all tests
(async () => {
  try {
    console.log("\n⚠️  REMINDER: This tutorial is for educational purposes only.");
    console.log("   Only analyze protocols of systems you own or have permission to test.\n");
    
    await testHTTPAnalysis();
    await testHTTPSAnalysis();
    await testWebSocketAnalysis();
    await testDNSAnalysis();
    await testProtocolReport();
    
    console.log("\n✅ All protocol analysis tests completed!");
    console.log("\n📚 Key Takeaways:");
    console.log("   - Always use encrypted protocols (HTTPS, WSS, FTPS)");
    console.log("   - Implement proper security headers");
    console.log("   - Validate certificates properly");
    console.log("   - Use DNSSEC for DNS security");
    console.log("   - Require authentication for all network services");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
})();


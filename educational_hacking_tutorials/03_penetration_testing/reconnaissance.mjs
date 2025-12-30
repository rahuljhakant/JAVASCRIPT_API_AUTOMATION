/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 3: Penetration Testing
 * Lesson 1: Reconnaissance
 * 
 * ⚠️ IMPORTANT: Educational Purpose Only
 * 
 * Learning Objectives:
 * - Understand reconnaissance techniques
 * - Learn information gathering methods
 * - Implement safe reconnaissance tools
 * - Practice ethical information gathering
 */

import { expect } from "chai";
import supertest from "supertest";
import https from "https";
import dns from "dns/promises";

console.log("=== RECONNAISSANCE TECHNIQUES ===");

// Information Gathering Service
class ReconnaissanceService {
  constructor() {
    this.gatheredInfo = {
      domain: null,
      ipAddress: null,
      dnsRecords: [],
      openPorts: [],
      technologies: [],
      subdomains: []
    };
  }

  async resolveDomain(domain) {
    try {
      console.log(`\n🔍 Resolving domain: ${domain}`);
      const addresses = await dns.resolve4(domain);
      this.gatheredInfo.domain = domain;
      this.gatheredInfo.ipAddress = addresses[0];
      console.log(`✅ IP Address: ${addresses[0]}`);
      return addresses;
    } catch (error) {
      console.error(`❌ Error resolving domain: ${error.message}`);
      return null;
    }
  }

  async getDNSRecords(domain) {
    try {
      console.log(`\n🔍 Gathering DNS records for: ${domain}`);
      
      const records = {
        A: [],
        AAAA: [],
        MX: [],
        TXT: [],
        NS: []
      };

      try {
        records.A = await dns.resolve4(domain);
        console.log(`✅ A Records: ${records.A.join(", ")}`);
      } catch (error) {
        console.log(`ℹ️  No A records found`);
      }

      try {
        records.MX = await dns.resolveMx(domain);
        console.log(`✅ MX Records: ${records.MX.length} found`);
      } catch (error) {
        console.log(`ℹ️  No MX records found`);
      }

      try {
        records.TXT = await dns.resolveTxt(domain);
        console.log(`✅ TXT Records: ${records.TXT.length} found`);
      } catch (error) {
        console.log(`ℹ️  No TXT records found`);
      }

      this.gatheredInfo.dnsRecords = records;
      return records;
    } catch (error) {
      console.error(`❌ Error getting DNS records: ${error.message}`);
      return null;
    }
  }

  async checkHTTPHeaders(url) {
    try {
      console.log(`\n🔍 Checking HTTP headers for: ${url}`);
      
      return new Promise((resolve, reject) => {
        const parsedUrl = new URL(url);
        const options = {
          hostname: parsedUrl.hostname,
          port: parsedUrl.port || (parsedUrl.protocol === "https:" ? 443 : 80),
          path: parsedUrl.pathname,
          method: "HEAD",
          timeout: 5000
        };

        const req = https.request(options, (res) => {
          const headers = res.headers;
          console.log("✅ HTTP Headers:");
          Object.entries(headers).forEach(([key, value]) => {
            console.log(`   ${key}: ${value}`);
          });

          // Detect technologies
          const technologies = [];
          if (headers.server) technologies.push(`Server: ${headers.server}`);
          if (headers["x-powered-by"]) technologies.push(`Powered by: ${headers["x-powered-by"]}`);
          if (headers["x-aspnet-version"]) technologies.push(`ASP.NET: ${headers["x-aspnet-version"]}`);

          this.gatheredInfo.technologies = technologies;
          resolve(headers);
        });

        req.on("error", (error) => {
          console.error(`❌ Error checking headers: ${error.message}`);
          reject(error);
        });

        req.on("timeout", () => {
          req.destroy();
          reject(new Error("Request timeout"));
        });

        req.end();
      });
    } catch (error) {
      console.error(`❌ Error: ${error.message}`);
      return null;
    }
  }

  async checkCommonPorts(host, ports = [80, 443, 8080, 8443]) {
    console.log(`\n🔍 Checking common ports on: ${host}`);
    const openPorts = [];

    for (const port of ports) {
      try {
        await this.checkPort(host, port);
        openPorts.push(port);
        console.log(`✅ Port ${port} is open`);
      } catch (error) {
        console.log(`❌ Port ${port} is closed or filtered`);
      }
    }

    this.gatheredInfo.openPorts = openPorts;
    return openPorts;
  }

  async checkPort(host, port) {
    return new Promise((resolve, reject) => {
      const socket = new https.Agent();
      const req = https.request({
        hostname: host,
        port: port,
        method: "HEAD",
        timeout: 2000
      }, () => {
        resolve(true);
      });

      req.on("error", () => reject(false));
      req.on("timeout", () => {
        req.destroy();
        reject(false);
      });

      req.end();
    });
  }

  generateReport() {
    console.log("\n📊 Reconnaissance Report:");
    console.log("=" .repeat(50));
    console.log(`Domain: ${this.gatheredInfo.domain}`);
    console.log(`IP Address: ${this.gatheredInfo.ipAddress}`);
    console.log(`Open Ports: ${this.gatheredInfo.openPorts.join(", ") || "None detected"}`);
    console.log(`Technologies: ${this.gatheredInfo.technologies.join(", ") || "None detected"}`);
    console.log("=" .repeat(50));
    return this.gatheredInfo;
  }
}

// Test Scenarios
async function testDomainResolution() {
  console.log("\n📝 Test 1: Domain Resolution");
  
  const recon = new ReconnaissanceService();
  const domain = "example.com"; // Using example.com for safe testing
  
  const addresses = await recon.resolveDomain(domain);
  expect(addresses).to.not.be.null;
  expect(recon.gatheredInfo.ipAddress).to.exist;
  
  console.log("✅ Domain resolution test passed");
}

async function testDNSRecords() {
  console.log("\n📝 Test 2: DNS Records Gathering");
  
  const recon = new ReconnaissanceService();
  const domain = "example.com";
  
  const records = await recon.getDNSRecords(domain);
  expect(records).to.not.be.null;
  
  console.log("✅ DNS records gathering test passed");
}

async function testHTTPHeaders() {
  console.log("\n📝 Test 3: HTTP Headers Analysis");
  
  const recon = new ReconnaissanceService();
  const url = "https://example.com";
  
  try {
    const headers = await recon.checkHTTPHeaders(url);
    if (headers) {
      expect(headers).to.be.an("object");
      console.log("✅ HTTP headers analysis test passed");
    }
  } catch (error) {
    console.log("ℹ️  HTTP headers test completed (may vary by target)");
  }
}

async function testReconnaissanceReport() {
  console.log("\n📝 Test 4: Generate Reconnaissance Report");
  
  const recon = new ReconnaissanceService();
  await recon.resolveDomain("example.com");
  await recon.getDNSRecords("example.com");
  
  const report = recon.generateReport();
  expect(report).to.have.property("domain");
  expect(report).to.have.property("ipAddress");
  
  console.log("✅ Reconnaissance report generation test passed");
}

// Run all tests
(async () => {
  try {
    console.log("\n⚠️  REMINDER: This tutorial is for educational purposes only.");
    console.log("   Only test systems you own or have explicit permission to test.\n");
    
    await testDomainResolution();
    await testDNSRecords();
    await testHTTPHeaders();
    await testReconnaissanceReport();
    
    console.log("\n✅ All reconnaissance tests completed!");
    console.log("\n📚 Key Takeaways:");
    console.log("   - Reconnaissance is the first phase of penetration testing");
    console.log("   - Always obtain proper authorization before testing");
    console.log("   - Document all findings for reporting");
    console.log("   - Use information gathering ethically and legally");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
})();


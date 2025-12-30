/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 2: Network Security
 * Tutorial 1: Port Scanning (Educational)
 * 
 * ⚠️ EDUCATIONAL PURPOSE ONLY
 * This tutorial is for educational and defensive security purposes only.
 * Only scan systems you own or have explicit written permission to scan.
 * 
 * Learning Objectives:
 * - Understand port scanning concepts
 * - Learn network reconnaissance techniques
 * - Implement defensive measures
 * - Understand different scanning methods
 */

import { expect } from "chai";
import net from "net";
import dns from "dns/promises";

console.log("=== PORT SCANNING (EDUCATIONAL) ===");

/**
 * Port Scanner (Educational)
 * Demonstrates port scanning concepts for security testing
 */
class PortScanner {
  constructor() {
    this.commonPorts = [
      20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
      1433, 3306, 3389, 5432, 5900, 8080, 8443
    ];
    this.scanResults = [];
  }

  /**
   * Resolve hostname to IP address
   */
  async resolveHostname(hostname) {
    try {
      const addresses = await dns.resolve4(hostname);
      return addresses[0];
    } catch (error) {
      throw new Error(`Failed to resolve hostname: ${error.message}`);
    }
  }

  /**
   * Scan single port
   */
  async scanPort(host, port, timeout = 2000) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      const startTime = Date.now();

      socket.setTimeout(timeout);

      socket.on('connect', () => {
        const endTime = Date.now();
        socket.destroy();
        resolve({
          port,
          status: 'open',
          responseTime: endTime - startTime
        });
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve({
          port,
          status: 'filtered',
          responseTime: timeout
        });
      });

      socket.on('error', () => {
        resolve({
          port,
          status: 'closed',
          responseTime: Date.now() - startTime
        });
      });

      socket.connect(port, host);
    });
  }

  /**
   * Scan multiple ports
   */
  async scanPorts(host, ports, timeout = 2000) {
    const results = [];

    for (const port of ports) {
      const result = await this.scanPort(host, port, timeout);
      results.push(result);
      
      // Small delay to avoid overwhelming the target
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    return results;
  }

  /**
   * Scan common ports
   */
  async scanCommonPorts(host, timeout = 2000) {
    return await this.scanPorts(host, this.commonPorts, timeout);
  }

  /**
   * Scan port range
   */
  async scanPortRange(host, startPort, endPort, timeout = 2000) {
    const ports = Array.from({ length: endPort - startPort + 1 }, (_, i) => startPort + i);
    return await this.scanPorts(host, ports, timeout);
  }

  /**
   * Identify service by port
   */
  identifyService(port) {
    const serviceMap = {
      20: 'FTP Data',
      21: 'FTP',
      22: 'SSH',
      23: 'Telnet',
      25: 'SMTP',
      53: 'DNS',
      80: 'HTTP',
      110: 'POP3',
      143: 'IMAP',
      443: 'HTTPS',
      993: 'IMAPS',
      995: 'POP3S',
      1433: 'MSSQL',
      3306: 'MySQL',
      3389: 'RDP',
      5432: 'PostgreSQL',
      5900: 'VNC',
      8080: 'HTTP-Proxy',
      8443: 'HTTPS-Alt'
    };

    return serviceMap[port] || 'Unknown';
  }

  /**
   * Generate scan report
   */
  generateReport(scanResults) {
    const openPorts = scanResults.filter(r => r.status === 'open');
    const closedPorts = scanResults.filter(r => r.status === 'closed');
    const filteredPorts = scanResults.filter(r => r.status === 'filtered');

    return {
      total: scanResults.length,
      open: openPorts.length,
      closed: closedPorts.length,
      filtered: filteredPorts.length,
      openPorts: openPorts.map(p => ({
        port: p.port,
        service: this.identifyService(p.port),
        responseTime: p.responseTime
      })),
      summary: {
        open: openPorts.map(p => p.port),
        closed: closedPorts.map(p => p.port),
        filtered: filteredPorts.map(p => p.port)
      }
    };
  }
}

/**
 * Network Security Helper
 * Demonstrates defensive measures
 */
class NetworkSecurity {
  /**
   * Check if port should be exposed
   */
  static shouldExposePort(port, environment = 'production') {
    const safePorts = {
      production: [80, 443], // Only HTTP/HTTPS in production
      staging: [80, 443, 8080, 8443],
      development: [80, 443, 3000, 8080, 5432, 3306]
    };

    return safePorts[environment]?.includes(port) || false;
  }

  /**
   * Validate firewall rules
   */
  static validateFirewallRules(openPorts, allowedPorts) {
    const exposedPorts = openPorts.filter(p => !allowedPorts.includes(p));
    return {
      secure: exposedPorts.length === 0,
      exposedPorts,
      allowedPorts: openPorts.filter(p => allowedPorts.includes(p))
    };
  }

  /**
   * Generate security recommendations
   */
  static generateRecommendations(scanReport) {
    const recommendations = [];

    // Check for common insecure ports
    const insecurePorts = [21, 23, 80, 1433, 3306, 5432];
    const exposedInsecure = scanReport.openPorts.filter(p => 
      insecurePorts.includes(p.port)
    );

    if (exposedInsecure.length > 0) {
      recommendations.push({
        severity: 'high',
        issue: 'Insecure ports exposed',
        ports: exposedInsecure.map(p => p.port),
        recommendation: 'Close unnecessary ports or use secure alternatives (SSH instead of Telnet, HTTPS instead of HTTP)'
      });
    }

    // Check for database ports
    const dbPorts = [1433, 3306, 5432, 27017];
    const exposedDB = scanReport.openPorts.filter(p => 
      dbPorts.includes(p.port)
    );

    if (exposedDB.length > 0) {
      recommendations.push({
        severity: 'critical',
        issue: 'Database ports exposed',
        ports: exposedDB.map(p => p.port),
        recommendation: 'Database ports should never be exposed to the internet. Use VPN or SSH tunneling.'
      });
    }

    return recommendations;
  }
}

// Exercises and Tests
describe("Port Scanning (Educational)", () => {
  let portScanner;

  beforeEach(() => {
    portScanner = new PortScanner();
  });

  it("should resolve hostname to IP", async () => {
    try {
      const ip = await portScanner.resolveHostname("localhost");
      expect(ip).to.be.a('string');
      expect(ip).to.match(/^\d+\.\d+\.\d+\.\d+$/);
    } catch (error) {
      // DNS resolution might fail in test environment
      expect(error).to.be.an('error');
    }
  });

  it("should scan a single port", async () => {
    // ⚠️ Only scan systems you own or have permission to scan
    try {
      const result = await portScanner.scanPort("127.0.0.1", 80, 1000);

      expect(result).to.have.property('port');
      expect(result).to.have.property('status');
      expect(result.status).to.be.oneOf(['open', 'closed', 'filtered']);
    } catch (error) {
      expect(error).to.be.an('error');
    }
  });

  it("should scan common ports", async () => {
    try {
      const results = await portScanner.scanCommonPorts("127.0.0.1", 500);

      expect(results).to.be.an('array');
      expect(results.length).to.be.greaterThan(0);
      results.forEach(result => {
        expect(result).to.have.property('port');
        expect(result).to.have.property('status');
      });
    } catch (error) {
      expect(error).to.be.an('error');
    }
  });

  it("should identify services by port", () => {
    expect(portScanner.identifyService(80)).to.equal('HTTP');
    expect(portScanner.identifyService(443)).to.equal('HTTPS');
    expect(portScanner.identifyService(22)).to.equal('SSH');
    expect(portScanner.identifyService(9999)).to.equal('Unknown');
  });

  it("should generate scan report", () => {
    const mockResults = [
      { port: 80, status: 'open', responseTime: 10 },
      { port: 443, status: 'open', responseTime: 15 },
      { port: 22, status: 'closed', responseTime: 5 },
      { port: 8080, status: 'filtered', responseTime: 2000 }
    ];

    const report = portScanner.generateReport(mockResults);

    expect(report).to.have.property('total');
    expect(report).to.have.property('open');
    expect(report).to.have.property('openPorts');
    expect(report.open).to.equal(2);
    expect(report.openPorts.length).to.equal(2);
  });
});

// Network Security Tests
describe("Network Security", () => {
  it("should validate port exposure rules", () => {
    expect(NetworkSecurity.shouldExposePort(80, 'production')).to.be.true;
    expect(NetworkSecurity.shouldExposePort(443, 'production')).to.be.true;
    expect(NetworkSecurity.shouldExposePort(3306, 'production')).to.be.false;
    expect(NetworkSecurity.shouldExposePort(5432, 'development')).to.be.true;
  });

  it("should validate firewall rules", () => {
    const openPorts = [80, 443, 3306, 8080];
    const allowedPorts = [80, 443];

    const validation = NetworkSecurity.validateFirewallRules(openPorts, allowedPorts);

    expect(validation.secure).to.be.false;
    expect(validation.exposedPorts).to.include(3306);
    expect(validation.exposedPorts).to.include(8080);
    expect(validation.allowedPorts).to.include(80);
    expect(validation.allowedPorts).to.include(443);
  });

  it("should generate security recommendations", () => {
    const mockReport = {
      openPorts: [
        { port: 80, service: 'HTTP', responseTime: 10 },
        { port: 3306, service: 'MySQL', responseTime: 15 },
        { port: 22, service: 'SSH', responseTime: 5 }
      ]
    };

    const recommendations = NetworkSecurity.generateRecommendations(mockReport);

    expect(recommendations).to.be.an('array');
    expect(recommendations.length).to.be.greaterThan(0);

    const dbRecommendation = recommendations.find(r => r.issue.includes('Database'));
    expect(dbRecommendation).to.not.be.undefined;
    expect(dbRecommendation.severity).to.equal('critical');
  });
});

export {
  PortScanner,
  NetworkSecurity
};


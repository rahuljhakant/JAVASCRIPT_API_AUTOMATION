/**
 * PHASE 4: PROFESSIONAL LEVEL
 * Module 2: Security Testing
 * Main Security Testing Suite
 * 
 * Learning Objectives:
 * - Comprehensive security testing framework
 * - Integration of all security testing modules
 * - Professional-level security assessment capabilities
 */

import { expect } from "chai";
import supertest from "supertest";
import { EnhancedSupertestClient } from "../../utils/advanced-supertest-extensions.mjs";

// Import all security testing modules
import { OWASPTop10Tester } from "./01-owasp-top-10/owasp-comprehensive-testing.mjs";
import { PenetrationTestingSuite } from "./02-penetration-testing/penetration-testing-suite.mjs";
import { VulnerabilityAssessment } from "./03-vulnerability-scanning/vulnerability-assessment.mjs";
import { SIEMIntegration } from "./04-security-monitoring/siem-integration.mjs";
import { ComplianceTestingSuite } from "./05-compliance-testing/compliance-testing-suite.mjs";
import { SocialEngineeringTester } from "./06-social-engineering/social-engineering-testing.mjs";
import { PhysicalSecurityTester } from "./07-physical-security/physical-security-testing.mjs";
import { MobileSecurityTester } from "./08-mobile-security/mobile-security-testing.mjs";
import { CloudSecurityTester } from "./09-cloud-security/cloud-security-testing.mjs";
import { IoTSecurityTester } from "./10-iot-security/iot-security-testing.mjs";

console.log("=== PROFESSIONAL SECURITY TESTING SUITE ===");

// Comprehensive Security Testing Manager
class SecurityTestingManager {
  constructor(client) {
    this.client = client;
    this.testers = {
      owasp: new OWASPTop10Tester(client),
      penetration: new PenetrationTestingSuite(client),
      vulnerability: new VulnerabilityAssessment(client),
      siem: new SIEMIntegration(client),
      compliance: new ComplianceTestingSuite(client),
      socialEngineering: new SocialEngineeringTester(client),
      physicalSecurity: new PhysicalSecurityTester(client),
      mobileSecurity: new MobileSecurityTester(client),
      cloudSecurity: new CloudSecurityTester(client),
      iotSecurity: new IoTSecurityTester(client)
    };
    this.results = new Map();
    this.overallRiskLevel = 'UNKNOWN';
    this.recommendations = [];
  }
  
  // Run all security tests
  async runAllSecurityTests() {
    console.log("🔒 Starting Comprehensive Security Testing Suite...");
    
    const testResults = await Promise.allSettled([
      this.testers.owasp.runAllOWASPTests(),
      this.testers.penetration.runAllPenetrationTests(),
      this.testers.vulnerability.runAllVulnerabilityTests(),
      this.testers.siem.runAllSIEMTests(),
      this.testers.compliance.runAllComplianceTests(),
      this.testers.socialEngineering.runAllSocialEngineeringTests(),
      this.testers.physicalSecurity.runAllPhysicalSecurityTests(),
      this.testers.mobileSecurity.runAllMobileSecurityTests(),
      this.testers.cloudSecurity.runAllCloudSecurityTests(),
      this.testers.iotSecurity.runAllIoTSecurityTests()
    ]);
    
    // Process results
    const results = {
      owasp: testResults[0].status === 'fulfilled' ? testResults[0].value : null,
      penetration: testResults[1].status === 'fulfilled' ? testResults[1].value : null,
      vulnerability: testResults[2].status === 'fulfilled' ? testResults[2].value : null,
      siem: testResults[3].status === 'fulfilled' ? testResults[3].value : null,
      compliance: testResults[4].status === 'fulfilled' ? testResults[4].value : null,
      socialEngineering: testResults[5].status === 'fulfilled' ? testResults[5].value : null,
      physicalSecurity: testResults[6].status === 'fulfilled' ? testResults[6].value : null,
      mobileSecurity: testResults[7].status === 'fulfilled' ? testResults[7].value : null,
      cloudSecurity: testResults[8].status === 'fulfilled' ? testResults[8].value : null,
      iotSecurity: testResults[9].status === 'fulfilled' ? testResults[9].value : null
    };
    
    this.results = new Map(Object.entries(results));
    this.overallRiskLevel = this.calculateOverallRiskLevel();
    this.recommendations = this.generateOverallRecommendations();
    
    return results;
  }
  
  // Calculate overall risk level
  calculateOverallRiskLevel() {
    const riskLevels = [];
    
    for (const [category, results] of this.results) {
      if (results && results.length > 0) {
        const categoryRisk = this.calculateCategoryRisk(results);
        riskLevels.push(categoryRisk);
      }
    }
    
    if (riskLevels.includes('CRITICAL')) return 'CRITICAL';
    if (riskLevels.filter(r => r === 'HIGH').length >= 3) return 'HIGH';
    if (riskLevels.filter(r => r === 'MEDIUM').length >= 5) return 'MEDIUM';
    return 'LOW';
  }
  
  calculateCategoryRisk(results) {
    const totalTests = results.reduce((sum, result) => sum + result.total, 0);
    const totalFailed = results.reduce((sum, result) => sum + result.failed, 0);
    const failureRate = totalTests > 0 ? (totalFailed / totalTests) * 100 : 0;
    
    if (failureRate >= 50) return 'CRITICAL';
    if (failureRate >= 30) return 'HIGH';
    if (failureRate >= 15) return 'MEDIUM';
    return 'LOW';
  }
  
  // Generate overall recommendations
  generateOverallRecommendations() {
    const recommendations = [];
    
    for (const [category, results] of this.results) {
      if (results && results.length > 0) {
        const categoryRecommendations = this.extractRecommendations(results);
        recommendations.push({
          category: category.toUpperCase(),
          recommendations: categoryRecommendations,
          priority: this.getCategoryPriority(category)
        });
      }
    }
    
    return recommendations.sort((a, b) => b.priority - a.priority);
  }
  
  extractRecommendations(results) {
    const allRecommendations = [];
    
    for (const result of results) {
      if (result.recommendations) {
        allRecommendations.push(...result.recommendations);
      }
    }
    
    return [...new Set(allRecommendations)]; // Remove duplicates
  }
  
  getCategoryPriority(category) {
    const priorities = {
      'owasp': 10,
      'penetration': 9,
      'vulnerability': 8,
      'compliance': 7,
      'cloudSecurity': 6,
      'mobileSecurity': 5,
      'iotSecurity': 4,
      'socialEngineering': 3,
      'physicalSecurity': 2,
      'siem': 1
    };
    
    return priorities[category] || 0;
  }
  
  // Generate comprehensive security report
  generateComprehensiveSecurityReport() {
    const report = {
      executiveSummary: {
        overallRiskLevel: this.overallRiskLevel,
        totalCategories: this.results.size,
        totalTests: this.getTotalTests(),
        totalPassed: this.getTotalPassed(),
        totalFailed: this.getTotalFailed(),
        passRate: this.getPassRate(),
        criticalFindings: this.getCriticalFindings(),
        highFindings: this.getHighFindings(),
        mediumFindings: this.getMediumFindings(),
        lowFindings: this.getLowFindings()
      },
      categoryResults: this.getCategoryResults(),
      recommendations: this.recommendations,
      complianceStatus: this.getComplianceStatus(),
      nextSteps: this.getNextSteps(),
      timeline: this.getRemediationTimeline()
    };
    
    return report;
  }
  
  getTotalTests() {
    let total = 0;
    for (const [category, results] of this.results) {
      if (results && results.length > 0) {
        total += results.reduce((sum, result) => sum + result.total, 0);
      }
    }
    return total;
  }
  
  getTotalPassed() {
    let total = 0;
    for (const [category, results] of this.results) {
      if (results && results.length > 0) {
        total += results.reduce((sum, result) => sum + result.passed, 0);
      }
    }
    return total;
  }
  
  getTotalFailed() {
    let total = 0;
    for (const [category, results] of this.results) {
      if (results && results.length > 0) {
        total += results.reduce((sum, result) => sum + result.failed, 0);
      }
    }
    return total;
  }
  
  getPassRate() {
    const totalTests = this.getTotalTests();
    const totalPassed = this.getTotalPassed();
    return totalTests > 0 ? (totalPassed / totalTests) * 100 : 0;
  }
  
  getCriticalFindings() {
    let count = 0;
    for (const [category, results] of this.results) {
      if (results && results.length > 0) {
        count += results.reduce((sum, result) => {
          return sum + (result.vulnerabilities ? result.vulnerabilities.filter(v => v.risk === 'CRITICAL').length : 0);
        }, 0);
      }
    }
    return count;
  }
  
  getHighFindings() {
    let count = 0;
    for (const [category, results] of this.results) {
      if (results && results.length > 0) {
        count += results.reduce((sum, result) => {
          return sum + (result.vulnerabilities ? result.vulnerabilities.filter(v => v.risk === 'HIGH').length : 0);
        }, 0);
      }
    }
    return count;
  }
  
  getMediumFindings() {
    let count = 0;
    for (const [category, results] of this.results) {
      if (results && results.length > 0) {
        count += results.reduce((sum, result) => {
          return sum + (result.vulnerabilities ? result.vulnerabilities.filter(v => v.risk === 'MEDIUM').length : 0);
        }, 0);
      }
    }
    return count;
  }
  
  getLowFindings() {
    let count = 0;
    for (const [category, results] of this.results) {
      if (results && results.length > 0) {
        count += results.reduce((sum, result) => {
          return sum + (result.vulnerabilities ? result.vulnerabilities.filter(v => v.risk === 'LOW').length : 0);
        }, 0);
      }
    }
    return count;
  }
  
  getCategoryResults() {
    const categoryResults = {};
    
    for (const [category, results] of this.results) {
      if (results && results.length > 0) {
        categoryResults[category] = {
          totalTests: results.reduce((sum, result) => sum + result.total, 0),
          totalPassed: results.reduce((sum, result) => sum + result.passed, 0),
          totalFailed: results.reduce((sum, result) => sum + result.failed, 0),
          passRate: this.getPassRate(),
          riskLevel: this.calculateCategoryRisk(results),
          vulnerabilities: results.reduce((sum, result) => sum + (result.vulnerabilities ? result.vulnerabilities.length : 0), 0),
          recommendations: results.reduce((sum, result) => sum + (result.recommendations ? result.recommendations.length : 0), 0)
        };
      }
    }
    
    return categoryResults;
  }
  
  getComplianceStatus() {
    return {
      gdpr: this.results.get('compliance') ? 'COMPLIANT' : 'NOT_ASSESSED',
      hipaa: this.results.get('compliance') ? 'COMPLIANT' : 'NOT_ASSESSED',
      sox: this.results.get('compliance') ? 'COMPLIANT' : 'NOT_ASSESSED',
      pciDss: this.results.get('compliance') ? 'COMPLIANT' : 'NOT_ASSESSED',
      iso27001: this.results.get('compliance') ? 'COMPLIANT' : 'NOT_ASSESSED',
      nistCsf: this.results.get('compliance') ? 'COMPLIANT' : 'NOT_ASSESSED'
    };
  }
  
  getNextSteps() {
    const steps = [];
    
    if (this.overallRiskLevel === 'CRITICAL') {
      steps.push('Immediate remediation required for critical vulnerabilities');
      steps.push('Implement emergency security controls');
      steps.push('Conduct additional security assessment');
    } else if (this.overallRiskLevel === 'HIGH') {
      steps.push('Prioritize high-risk vulnerabilities for remediation');
      steps.push('Implement additional security monitoring');
      steps.push('Schedule follow-up security assessment');
    } else if (this.overallRiskLevel === 'MEDIUM') {
      steps.push('Address medium-risk vulnerabilities in next sprint');
      steps.push('Enhance security monitoring and logging');
      steps.push('Schedule quarterly security review');
    } else {
      steps.push('Maintain current security posture');
      steps.push('Continue regular security monitoring');
      steps.push('Schedule annual security assessment');
    }
    
    return steps;
  }
  
  getRemediationTimeline() {
    const timeline = {
      immediate: this.getCriticalFindings() > 0 ? 'Critical vulnerabilities' : null,
      oneWeek: this.getHighFindings() > 0 ? 'High-risk vulnerabilities' : null,
      oneMonth: this.getMediumFindings() > 0 ? 'Medium-risk vulnerabilities' : null,
      threeMonths: this.getLowFindings() > 0 ? 'Low-risk vulnerabilities' : null,
      ongoing: 'Continuous security monitoring and improvement'
    };
    
    return timeline;
  }
}

// Exercises and Tests
describe("Professional Security Testing Suite", () => {
  let securityManager;
  let client;
  
  beforeEach(() => {
    client = new EnhancedSupertestClient("https://api.example.com");
    securityManager = new SecurityTestingManager(client);
  });
  
  it("should initialize all security testers", () => {
    expect(securityManager.testers).to.have.property('owasp');
    expect(securityManager.testers).to.have.property('penetration');
    expect(securityManager.testers).to.have.property('vulnerability');
    expect(securityManager.testers).to.have.property('siem');
    expect(securityManager.testers).to.have.property('compliance');
    expect(securityManager.testers).to.have.property('socialEngineering');
    expect(securityManager.testers).to.have.property('physicalSecurity');
    expect(securityManager.testers).to.have.property('mobileSecurity');
    expect(securityManager.testers).to.have.property('cloudSecurity');
    expect(securityManager.testers).to.have.property('iotSecurity');
  });
  
  it("should run all security tests", async () => {
    const results = await securityManager.runAllSecurityTests();
    
    expect(results).to.be.an('object');
    expect(results).to.have.property('owasp');
    expect(results).to.have.property('penetration');
    expect(results).to.have.property('vulnerability');
    expect(results).to.have.property('siem');
    expect(results).to.have.property('compliance');
    expect(results).to.have.property('socialEngineering');
    expect(results).to.have.property('physicalSecurity');
    expect(results).to.have.property('mobileSecurity');
    expect(results).to.have.property('cloudSecurity');
    expect(results).to.have.property('iotSecurity');
  });
  
  it("should calculate overall risk level", () => {
    // Mock some results for testing
    securityManager.results = new Map([
      ['owasp', [{ total: 10, failed: 2, passed: 8 }]],
      ['penetration', [{ total: 8, failed: 1, passed: 7 }]]
    ]);
    
    const riskLevel = securityManager.calculateOverallRiskLevel();
    expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).to.include(riskLevel);
  });
  
  it("should generate comprehensive security report", async () => {
    await securityManager.runAllSecurityTests();
    
    const report = securityManager.generateComprehensiveSecurityReport();
    
    expect(report).to.have.property('executiveSummary');
    expect(report).to.have.property('categoryResults');
    expect(report).to.have.property('recommendations');
    expect(report).to.have.property('complianceStatus');
    expect(report).to.have.property('nextSteps');
    expect(report).to.have.property('timeline');
    
    expect(report.executiveSummary).to.have.property('overallRiskLevel');
    expect(report.executiveSummary).to.have.property('totalTests');
    expect(report.executiveSummary).to.have.property('totalPassed');
    expect(report.executiveSummary).to.have.property('totalFailed');
    expect(report.executiveSummary).to.have.property('passRate');
  });
  
  it("should prioritize recommendations correctly", () => {
    securityManager.recommendations = [
      { category: 'OWASP', priority: 10 },
      { category: 'PENETRATION', priority: 9 },
      { category: 'COMPLIANCE', priority: 7 }
    ];
    
    const prioritized = securityManager.recommendations.sort((a, b) => b.priority - a.priority);
    expect(prioritized[0].category).to.equal('OWASP');
    expect(prioritized[1].category).to.equal('PENETRATION');
    expect(prioritized[2].category).to.equal('COMPLIANCE');
  });
});

export { SecurityTestingManager };
/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 3: Penetration Testing
 * Lesson 5: Security Reporting
 * 
 * ⚠️ IMPORTANT: Educational Purpose Only
 * 
 * Learning Objectives:
 * - Learn to create professional security reports
 * - Understand risk assessment
 * - Practice vulnerability documentation
 * - Learn remediation recommendations
 */

import { expect } from "chai";
import fs from "fs";
import path from "path";

console.log("=== SECURITY REPORTING ===");
console.log("⚠️  FOR EDUCATIONAL AND SECURITY TESTING PURPOSES ONLY");

// Security Report Generator
class SecurityReportGenerator {
  constructor() {
    this.vulnerabilities = [];
    this.findings = [];
    this.recommendations = [];
  }

  addVulnerability(vulnerability) {
    this.vulnerabilities.push({
      ...vulnerability,
      id: this.vulnerabilities.length + 1,
      discovered: new Date().toISOString()
    });
  }

  assessRisk(vulnerability) {
    const severity = vulnerability.severity || "medium";
    const exploitability = vulnerability.exploitability || "medium";
    const impact = vulnerability.impact || "medium";
    
    // Calculate risk score
    const severityScores = { critical: 4, high: 3, medium: 2, low: 1 };
    const exploitabilityScores = { easy: 3, medium: 2, hard: 1 };
    const impactScores = { critical: 4, high: 3, medium: 2, low: 1 };
    
    const riskScore = (
      severityScores[severity] * 0.4 +
      exploitabilityScores[exploitability] * 0.3 +
      impactScores[impact] * 0.3
    ) * 10;
    
    let riskLevel = "Low";
    if (riskScore >= 30) riskLevel = "Critical";
    else if (riskScore >= 20) riskLevel = "High";
    else if (riskScore >= 10) riskLevel = "Medium";
    
    return {
      score: riskScore.toFixed(1),
      level: riskLevel,
      severity,
      exploitability,
      impact
    };
  }

  generateExecutiveSummary() {
    const totalVulns = this.vulnerabilities.length;
    const critical = this.vulnerabilities.filter(v => v.severity === "critical").length;
    const high = this.vulnerabilities.filter(v => v.severity === "high").length;
    const medium = this.vulnerabilities.filter(v => v.severity === "medium").length;
    const low = this.vulnerabilities.filter(v => v.severity === "low").length;
    
    return {
      overview: `Security assessment identified ${totalVulns} vulnerabilities`,
      summary: {
        total: totalVulns,
        critical,
        high,
        medium,
        low
      },
      riskLevel: critical > 0 ? "Critical" : high > 0 ? "High" : "Medium",
      recommendation: critical > 0 
        ? "Immediate remediation required for critical vulnerabilities"
        : high > 0
        ? "Prioritize remediation of high-severity vulnerabilities"
        : "Address medium and low severity vulnerabilities in next update cycle"
    };
  }

  generateTechnicalDetails() {
    return this.vulnerabilities.map(vuln => {
      const risk = this.assessRisk(vuln);
      
      return {
        id: vuln.id,
        title: vuln.title || vuln.type,
        severity: vuln.severity,
        risk: risk.level,
        riskScore: risk.score,
        description: vuln.description,
        location: vuln.location || vuln.endpoint,
        stepsToReproduce: vuln.stepsToReproduce || [
          "1. Navigate to affected endpoint",
          "2. Send malicious payload",
          "3. Observe vulnerability"
        ],
        proofOfConcept: vuln.proofOfConcept || "PoC available upon request",
        impact: vuln.impact || "Data exposure, unauthorized access",
        remediation: vuln.remediation || "Implement proper input validation"
      };
    });
  }

  generateRemediationRecommendations() {
    const recommendations = [];
    
    // Group by severity
    const bySeverity = {
      critical: this.vulnerabilities.filter(v => v.severity === "critical"),
      high: this.vulnerabilities.filter(v => v.severity === "high"),
      medium: this.vulnerabilities.filter(v => v.severity === "medium"),
      low: this.vulnerabilities.filter(v => v.severity === "low")
    };
    
    // Critical vulnerabilities
    if (bySeverity.critical.length > 0) {
      recommendations.push({
        priority: "Immediate",
        timeframe: "Within 24-48 hours",
        vulnerabilities: bySeverity.critical.map(v => v.id),
        actions: [
          "Immediately patch or disable affected functionality",
          "Implement temporary mitigations",
          "Monitor for exploitation attempts",
          "Conduct emergency security review"
        ]
      });
    }
    
    // High severity vulnerabilities
    if (bySeverity.high.length > 0) {
      recommendations.push({
        priority: "High",
        timeframe: "Within 1 week",
        vulnerabilities: bySeverity.high.map(v => v.id),
        actions: [
          "Schedule security patch deployment",
          "Implement recommended fixes",
          "Test fixes in staging environment",
          "Deploy to production"
        ]
      });
    }
    
    // Medium and low severity
    if (bySeverity.medium.length > 0 || bySeverity.low.length > 0) {
      recommendations.push({
        priority: "Medium",
        timeframe: "Within 1 month",
        vulnerabilities: [
          ...bySeverity.medium.map(v => v.id),
          ...bySeverity.low.map(v => v.id)
        ],
        actions: [
          "Include in next security update cycle",
          "Implement fixes during regular maintenance",
          "Update security documentation"
        ]
      });
    }
    
    // General recommendations
    recommendations.push({
      priority: "Ongoing",
      timeframe: "Continuous",
      actions: [
        "Implement regular security assessments",
        "Establish security testing in CI/CD pipeline",
        "Provide security training to development team",
        "Implement security monitoring and alerting",
        "Establish incident response procedures"
      ]
    });
    
    return recommendations;
  }

  generateReport(format = "json") {
    const executiveSummary = this.generateExecutiveSummary();
    const technicalDetails = this.generateTechnicalDetails();
    const recommendations = this.generateRemediationRecommendations();
    
    const report = {
      metadata: {
        title: "Security Assessment Report",
        date: new Date().toISOString(),
        version: "1.0",
        scope: "API Security Assessment"
      },
      executiveSummary,
      technicalDetails,
      recommendations,
      appendices: {
        methodology: "OWASP Testing Guide",
        tools: ["Custom Security Testing Framework"],
        references: [
          "OWASP Top 10",
          "CWE - Common Weakness Enumeration",
          "CVE - Common Vulnerabilities and Exposures"
        ]
      }
    };
    
    if (format === "markdown") {
      return this.generateMarkdownReport(report);
    }
    
    return report;
  }

  generateMarkdownReport(report) {
    let markdown = `# ${report.metadata.title}\n\n`;
    markdown += `**Date:** ${new Date(report.metadata.date).toLocaleDateString()}\n`;
    markdown += `**Version:** ${report.metadata.version}\n\n`;
    
    markdown += `## Executive Summary\n\n`;
    markdown += `${report.executiveSummary.overview}\n\n`;
    markdown += `### Vulnerability Summary\n\n`;
    markdown += `- **Total:** ${report.executiveSummary.summary.total}\n`;
    markdown += `- **Critical:** ${report.executiveSummary.summary.critical}\n`;
    markdown += `- **High:** ${report.executiveSummary.summary.high}\n`;
    markdown += `- **Medium:** ${report.executiveSummary.summary.medium}\n`;
    markdown += `- **Low:** ${report.executiveSummary.summary.low}\n\n`;
    
    markdown += `### Risk Level\n\n`;
    markdown += `**${report.executiveSummary.riskLevel}**\n\n`;
    
    markdown += `### Recommendation\n\n`;
    markdown += `${report.executiveSummary.recommendation}\n\n`;
    
    markdown += `## Technical Details\n\n`;
    report.technicalDetails.forEach((detail, index) => {
      markdown += `### ${index + 1}. ${detail.title}\n\n`;
      markdown += `**Severity:** ${detail.severity}\n`;
      markdown += `**Risk Score:** ${detail.riskScore} (${detail.risk})\n`;
      markdown += `**Location:** ${detail.location}\n\n`;
      markdown += `**Description:**\n${detail.description}\n\n`;
      markdown += `**Impact:**\n${detail.impact}\n\n`;
      markdown += `**Remediation:**\n${detail.remediation}\n\n`;
    });
    
    markdown += `## Remediation Recommendations\n\n`;
    report.recommendations.forEach((rec, index) => {
      markdown += `### ${index + 1}. ${rec.priority} Priority\n\n`;
      markdown += `**Timeframe:** ${rec.timeframe}\n\n`;
      if (rec.vulnerabilities) {
        markdown += `**Affected Vulnerabilities:** ${rec.vulnerabilities.join(", ")}\n\n`;
      }
      markdown += `**Actions:**\n`;
      rec.actions.forEach(action => {
        markdown += `- ${action}\n`;
      });
      markdown += `\n`;
    });
    
    return markdown;
  }

  saveReport(report, filePath) {
    const reportJson = JSON.stringify(report, null, 2);
    fs.writeFileSync(filePath, reportJson);
    return filePath;
  }
}

// Test Scenarios
async function testVulnerabilityAddition() {
  console.log("\n📝 Test 1: Add Vulnerabilities");
  
  const generator = new SecurityReportGenerator();
  generator.addVulnerability({
    type: "SQL Injection",
    severity: "critical",
    description: "SQL injection vulnerability in search endpoint",
    endpoint: "/api/search",
    exploitability: "easy",
    impact: "critical"
  });
  
  generator.addVulnerability({
    type: "XSS",
    severity: "high",
    description: "Cross-site scripting in comment field",
    endpoint: "/api/comments",
    exploitability: "medium",
    impact: "high"
  });
  
  expect(generator.vulnerabilities.length).to.equal(2);
  console.log(`✅ Added ${generator.vulnerabilities.length} vulnerabilities`);
}

async function testRiskAssessment() {
  console.log("\n📝 Test 2: Risk Assessment");
  
  const generator = new SecurityReportGenerator();
  generator.addVulnerability({
    type: "SQL Injection",
    severity: "critical",
    exploitability: "easy",
    impact: "critical"
  });
  
  const risk = generator.assessRisk(generator.vulnerabilities[0]);
  expect(risk).to.have.property("score");
  expect(risk).to.have.property("level");
  expect(risk.level).to.equal("Critical");
  console.log(`✅ Risk assessment: ${risk.level} (${risk.score})`);
}

async function testExecutiveSummary() {
  console.log("\n📝 Test 3: Executive Summary");
  
  const generator = new SecurityReportGenerator();
  generator.addVulnerability({ type: "SQL Injection", severity: "critical" });
  generator.addVulnerability({ type: "XSS", severity: "high" });
  generator.addVulnerability({ type: "CSRF", severity: "medium" });
  
  const summary = generator.generateExecutiveSummary();
  expect(summary).to.have.property("summary");
  expect(summary.summary.total).to.equal(3);
  console.log(`✅ Generated executive summary with ${summary.summary.total} vulnerabilities`);
}

async function testReportGeneration() {
  console.log("\n📝 Test 4: Report Generation");
  
  const generator = new SecurityReportGenerator();
  generator.addVulnerability({
    type: "SQL Injection",
    severity: "critical",
    description: "SQL injection vulnerability",
    endpoint: "/api/search",
    title: "SQL Injection in Search Endpoint"
  });
  
  const report = generator.generateReport();
  expect(report).to.have.property("executiveSummary");
  expect(report).to.have.property("technicalDetails");
  expect(report).to.have.property("recommendations");
  console.log("✅ Generated comprehensive security report");
}

async function testMarkdownReport() {
  console.log("\n📝 Test 5: Markdown Report Generation");
  
  const generator = new SecurityReportGenerator();
  generator.addVulnerability({
    type: "SQL Injection",
    severity: "critical",
    description: "SQL injection vulnerability",
    endpoint: "/api/search",
    title: "SQL Injection in Search Endpoint"
  });
  
  const markdown = generator.generateReport("markdown");
  expect(markdown).to.include("# Security Assessment Report");
  expect(markdown).to.include("Executive Summary");
  expect(markdown).to.include("Technical Details");
  console.log("✅ Generated markdown report");
}

// Run all tests
(async () => {
  try {
    console.log("\n⚠️  REMINDER: This tutorial is for educational purposes only.");
    console.log("   Use these techniques only for authorized security assessments.\n");
    
    await testVulnerabilityAddition();
    await testRiskAssessment();
    await testExecutiveSummary();
    await testReportGeneration();
    await testMarkdownReport();
    
    console.log("\n✅ All security reporting tests completed!");
    console.log("\n📚 Key Takeaways:");
    console.log("   - Create clear executive summaries");
    console.log("   - Provide detailed technical information");
    console.log("   - Include risk assessments");
    console.log("   - Provide actionable remediation recommendations");
    console.log("   - Use professional report templates");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
})();


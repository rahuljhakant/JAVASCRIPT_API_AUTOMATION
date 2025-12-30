/**
 * PHASE 5: EXPERT LEVEL
 * Module 2: Advanced Reporting
 * Lesson 1: Custom Reporting
 * 
 * Learning Objectives:
 * - Create custom test reports
 * - Generate comprehensive test analytics
 * - Implement interactive dashboards
 * - Export reports in multiple formats
 */

import { expect } from "chai";
import supertest from "supertest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== ADVANCED REPORTING ===");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = getApiToken();

// Report Generator
class ReportGenerator {
  constructor(outputDir) {
    this.outputDir = outputDir;
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    this.testResults = [];
  }

  addTestResult(result) {
    this.testResults.push({
      ...result,
      timestamp: result.timestamp || Date.now()
    });
  }

  generateHTMLReport() {
    const total = this.testResults.length;
    const passed = this.testResults.filter(r => r.passed).length;
    const failed = total - passed;
    const duration = this.testResults.reduce((sum, r) => sum + (r.duration || 0), 0);

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
        }
        .stat-card {
            text-align: center;
            padding: 20px;
            background: #f9f9f9;
            border-radius: 8px;
        }
        .stat-value {
            font-size: 36px;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            color: #666;
            margin-top: 10px;
        }
        .passed { color: #4CAF50; }
        .failed { color: #f44336; }
        .results {
            padding: 30px;
        }
        .test-result {
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
            border-left: 4px solid;
        }
        .test-result.passed {
            background: #e8f5e9;
            border-color: #4CAF50;
        }
        .test-result.failed {
            background: #ffebee;
            border-color: #f44336;
        }
        .test-name {
            font-weight: bold;
            margin-bottom: 5px;
        }
        .test-details {
            color: #666;
            font-size: 14px;
        }
        .chart-container {
            padding: 30px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Test Execution Report</h1>
            <p>Generated: ${new Date().toLocaleString()}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">${total}</div>
                <div class="stat-label">Total Tests</div>
            </div>
            <div class="stat-card">
                <div class="stat-value passed">${passed}</div>
                <div class="stat-label">Passed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value failed">${failed}</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${(duration / 1000).toFixed(2)}s</div>
                <div class="stat-label">Total Duration</div>
            </div>
        </div>
        
        <div class="results">
            <h2>Test Results</h2>
            ${this.testResults.map(result => `
                <div class="test-result ${result.passed ? 'passed' : 'failed'}">
                    <div class="test-name">${result.name}</div>
                    <div class="test-details">
                        Duration: ${result.duration || 0}ms | 
                        Status: ${result.passed ? '✅ Passed' : '❌ Failed'}
                        ${result.error ? ` | Error: ${result.error}` : ''}
                    </div>
                </div>
            `).join('')}
        </div>
    </div>
</body>
</html>
    `;

    const filePath = path.join(this.outputDir, "test-report.html");
    fs.writeFileSync(filePath, html);
    return filePath;
  }

  generateJSONReport() {
    const report = {
      summary: {
        total: this.testResults.length,
        passed: this.testResults.filter(r => r.passed).length,
        failed: this.testResults.filter(r => !r.passed).length,
        duration: this.testResults.reduce((sum, r) => sum + (r.duration || 0), 0),
        timestamp: Date.now()
      },
      results: this.testResults
    };

    const filePath = path.join(this.outputDir, "test-report.json");
    fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
    return filePath;
  }

  generateCSVReport() {
    const headers = ["Test Name", "Status", "Duration (ms)", "Error", "Timestamp"];
    const rows = this.testResults.map(r => [
      r.name,
      r.passed ? "PASSED" : "FAILED",
      r.duration || 0,
      r.error || "",
      new Date(r.timestamp).toISOString()
    ]);

    const csv = [
      headers.join(","),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(","))
    ].join("\n");

    const filePath = path.join(this.outputDir, "test-report.csv");
    fs.writeFileSync(filePath, csv);
    return filePath;
  }
}

// Analytics Generator
class AnalyticsGenerator {
  constructor(testResults) {
    this.testResults = testResults;
  }

  calculateMetrics() {
    const total = this.testResults.length;
    const passed = this.testResults.filter(r => r.passed).length;
    const failed = total - passed;
    const durations = this.testResults.map(r => r.duration || 0).filter(d => d > 0);

    return {
      total,
      passed,
      failed,
      passRate: total > 0 ? (passed / total) * 100 : 0,
      averageDuration: durations.length > 0
        ? durations.reduce((a, b) => a + b, 0) / durations.length
        : 0,
      minDuration: durations.length > 0 ? Math.min(...durations) : 0,
      maxDuration: durations.length > 0 ? Math.max(...durations) : 0,
      medianDuration: this.calculateMedian(durations)
    };
  }

  calculateMedian(values) {
    if (values.length === 0) return 0;
    const sorted = [...values].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 === 0
      ? (sorted[mid - 1] + sorted[mid]) / 2
      : sorted[mid];
  }

  generateTrendAnalysis() {
    // Group by time periods (hourly for demo)
    const grouped = {};
    this.testResults.forEach(result => {
      const hour = new Date(result.timestamp).getHours();
      if (!grouped[hour]) {
        grouped[hour] = { passed: 0, failed: 0 };
      }
      if (result.passed) {
        grouped[hour].passed++;
      } else {
        grouped[hour].failed++;
      }
    });

    return grouped;
  }
}

// Test Scenarios
async function testReportGeneration() {
  console.log("\n📝 Test 1: Report Generation");
  
  const reportDir = path.join(__dirname, "../../../reports");
  const generator = new ReportGenerator(reportDir);
  
  // Add sample test results
  generator.addTestResult({
    name: "User Creation Test",
    passed: true,
    duration: 150
  });
  
  generator.addTestResult({
    name: "User Update Test",
    passed: true,
    duration: 200
  });
  
  generator.addTestResult({
    name: "User Deletion Test",
    passed: false,
    duration: 100,
    error: "User not found"
  });
  
  // Generate reports
  const htmlPath = generator.generateHTMLReport();
  const jsonPath = generator.generateJSONReport();
  const csvPath = generator.generateCSVReport();
  
  expect(fs.existsSync(htmlPath)).to.be.true;
  expect(fs.existsSync(jsonPath)).to.be.true;
  expect(fs.existsSync(csvPath)).to.be.true;
  
  console.log(`✅ HTML report: ${htmlPath}`);
  console.log(`✅ JSON report: ${jsonPath}`);
  console.log(`✅ CSV report: ${csvPath}`);
}

async function testAnalytics() {
  console.log("\n📝 Test 2: Analytics Generation");
  
  const testResults = [
    { name: "Test 1", passed: true, duration: 100, timestamp: Date.now() },
    { name: "Test 2", passed: true, duration: 150, timestamp: Date.now() },
    { name: "Test 3", passed: false, duration: 200, timestamp: Date.now() }
  ];
  
  const analytics = new AnalyticsGenerator(testResults);
  const metrics = analytics.calculateMetrics();
  
  expect(metrics.total).to.equal(3);
  expect(metrics.passed).to.equal(2);
  expect(metrics.failed).to.equal(1);
  expect(metrics.passRate).to.be.closeTo(66.67, 0.01);
  
  const trends = analytics.generateTrendAnalysis();
  console.log("📊 Metrics:", metrics);
  console.log("📈 Trends:", trends);
  
  console.log("✅ Analytics test passed");
}

async function testRealAPITestReport() {
  console.log("\n📝 Test 3: Real API Test Report");
  
  const reportDir = path.join(__dirname, "../../../reports");
  const generator = new ReportGenerator(reportDir);
  
  // Run actual API test
  const startTime = Date.now();
  try {
    const response = await request
      .get("/users")
      .set("Authorization", `Bearer ${TOKEN}`);
    
    const duration = Date.now() - startTime;
    
    generator.addTestResult({
      name: "Get Users API Test",
      passed: response.status === 200,
      duration,
      statusCode: response.status
    });
  } catch (error) {
    const duration = Date.now() - startTime;
    generator.addTestResult({
      name: "Get Users API Test",
      passed: false,
      duration,
      error: error.message
    });
  }
  
  const htmlPath = generator.generateHTMLReport();
  console.log(`✅ Real API test report generated: ${htmlPath}`);
}

// Run all tests
(async () => {
  try {
    await testReportGeneration();
    await testAnalytics();
    await testRealAPITestReport();
    
    console.log("\n✅ All advanced reporting tests completed!");
  } catch (error) {
    console.error("❌ Reporting test failed:", error.message);
    process.exit(1);
  }
})();


/**
 * PHASE 4: PROFESSIONAL LEVEL
 * Module 5: Monitoring & Alerting
 * Lesson 1: Monitoring Setup
 * 
 * Learning Objectives:
 * - Set up monitoring for API tests
 * - Implement health checks and metrics collection
 * - Create alerting rules for test failures
 * - Integrate with monitoring tools (Prometheus, Grafana)
 */

import { expect } from "chai";
import supertest from "supertest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== MONITORING & ALERTING ===");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = getApiToken();

// Metrics Collector
class MetricsCollector {
  constructor() {
    this.metrics = {
      requests: [],
      errors: [],
      responseTimes: [],
      testResults: []
    };
  }

  recordRequest(endpoint, method, statusCode, responseTime, success) {
    const metric = {
      timestamp: Date.now(),
      endpoint,
      method,
      statusCode,
      responseTime,
      success
    };

    this.metrics.requests.push(metric);
    this.metrics.responseTimes.push(responseTime);

    if (!success) {
      this.metrics.errors.push(metric);
    }
  }

  recordTestResult(testName, passed, duration, error = null) {
    this.metrics.testResults.push({
      timestamp: Date.now(),
      testName,
      passed,
      duration,
      error: error?.message
    });
  }

  getMetrics() {
    const totalRequests = this.metrics.requests.length;
    const successfulRequests = this.metrics.requests.filter(r => r.success).length;
    const failedRequests = totalRequests - successfulRequests;
    const avgResponseTime = this.metrics.responseTimes.length > 0
      ? this.metrics.responseTimes.reduce((a, b) => a + b, 0) / this.metrics.responseTimes.length
      : 0;

    return {
      totalRequests,
      successfulRequests,
      failedRequests,
      successRate: totalRequests > 0 ? (successfulRequests / totalRequests) * 100 : 0,
      averageResponseTime: avgResponseTime,
      minResponseTime: this.metrics.responseTimes.length > 0 ? Math.min(...this.metrics.responseTimes) : 0,
      maxResponseTime: this.metrics.responseTimes.length > 0 ? Math.max(...this.metrics.responseTimes) : 0,
      errorCount: this.metrics.errors.length,
      testPassRate: this.metrics.testResults.length > 0
        ? (this.metrics.testResults.filter(t => t.passed).length / this.metrics.testResults.length) * 100
        : 0
    };
  }

  exportPrometheusFormat() {
    const metrics = this.getMetrics();
    const timestamp = Date.now();

    return `
# HELP api_requests_total Total number of API requests
# TYPE api_requests_total counter
api_requests_total ${metrics.totalRequests} ${timestamp}

# HELP api_requests_successful_total Total number of successful API requests
# TYPE api_requests_successful_total counter
api_requests_successful_total ${metrics.successfulRequests} ${timestamp}

# HELP api_requests_failed_total Total number of failed API requests
# TYPE api_requests_failed_total counter
api_requests_failed_total ${metrics.failedRequests} ${timestamp}

# HELP api_response_time_seconds Average response time in seconds
# TYPE api_response_time_seconds gauge
api_response_time_seconds ${metrics.averageResponseTime / 1000} ${timestamp}

# HELP api_test_pass_rate Test pass rate percentage
# TYPE api_test_pass_rate gauge
api_test_pass_rate ${metrics.testPassRate} ${timestamp}
`;
  }
}

// Health Check Monitor
class HealthCheckMonitor {
  constructor(apiClient, authToken) {
    this.apiClient = apiClient;
    this.authToken = authToken;
    this.healthChecks = [];
  }

  async performHealthCheck(name, endpoint, expectedStatus = 200) {
    const startTime = Date.now();
    
    try {
      const response = await this.apiClient
        .get(endpoint)
        .set("Authorization", `Bearer ${this.authToken}`)
        .timeout(5000);

      const responseTime = Date.now() - startTime;
      const healthy = response.status === expectedStatus && responseTime < 3000;

      const healthCheck = {
        name,
        endpoint,
        timestamp: Date.now(),
        healthy,
        statusCode: response.status,
        responseTime,
        message: healthy ? "Healthy" : "Unhealthy"
      };

      this.healthChecks.push(healthCheck);
      return healthCheck;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      const healthCheck = {
        name,
        endpoint,
        timestamp: Date.now(),
        healthy: false,
        statusCode: 0,
        responseTime,
        message: error.message
      };

      this.healthChecks.push(healthCheck);
      return healthCheck;
    }
  }

  getHealthStatus() {
    const healthy = this.healthChecks.filter(h => h.healthy).length;
    const total = this.healthChecks.length;
    
    return {
      overall: healthy === total && total > 0,
      healthyCount: healthy,
      totalCount: total,
      healthRate: total > 0 ? (healthy / total) * 100 : 0,
      checks: this.healthChecks
    };
  }
}

// Alert Manager
class AlertManager {
  constructor() {
    this.alerts = [];
    this.rules = [];
  }

  addRule(name, condition, severity = "warning") {
    this.rules.push({
      name,
      condition,
      severity,
      triggered: false
    });
  }

  checkAlerts(metrics, healthStatus) {
    const newAlerts = [];

    for (const rule of this.rules) {
      let shouldAlert = false;

      switch (rule.name) {
        case "high_error_rate":
          shouldAlert = metrics.successRate < 95;
          break;
        case "slow_response":
          shouldAlert = metrics.averageResponseTime > 2000;
          break;
        case "test_failures":
          shouldAlert = metrics.testPassRate < 90;
          break;
        case "unhealthy_service":
          shouldAlert = !healthStatus.overall;
          break;
        default:
          shouldAlert = rule.condition(metrics, healthStatus);
      }

      if (shouldAlert && !rule.triggered) {
        rule.triggered = true;
        const alert = {
          name: rule.name,
          severity: rule.severity,
          message: this.getAlertMessage(rule.name, metrics, healthStatus),
          timestamp: Date.now()
        };
        this.alerts.push(alert);
        newAlerts.push(alert);
      } else if (!shouldAlert) {
        rule.triggered = false;
      }
    }

    return newAlerts;
  }

  getAlertMessage(ruleName, metrics, healthStatus) {
    const messages = {
      high_error_rate: `High error rate detected: ${(100 - metrics.successRate).toFixed(2)}%`,
      slow_response: `Slow response time: ${metrics.averageResponseTime.toFixed(2)}ms`,
      test_failures: `Low test pass rate: ${metrics.testPassRate.toFixed(2)}%`,
      unhealthy_service: `Service unhealthy: ${healthStatus.healthRate.toFixed(2)}% health rate`
    };

    return messages[ruleName] || "Alert triggered";
  }

  getAlerts() {
    return this.alerts;
  }
}

// Monitoring Dashboard Generator
class MonitoringDashboard {
  constructor(outputDir) {
    this.outputDir = outputDir;
  }

  generateHTMLDashboard(metrics, healthStatus, alerts) {
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Monitoring Dashboard</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .dashboard {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .metric-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .metric-value {
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
        }
        .metric-label {
            color: #666;
            margin-top: 5px;
        }
        .alert {
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
            border-left: 4px solid;
        }
        .alert-warning {
            background: #fff3cd;
            border-color: #ffc107;
        }
        .alert-error {
            background: #f8d7da;
            border-color: #dc3545;
        }
        .health-status {
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .healthy {
            background: #d4edda;
            border: 1px solid #c3e6cb;
        }
        .unhealthy {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>API Monitoring Dashboard</h1>
            <p>Last updated: ${new Date().toLocaleString()}</p>
        </div>
        
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">${metrics.totalRequests}</div>
                <div class="metric-label">Total Requests</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${metrics.successRate.toFixed(2)}%</div>
                <div class="metric-label">Success Rate</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${metrics.averageResponseTime.toFixed(0)}ms</div>
                <div class="metric-label">Avg Response Time</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${metrics.testPassRate.toFixed(2)}%</div>
                <div class="metric-label">Test Pass Rate</div>
            </div>
        </div>
        
        <div class="health-status ${healthStatus.overall ? 'healthy' : 'unhealthy'}">
            <h2>Health Status: ${healthStatus.overall ? '✅ Healthy' : '❌ Unhealthy'}</h2>
            <p>Health Rate: ${healthStatus.healthRate.toFixed(2)}%</p>
        </div>
        
        ${alerts.length > 0 ? `
        <div>
            <h2>Active Alerts (${alerts.length})</h2>
            ${alerts.map(alert => `
                <div class="alert alert-${alert.severity === 'critical' ? 'error' : 'warning'}">
                    <strong>${alert.name}</strong>: ${alert.message}
                </div>
            `).join('')}
        </div>
        ` : '<div><h2>✅ No Active Alerts</h2></div>'}
    </div>
</body>
</html>
    `;

    const filePath = path.join(this.outputDir, "monitoring-dashboard.html");
    fs.writeFileSync(filePath, html);
    return filePath;
  }
}

// Test Scenarios
async function testMetricsCollection() {
  console.log("\n📝 Test 1: Metrics Collection");
  
  const collector = new MetricsCollector();
  
  // Simulate some requests
  collector.recordRequest("/users", "GET", 200, 150, true);
  collector.recordRequest("/users", "GET", 200, 200, true);
  collector.recordRequest("/users", "POST", 201, 300, true);
  collector.recordRequest("/users", "GET", 500, 100, false);
  
  collector.recordTestResult("test1", true, 150);
  collector.recordTestResult("test2", true, 200);
  collector.recordTestResult("test3", false, 100, new Error("Test failed"));
  
  const metrics = collector.getMetrics();
  
  expect(metrics.totalRequests).to.equal(4);
  expect(metrics.successfulRequests).to.equal(3);
  expect(metrics.failedRequests).to.equal(1);
  
  console.log("📊 Metrics:", metrics);
  console.log("✅ Metrics collection test passed");
}

async function testHealthMonitoring() {
  console.log("\n📝 Test 2: Health Check Monitoring");
  
  const monitor = new HealthCheckMonitor(request, TOKEN);
  
  const healthCheck = await monitor.performHealthCheck(
    "Users API",
    "/users",
    200
  );
  
  expect(healthCheck).to.have.property("healthy");
  expect(healthCheck).to.have.property("responseTime");
  
  const status = monitor.getHealthStatus();
  console.log("🏥 Health Status:", status);
  
  console.log("✅ Health monitoring test passed");
}

async function testAlerting() {
  console.log("\n📝 Test 3: Alert Management");
  
  const alertManager = new AlertManager();
  
  alertManager.addRule("high_error_rate", null, "critical");
  alertManager.addRule("slow_response", null, "warning");
  alertManager.addRule("test_failures", null, "warning");
  
  const metrics = {
    successRate: 90, // Below 95% threshold
    averageResponseTime: 2500, // Above 2000ms threshold
    testPassRate: 85 // Below 90% threshold
  };
  
  const healthStatus = {
    overall: true,
    healthRate: 100
  };
  
  const alerts = alertManager.checkAlerts(metrics, healthStatus);
  
  expect(alerts.length).to.be.greaterThan(0);
  console.log("🚨 Alerts triggered:", alerts);
  
  console.log("✅ Alerting test passed");
}

async function testDashboardGeneration() {
  console.log("\n📝 Test 4: Dashboard Generation");
  
  const dashboardDir = path.join(__dirname, "../../../monitoring");
  if (!fs.existsSync(dashboardDir)) {
    fs.mkdirSync(dashboardDir, { recursive: true });
  }
  
  const collector = new MetricsCollector();
  collector.recordRequest("/users", "GET", 200, 150, true);
  collector.recordTestResult("test1", true, 150);
  
  const monitor = new HealthCheckMonitor(request, TOKEN);
  await monitor.performHealthCheck("Users API", "/users");
  
  const alertManager = new AlertManager();
  alertManager.addRule("test_failures", null, "warning");
  
  const metrics = collector.getMetrics();
  const healthStatus = monitor.getHealthStatus();
  const alerts = alertManager.checkAlerts(metrics, healthStatus);
  
  const dashboard = new MonitoringDashboard(dashboardDir);
  const dashboardPath = dashboard.generateHTMLDashboard(metrics, healthStatus, alerts);
  
  expect(fs.existsSync(dashboardPath)).to.be.true;
  console.log(`✅ Dashboard generated: ${dashboardPath}`);
}

// Run all tests
(async () => {
  try {
    await testMetricsCollection();
    await testHealthMonitoring();
    await testAlerting();
    await testDashboardGeneration();
    
    console.log("\n✅ All monitoring & alerting tests completed!");
  } catch (error) {
    console.error("❌ Monitoring test failed:", error.message);
    process.exit(1);
  }
})();


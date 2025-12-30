/**
 * PHASE 3: ADVANCED LEVEL
 * Module 7: Comprehensive Logging
 * Lesson 1: Advanced Logging
 * 
 * Learning Objectives:
 * - Implement comprehensive logging strategies
 * - Create structured logging for API tests
 * - Implement log levels and filtering
 * - Generate detailed test execution logs
 */

import { expect } from "chai";
import supertest from "supertest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== COMPREHENSIVE LOGGING ===");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = getApiToken();

// Logs Directory
const LOGS_DIR = path.join(__dirname, "../../../logs");
if (!fs.existsSync(LOGS_DIR)) {
  fs.mkdirSync(LOGS_DIR, { recursive: true });
}

// Log Levels
const LogLevel = {
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3,
  FATAL: 4
};

// Advanced Logger
class AdvancedLogger {
  constructor(logFile, logLevel = LogLevel.INFO) {
    this.logFile = logFile;
    this.logLevel = logLevel;
    this.logs = [];
  }

  formatMessage(level, message, metadata = {}) {
    return {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      message,
      ...metadata
    };
  }

  writeLog(level, message, metadata = {}) {
    const logEntry = this.formatMessage(level, message, metadata);
    this.logs.push(logEntry);
    
    // Write to file
    const logLine = JSON.stringify(logEntry) + "\n";
    fs.appendFileSync(this.logFile, logLine);
    
    // Console output with colors
    const colors = {
      DEBUG: "\x1b[36m", // Cyan
      INFO: "\x1b[32m",  // Green
      WARN: "\x1b[33m",  // Yellow
      ERROR: "\x1b[31m", // Red
      FATAL: "\x1b[35m"  // Magenta
    };
    const reset = "\x1b[0m";
    
    if (LogLevel[level] >= this.logLevel) {
      console.log(`${colors[level]}[${level}]${reset} ${message}`, metadata);
    }
  }

  debug(message, metadata) {
    this.writeLog("DEBUG", message, metadata);
  }

  info(message, metadata) {
    this.writeLog("INFO", message, metadata);
  }

  warn(message, metadata) {
    this.writeLog("WARN", message, metadata);
  }

  error(message, metadata) {
    this.writeLog("ERROR", message, metadata);
  }

  fatal(message, metadata) {
    this.writeLog("FATAL", message, metadata);
  }

  getLogs() {
    return this.logs;
  }

  clearLogs() {
    this.logs = [];
    if (fs.existsSync(this.logFile)) {
      fs.writeFileSync(this.logFile, "");
    }
  }
}

// API Request Logger
class APIRequestLogger {
  constructor(logger) {
    this.logger = logger;
  }

  logRequest(method, url, headers, body) {
    this.logger.debug("API Request", {
      method,
      url,
      headers: this.sanitizeHeaders(headers),
      body: this.sanitizeBody(body)
    });
  }

  logResponse(response, responseTime) {
    this.logger.info("API Response", {
      status: response.status,
      statusText: response.statusText,
      responseTime: `${responseTime}ms`,
      headers: this.sanitizeHeaders(response.headers),
      bodySize: JSON.stringify(response.body).length
    });
  }

  logError(error, context) {
    this.logger.error("API Error", {
      message: error.message,
      stack: error.stack,
      context
    });
  }

  sanitizeHeaders(headers) {
    const sanitized = { ...headers };
    if (sanitized.Authorization) {
      sanitized.Authorization = "Bearer ***";
    }
    return sanitized;
  }

  sanitizeBody(body) {
    if (!body) return null;
    const sanitized = { ...body };
    if (sanitized.password) {
      sanitized.password = "***";
    }
    return sanitized;
  }
}

// Test Execution Logger
class TestExecutionLogger {
  constructor(logger) {
    this.logger = logger;
    this.testStartTime = null;
    this.testResults = [];
  }

  startTest(testName) {
    this.testStartTime = Date.now();
    this.logger.info(`Starting test: ${testName}`, { testName });
  }

  endTest(testName, success, error = null) {
    const duration = Date.now() - this.testStartTime;
    const result = {
      testName,
      success,
      duration: `${duration}ms`,
      timestamp: new Date().toISOString()
    };

    if (success) {
      this.logger.info(`Test passed: ${testName}`, result);
    } else {
      this.logger.error(`Test failed: ${testName}`, { ...result, error: error?.message });
    }

    this.testResults.push(result);
    return result;
  }

  getTestSummary() {
    const total = this.testResults.length;
    const passed = this.testResults.filter(r => r.success).length;
    const failed = total - passed;
    const totalDuration = this.testResults.reduce((sum, r) => 
      sum + parseInt(r.duration), 0
    );

    return {
      total,
      passed,
      failed,
      successRate: `${((passed / total) * 100).toFixed(2)}%`,
      totalDuration: `${totalDuration}ms`,
      averageDuration: `${(totalDuration / total).toFixed(2)}ms`
    };
  }
}

// Performance Logger
class PerformanceLogger {
  constructor(logger) {
    this.logger = logger;
    this.metrics = [];
  }

  recordMetric(operation, duration, metadata = {}) {
    const metric = {
      operation,
      duration,
      timestamp: Date.now(),
      ...metadata
    };
    
    this.metrics.push(metric);
    this.logger.debug(`Performance metric: ${operation}`, metric);
    
    return metric;
  }

  getMetrics() {
    return this.metrics;
  }

  getSummary() {
    const grouped = {};
    
    this.metrics.forEach(metric => {
      if (!grouped[metric.operation]) {
        grouped[metric.operation] = {
          count: 0,
          totalDuration: 0,
          min: Infinity,
          max: 0
        };
      }
      
      const group = grouped[metric.operation];
      group.count++;
      group.totalDuration += metric.duration;
      group.min = Math.min(group.min, metric.duration);
      group.max = Math.max(group.max, metric.duration);
    });

    const summary = {};
    Object.keys(grouped).forEach(operation => {
      const group = grouped[operation];
      summary[operation] = {
        count: group.count,
        average: `${(group.totalDuration / group.count).toFixed(2)}ms`,
        min: `${group.min}ms`,
        max: `${group.max}ms`,
        total: `${group.totalDuration}ms`
      };
    });

    return summary;
  }
}

// Test Scenarios with Comprehensive Logging
async function testWithLogging() {
  console.log("\n📝 Test 1: Comprehensive Logging");
  
  const logFile = path.join(LOGS_DIR, `test-${Date.now()}.log`);
  const logger = new AdvancedLogger(logFile, LogLevel.DEBUG);
  const requestLogger = new APIRequestLogger(logger);
  const testLogger = new TestExecutionLogger(logger);
  const perfLogger = new PerformanceLogger(logger);
  
  testLogger.startTest("User Creation Test");
  
  try {
    const startTime = Date.now();
    
    const newUser = {
      name: "Logging Test User",
      email: `loggingtest${Date.now()}@example.com`,
      gender: "male",
      status: "active"
    };
    
    requestLogger.logRequest("POST", "/users", { Authorization: `Bearer ${TOKEN}` }, newUser);
    
    const response = await request
      .post("/users")
      .set("Authorization", `Bearer ${TOKEN}`)
      .send(newUser);
    
    const responseTime = Date.now() - startTime;
    requestLogger.logResponse(response, responseTime);
    perfLogger.recordMetric("create_user", responseTime, { status: response.status });
    
    expect(response.status).to.equal(201);
    const userId = response.body.data.id;
    
    logger.info("User created successfully", { userId, email: newUser.email });
    
    // Get user
    const getStartTime = Date.now();
    requestLogger.logRequest("GET", `/users/${userId}`, { Authorization: `Bearer ${TOKEN}` });
    
    const getResponse = await request
      .get(`/users/${userId}`)
      .set("Authorization", `Bearer ${TOKEN}`);
    
    const getResponseTime = Date.now() - getStartTime;
    requestLogger.logResponse(getResponse, getResponseTime);
    perfLogger.recordMetric("get_user", getResponseTime, { status: getResponse.status });
    
    expect(getResponse.status).to.equal(200);
    
    // Cleanup
    await request
      .delete(`/users/${userId}`)
      .set("Authorization", `Bearer ${TOKEN}`);
    
    logger.info("User deleted successfully", { userId });
    
    testLogger.endTest("User Creation Test", true);
    
  } catch (error) {
    requestLogger.logError(error, { test: "User Creation Test" });
    testLogger.endTest("User Creation Test", false, error);
    throw error;
  }
  
  // Log summary
  const testSummary = testLogger.getTestSummary();
  const perfSummary = perfLogger.getSummary();
  
  logger.info("Test Summary", testSummary);
  logger.info("Performance Summary", perfSummary);
  
  console.log("\n📊 Test Summary:");
  console.table(testSummary);
  console.log("\n⚡ Performance Summary:");
  console.table(perfSummary);
  
  console.log(`\n📄 Full log saved to: ${logFile}`);
}

async function testErrorLogging() {
  console.log("\n📝 Test 2: Error Logging");
  
  const logFile = path.join(LOGS_DIR, `error-test-${Date.now()}.log`);
  const logger = new AdvancedLogger(logFile, LogLevel.DEBUG);
  const requestLogger = new APIRequestLogger(logger);
  
  try {
    // Intentionally create invalid request
    requestLogger.logRequest("POST", "/users", { Authorization: `Bearer ${TOKEN}` }, {
      name: "Invalid User",
      email: "invalid-email" // Invalid email format
    });
    
    const response = await request
      .post("/users")
      .set("Authorization", `Bearer ${TOKEN}`)
      .send({
        name: "Invalid User",
        email: "invalid-email"
      });
    
    requestLogger.logResponse(response, 0);
    
    if (response.status !== 201) {
      logger.warn("Expected validation error occurred", {
        status: response.status,
        errors: response.body.data
      });
    }
    
  } catch (error) {
    requestLogger.logError(error, { test: "Error Logging Test" });
    logger.error("Error test completed", { error: error.message });
  }
  
  console.log(`📄 Error log saved to: ${logFile}`);
}

// Run all tests
(async () => {
  try {
    await testWithLogging();
    await testErrorLogging();
    
    console.log("\n✅ All logging tests completed!");
    console.log(`📁 Logs saved to: ${LOGS_DIR}`);
  } catch (error) {
    console.error("❌ Logging test failed:", error.message);
    process.exit(1);
  }
})();


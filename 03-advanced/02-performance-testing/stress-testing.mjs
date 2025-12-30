/**
 * PHASE 3: ADVANCED LEVEL
 * Module 2: Performance Testing
 * Lesson 2: Stress Testing
 * 
 * Learning Objectives:
 * - Implement stress testing to find breaking points
 * - Test API behavior under extreme load
 * - Identify system limits and failure modes
 * - Analyze recovery patterns
 */

import { expect } from "chai";
import supertest from "supertest";
import { performance } from "perf_hooks";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== STRESS TESTING ===");

const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = getApiToken();

// Stress Test Configuration
class StressTestConfig {
  constructor() {
    this.maxConcurrency = 100;
    this.rampUpRate = 10; // users per second
    this.holdDuration = 30000; // 30 seconds
    this.rampDownRate = 5; // users per second
  }
}

// Stress Test Monitor
class StressTestMonitor {
  constructor() {
    this.metrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      timeouts: 0,
      errors: [],
      responseTimes: [],
      startTime: null,
      endTime: null
    };
  }

  start() {
    this.metrics.startTime = Date.now();
  }

  record(result) {
    this.metrics.totalRequests++;
    
    if (result.success) {
      this.metrics.successfulRequests++;
      this.metrics.responseTimes.push(result.responseTime);
    } else {
      this.metrics.failedRequests++;
      if (result.timeout) {
        this.metrics.timeouts++;
      }
      this.metrics.errors.push(result);
    }
  }

  stop() {
    this.metrics.endTime = Date.now();
  }

  getReport() {
    const duration = (this.metrics.endTime - this.metrics.startTime) / 1000;
    const sortedTimes = [...this.metrics.responseTimes].sort((a, b) => a - b);
    
    return {
      duration: `${duration.toFixed(2)}s`,
      totalRequests: this.metrics.totalRequests,
      successfulRequests: this.metrics.successfulRequests,
      failedRequests: this.metrics.failedRequests,
      successRate: ((this.metrics.successfulRequests / this.metrics.totalRequests) * 100).toFixed(2) + "%",
      timeouts: this.metrics.timeouts,
      averageResponseTime: this.metrics.responseTimes.length > 0 
        ? (this.metrics.responseTimes.reduce((a, b) => a + b, 0) / this.metrics.responseTimes.length).toFixed(2) + "ms"
        : "N/A",
      minResponseTime: sortedTimes.length > 0 ? sortedTimes[0].toFixed(2) + "ms" : "N/A",
      maxResponseTime: sortedTimes.length > 0 ? sortedTimes[sortedTimes.length - 1].toFixed(2) + "ms" : "N/A",
      p95: sortedTimes.length > 0 ? sortedTimes[Math.floor(sortedTimes.length * 0.95)].toFixed(2) + "ms" : "N/A",
      requestsPerSecond: (this.metrics.totalRequests / duration).toFixed(2)
    };
  }
}

// Stress Test Runner
class StressTestRunner {
  constructor(apiClient, authToken, config) {
    this.apiClient = apiClient;
    this.authToken = authToken;
    this.config = config;
    this.monitor = new StressTestMonitor();
  }

  async makeRequest(endpoint, method = "GET", payload = null, timeout = 10000) {
    const startTime = performance.now();
    
    try {
      const timeoutPromise = new Promise((_, reject) => 
        setTimeout(() => reject(new Error("Request timeout")), timeout)
      );
      
      let req = this.apiClient[method.toLowerCase()](endpoint)
        .set("Authorization", `Bearer ${this.authToken}`);
      
      if (payload) {
        req = req.send(payload);
      }
      
      const response = await Promise.race([req, timeoutPromise]);
      const endTime = performance.now();
      const responseTime = endTime - startTime;
      
      this.monitor.record({
        success: response.status >= 200 && response.status < 300,
        responseTime,
        statusCode: response.status
      });
      
      return response;
    } catch (error) {
      const endTime = performance.now();
      const responseTime = endTime - startTime;
      
      this.monitor.record({
        success: false,
        responseTime,
        timeout: error.message === "Request timeout",
        error: error.message
      });
      
      throw error;
    }
  }

  async rampUp(concurrency, targetConcurrency, rampUpTime) {
    const steps = 10;
    const stepConcurrency = (targetConcurrency - concurrency) / steps;
    const stepDuration = rampUpTime / steps;
    
    for (let step = 0; step < steps; step++) {
      const currentConcurrency = Math.floor(concurrency + (step * stepConcurrency));
      const requests = [];
      
      for (let i = 0; i < currentConcurrency; i++) {
        requests.push(this.makeRequest("/users", "GET"));
      }
      
      await Promise.allSettled(requests);
      await new Promise(resolve => setTimeout(resolve, stepDuration));
    }
  }

  async holdLoad(concurrency, duration) {
    const endTime = Date.now() + duration;
    const requestInterval = 1000 / (concurrency / 10); // Distribute requests evenly
    
    while (Date.now() < endTime) {
      const batch = [];
      for (let i = 0; i < Math.min(concurrency, 10); i++) {
        batch.push(this.makeRequest("/users", "GET"));
      }
      await Promise.allSettled(batch);
      await new Promise(resolve => setTimeout(resolve, requestInterval));
    }
  }

  async runStressTest(endpoint, method, payload) {
    this.monitor.start();
    
    try {
      // Phase 1: Ramp Up
      console.log("📈 Phase 1: Ramping up to maximum load...");
      await this.rampUp(1, this.config.maxConcurrency, 20000);
      
      // Phase 2: Hold at maximum load
      console.log("🔥 Phase 2: Holding at maximum load...");
      await this.holdLoad(this.config.maxConcurrency, this.config.holdDuration);
      
      // Phase 3: Ramp Down
      console.log("📉 Phase 3: Ramping down...");
      await this.rampUp(this.config.maxConcurrency, 1, 10000);
      
    } catch (error) {
      console.error("Stress test error:", error.message);
    } finally {
      this.monitor.stop();
    }
    
    return this.monitor.getReport();
  }
}

// Test Scenarios
async function testStressGetRequests() {
  console.log("\n🔥 Stress Test 1: GET Requests");
  
  const config = new StressTestConfig();
  config.maxConcurrency = 50;
  config.holdDuration = 20000;
  
  const runner = new StressTestRunner(request, TOKEN, config);
  const report = await runner.runStressTest("/users", "GET");
  
  console.log("\n📊 Stress Test Report:");
  console.table(report);
  
  expect(report.totalRequests).to.be.greaterThan(0);
}

async function testStressPostRequests() {
  console.log("\n🔥 Stress Test 2: POST Requests");
  
  const config = new StressTestConfig();
  config.maxConcurrency = 20; // Lower for write operations
  config.holdDuration = 15000;
  
  const runner = new StressTestRunner(request, TOKEN, config);
  const testUser = {
    name: "Stress Test User",
    email: `stresstest${Date.now()}@example.com`,
    gender: "male",
    status: "active"
  };
  
  const report = await runner.runStressTest("/users", "POST", testUser);
  
  console.log("\n📊 Stress Test Report:");
  console.table(report);
  
  expect(report.totalRequests).to.be.greaterThan(0);
}

// Run tests
(async () => {
  try {
    await testStressGetRequests();
    await testStressPostRequests();
    
    console.log("\n✅ All stress tests completed!");
  } catch (error) {
    console.error("❌ Stress test failed:", error.message);
    process.exit(1);
  }
})();


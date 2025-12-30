/**
 * PHASE 3: ADVANCED LEVEL
 * Module 2: Performance Testing
 * Lesson 1: Load Testing
 * 
 * Learning Objectives:
 * - Implement comprehensive load testing scenarios
 * - Measure API response times under load
 * - Identify performance bottlenecks
 * - Analyze throughput and latency metrics
 */

import { expect } from "chai";
import supertest from "supertest";
import { performance } from "perf_hooks";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== LOAD TESTING ===");

// API client setup
const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = getApiToken();

// Performance Metrics Collector
class PerformanceMetrics {
  constructor() {
    this.metrics = {
      requests: [],
      responseTimes: [],
      errors: [],
      throughput: 0,
      p50: 0,
      p95: 0,
      p99: 0
    };
  }

  recordRequest(responseTime, statusCode, success) {
    this.metrics.requests.push({
      responseTime,
      statusCode,
      success,
      timestamp: Date.now()
    });
    this.metrics.responseTimes.push(responseTime);
    
    if (!success) {
      this.metrics.errors.push({
        statusCode,
        responseTime,
        timestamp: Date.now()
      });
    }
  }

  calculatePercentile(percentile) {
    const sorted = [...this.metrics.responseTimes].sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * sorted.length) - 1;
    return sorted[index] || 0;
  }

  calculateMetrics() {
    const totalRequests = this.metrics.requests.length;
    const successfulRequests = this.metrics.requests.filter(r => r.success).length;
    const totalTime = this.metrics.responseTimes.reduce((a, b) => a + b, 0);
    
    this.metrics.throughput = totalRequests / (totalTime / 1000); // requests per second
    this.metrics.p50 = this.calculatePercentile(50);
    this.metrics.p95 = this.calculatePercentile(95);
    this.metrics.p99 = this.calculatePercentile(99);
    
    return {
      totalRequests,
      successfulRequests,
      failedRequests: totalRequests - successfulRequests,
      successRate: (successfulRequests / totalRequests) * 100,
      averageResponseTime: totalTime / totalRequests,
      minResponseTime: Math.min(...this.metrics.responseTimes),
      maxResponseTime: Math.max(...this.metrics.responseTimes),
      p50: this.metrics.p50,
      p95: this.metrics.p95,
      p99: this.metrics.p99,
      throughput: this.metrics.throughput
    };
  }
}

// Load Test Runner
class LoadTestRunner {
  constructor(apiClient, authToken) {
    this.apiClient = apiClient;
    this.authToken = authToken;
    this.metrics = new PerformanceMetrics();
  }

  async runSingleRequest(endpoint, method = "GET", payload = null) {
    const startTime = performance.now();
    
    try {
      let response;
      const req = this.apiClient[method.toLowerCase()](endpoint)
        .set("Authorization", `Bearer ${this.authToken}`);
      
      if (payload) {
        req.send(payload);
      }
      
      response = await req;
      const endTime = performance.now();
      const responseTime = endTime - startTime;
      
      this.metrics.recordRequest(
        responseTime,
        response.status,
        response.status >= 200 && response.status < 300
      );
      
      return { response, responseTime };
    } catch (error) {
      const endTime = performance.now();
      const responseTime = endTime - startTime;
      this.metrics.recordRequest(responseTime, 0, false);
      throw error;
    }
  }

  async runConcurrentRequests(endpoint, method, payload, concurrency, totalRequests) {
    const requests = [];
    const batches = Math.ceil(totalRequests / concurrency);
    
    for (let batch = 0; batch < batches; batch++) {
      const batchPromises = [];
      const batchSize = Math.min(concurrency, totalRequests - (batch * concurrency));
      
      for (let i = 0; i < batchSize; i++) {
        batchPromises.push(this.runSingleRequest(endpoint, method, payload));
      }
      
      await Promise.all(batchPromises);
      
      // Small delay between batches to avoid overwhelming the server
      if (batch < batches - 1) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
  }

  async runRampUpTest(endpoint, method, payload, maxConcurrency, rampUpTime) {
    const startTime = Date.now();
    const requests = [];
    const concurrencySteps = 5;
    const stepConcurrency = maxConcurrency / concurrencySteps;
    const stepDuration = rampUpTime / concurrencySteps;
    
    for (let step = 1; step <= concurrencySteps; step++) {
      const currentConcurrency = Math.floor(step * stepConcurrency);
      const stepStartTime = Date.now();
      
      while (Date.now() - stepStartTime < stepDuration) {
        const batchPromises = [];
        for (let i = 0; i < currentConcurrency; i++) {
          batchPromises.push(this.runSingleRequest(endpoint, method, payload));
        }
        await Promise.all(batchPromises);
      }
    }
  }

  getMetrics() {
    return this.metrics.calculateMetrics();
  }
}

// Test Scenarios
async function testBasicLoad() {
  console.log("\n📊 Test 1: Basic Load Test (10 concurrent requests)");
  
  const runner = new LoadTestRunner(request, TOKEN);
  await runner.runConcurrentRequests("/users", "GET", null, 10, 50);
  
  const metrics = runner.getMetrics();
  console.log("Results:", metrics);
  
  expect(metrics.successRate).to.be.greaterThan(95);
  expect(metrics.averageResponseTime).to.be.lessThan(2000);
}

async function testHighLoad() {
  console.log("\n📊 Test 2: High Load Test (50 concurrent requests)");
  
  const runner = new LoadTestRunner(request, TOKEN);
  await runner.runConcurrentRequests("/users", "GET", null, 50, 200);
  
  const metrics = runner.getMetrics();
  console.log("Results:", metrics);
  
  expect(metrics.successRate).to.be.greaterThan(90);
  expect(metrics.p95).to.be.lessThan(5000);
}

async function testRampUpLoad() {
  console.log("\n📊 Test 3: Ramp-Up Load Test");
  
  const runner = new LoadTestRunner(request, TOKEN);
  await runner.runRampUpTest("/users", "GET", null, 30, 10000);
  
  const metrics = runner.getMetrics();
  console.log("Results:", metrics);
  
  expect(metrics.successRate).to.be.greaterThan(90);
}

async function testWriteOperationsLoad() {
  console.log("\n📊 Test 4: Write Operations Load Test");
  
  const runner = new LoadTestRunner(request, TOKEN);
  const testUser = {
    name: "Load Test User",
    email: `loadtest${Date.now()}@example.com`,
    gender: "male",
    status: "active"
  };
  
  await runner.runConcurrentRequests("/users", "POST", testUser, 5, 20);
  
  const metrics = runner.getMetrics();
  console.log("Results:", metrics);
  
  expect(metrics.successRate).to.be.greaterThan(80);
}

// Run all tests
(async () => {
  try {
    await testBasicLoad();
    await testHighLoad();
    await testRampUpLoad();
    await testWriteOperationsLoad();
    
    console.log("\n✅ All load tests completed!");
  } catch (error) {
    console.error("❌ Load test failed:", error.message);
    process.exit(1);
  }
})();


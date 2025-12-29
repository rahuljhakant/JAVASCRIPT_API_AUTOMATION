/**
 * PHASE 5: EXPERT LEVEL
 * Module 4: Performance Engineering
 * Lesson 1: K6 Load Testing
 * 
 * Learning Objectives:
 * - Implement K6 load testing scenarios
 * - Create performance benchmarks
 * - Analyze load test results
 * - Optimize API performance
 */

import { expect } from "chai";
import supertest from "supertest";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== K6 LOAD TESTING ===");

// K6 Test Scenario Builder
class K6ScenarioBuilder {
  constructor() {
    this.scenarios = new Map();
    this.thresholds = new Map();
    this.options = {};
  }
  
  // Create smoke test scenario
  createSmokeTest(options = {}) {
    const scenario = {
      name: 'smoke_test',
      executor: 'constant-vus',
      vus: options.vus || 1,
      duration: options.duration || '30s',
      tags: { test_type: 'smoke' }
    };
    
    this.scenarios.set('smoke_test', scenario);
    return scenario;
  }
  
  // Create load test scenario
  createLoadTest(options = {}) {
    const scenario = {
      name: 'load_test',
      executor: 'constant-vus',
      vus: options.vus || 10,
      duration: options.duration || '5m',
      tags: { test_type: 'load' }
    };
    
    this.scenarios.set('load_test', scenario);
    return scenario;
  }
  
  // Create stress test scenario
  createStressTest(options = {}) {
    const scenario = {
      name: 'stress_test',
      executor: 'ramping-vus',
      startVUs: options.startVUs || 1,
      stages: options.stages || [
        { duration: '2m', target: 20 },
        { duration: '5m', target: 20 },
        { duration: '2m', target: 0 }
      ],
      tags: { test_type: 'stress' }
    };
    
    this.scenarios.set('stress_test', scenario);
    return scenario;
  }
  
  // Create spike test scenario
  createSpikeTest(options = {}) {
    const scenario = {
      name: 'spike_test',
      executor: 'ramping-vus',
      startVUs: options.startVUs || 1,
      stages: options.stages || [
        { duration: '10s', target: 100 },
        { duration: '1m', target: 100 },
        { duration: '10s', target: 1400 },
        { duration: '3m', target: 1400 },
        { duration: '10s', target: 100 },
        { duration: '3m', target: 100 },
        { duration: '10s', target: 0 }
      ],
      tags: { test_type: 'spike' }
    };
    
    this.scenarios.set('spike_test', scenario);
    return scenario;
  }
  
  // Create volume test scenario
  createVolumeTest(options = {}) {
    const scenario = {
      name: 'volume_test',
      executor: 'constant-arrival-rate',
      rate: options.rate || 50,
      timeUnit: options.timeUnit || '1s',
      duration: options.duration || '10m',
      preAllocatedVUs: options.preAllocatedVUs || 100,
      maxVUs: options.maxVUs || 200,
      tags: { test_type: 'volume' }
    };
    
    this.scenarios.set('volume_test', scenario);
    return scenario;
  }
  
  // Add performance thresholds
  addThresholds(thresholds) {
    Object.entries(thresholds).forEach(([name, value]) => {
      this.thresholds.set(name, value);
    });
  }
  
  // Set global options
  setOptions(options) {
    this.options = { ...this.options, ...options };
  }
  
  // Generate K6 configuration
  generateConfig() {
    return {
      scenarios: Object.fromEntries(this.scenarios),
      thresholds: Object.fromEntries(this.thresholds),
      options: this.options
    };
  }
}

// Performance Metrics Analyzer
class PerformanceMetricsAnalyzer {
  constructor() {
    this.metrics = new Map();
    this.baselines = new Map();
  }
  
  // Analyze response time metrics
  analyzeResponseTime(data) {
    const responseTimes = data.map(d => d.responseTime || 0).filter(rt => rt > 0);
    
    if (responseTimes.length === 0) {
      return { error: 'No valid response times found' };
    }
    
    const sorted = responseTimes.sort((a, b) => a - b);
    const count = sorted.length;
    
    return {
      min: Math.min(...responseTimes),
      max: Math.max(...responseTimes),
      avg: responseTimes.reduce((sum, rt) => sum + rt, 0) / count,
      median: this.calculatePercentile(sorted, 50),
      p90: this.calculatePercentile(sorted, 90),
      p95: this.calculatePercentile(sorted, 95),
      p99: this.calculatePercentile(sorted, 99),
      count
    };
  }
  
  // Calculate percentile
  calculatePercentile(sortedArray, percentile) {
    const index = Math.ceil((percentile / 100) * sortedArray.length) - 1;
    return sortedArray[index];
  }
  
  // Analyze throughput metrics
  analyzeThroughput(data, duration) {
    const successfulRequests = data.filter(d => d.status === 200 || d.status === 201);
    const failedRequests = data.filter(d => d.status >= 400);
    
    return {
      totalRequests: data.length,
      successfulRequests: successfulRequests.length,
      failedRequests: failedRequests.length,
      successRate: (successfulRequests.length / data.length) * 100,
      requestsPerSecond: data.length / (duration / 1000),
      successfulRPS: successfulRequests.length / (duration / 1000)
    };
  }
  
  // Analyze error rates
  analyzeErrorRates(data) {
    const errors = data.filter(d => d.status >= 400);
    const errorTypes = {};
    
    errors.forEach(error => {
      const status = error.status;
      errorTypes[status] = (errorTypes[status] || 0) + 1;
    });
    
    return {
      totalErrors: errors.length,
      errorRate: (errors.length / data.length) * 100,
      errorTypes,
      mostCommonError: Object.keys(errorTypes).reduce((a, b) => 
        errorTypes[a] > errorTypes[b] ? a : b
      )
    };
  }
  
  // Compare with baseline
  compareWithBaseline(testName, metrics) {
    const baseline = this.baselines.get(testName);
    if (!baseline) {
      this.baselines.set(testName, metrics);
      return { status: 'baseline_created', metrics };
    }
    
    const comparison = {};
    
    Object.keys(metrics).forEach(key => {
      if (typeof metrics[key] === 'number' && typeof baseline[key] === 'number') {
        const change = ((metrics[key] - baseline[key]) / baseline[key]) * 100;
        comparison[key] = {
          current: metrics[key],
          baseline: baseline[key],
          change: change,
          status: this.getPerformanceStatus(key, change)
        };
      }
    });
    
    return { status: 'compared', comparison };
  }
  
  // Get performance status
  getPerformanceStatus(metric, change) {
    const thresholds = {
      responseTime: { good: -10, warning: 20 },
      throughput: { good: 10, warning: -10 },
      errorRate: { good: -10, warning: 10 }
    };
    
    const threshold = thresholds[metric];
    if (!threshold) return 'unknown';
    
    if (change <= threshold.good) return 'improved';
    if (change <= threshold.warning) return 'stable';
    return 'degraded';
  }
  
  // Generate performance report
  generateReport(testName, data, duration) {
    const responseTime = this.analyzeResponseTime(data);
    const throughput = this.analyzeThroughput(data, duration);
    const errorRates = this.analyzeErrorRates(data);
    
    const metrics = {
      responseTime,
      throughput,
      errorRates,
      timestamp: new Date().toISOString()
    };
    
    const comparison = this.compareWithBaseline(testName, metrics);
    
    return {
      testName,
      metrics,
      comparison,
      summary: this.generateSummary(metrics)
    };
  }
  
  // Generate performance summary
  generateSummary(metrics) {
    const { responseTime, throughput, errorRates } = metrics;
    
    const issues = [];
    
    if (responseTime.p95 > 2000) {
      issues.push('High 95th percentile response time');
    }
    
    if (throughput.successRate < 95) {
      issues.push('Low success rate');
    }
    
    if (errorRates.errorRate > 5) {
      issues.push('High error rate');
    }
    
    return {
      status: issues.length === 0 ? 'good' : 'needs_attention',
      issues,
      recommendations: this.generateRecommendations(issues)
    };
  }
  
  // Generate recommendations
  generateRecommendations(issues) {
    const recommendations = [];
    
    if (issues.includes('High 95th percentile response time')) {
      recommendations.push('Consider optimizing database queries');
      recommendations.push('Implement caching strategies');
      recommendations.push('Review server resources');
    }
    
    if (issues.includes('Low success rate')) {
      recommendations.push('Investigate error patterns');
      recommendations.push('Check server logs');
      recommendations.push('Review error handling');
    }
    
    if (issues.includes('High error rate')) {
      recommendations.push('Implement retry mechanisms');
      recommendations.push('Add circuit breakers');
      recommendations.push('Review input validation');
    }
    
    return recommendations;
  }
}

// Load Test Executor
class LoadTestExecutor {
  constructor() {
    this.results = new Map();
    this.isRunning = false;
  }
  
  // Execute smoke test
  async executeSmokeTest(apiClient, endpoints) {
    const scenario = new K6ScenarioBuilder().createSmokeTest();
    return await this.executeScenario('smoke_test', scenario, apiClient, endpoints);
  }
  
  // Execute load test
  async executeLoadTest(apiClient, endpoints, options = {}) {
    const scenario = new K6ScenarioBuilder().createLoadTest(options);
    return await this.executeScenario('load_test', scenario, apiClient, endpoints);
  }
  
  // Execute stress test
  async executeStressTest(apiClient, endpoints, options = {}) {
    const scenario = new K6ScenarioBuilder().createStressTest(options);
    return await this.executeScenario('stress_test', scenario, apiClient, endpoints);
  }
  
  // Execute spike test
  async executeSpikeTest(apiClient, endpoints, options = {}) {
    const scenario = new K6ScenarioBuilder().createSpikeTest(options);
    return await this.executeScenario('spike_test', scenario, apiClient, endpoints);
  }
  
  // Execute scenario
  async executeScenario(scenarioName, scenario, apiClient, endpoints) {
    this.isRunning = true;
    const startTime = Date.now();
    const results = [];
    
    try {
      const vus = scenario.vus || scenario.startVUs || 1;
      const duration = this.parseDuration(scenario.duration);
      
      // Simulate concurrent users
      const promises = Array.from({ length: vus }, (_, index) => 
        this.simulateUser(apiClient, endpoints, duration, index)
      );
      
      const userResults = await Promise.all(promises);
      results.push(...userResults.flat());
      
    } catch (error) {
      console.error(`Scenario ${scenarioName} failed:`, error);
    } finally {
      this.isRunning = false;
    }
    
    const endTime = Date.now();
    const totalDuration = endTime - startTime;
    
    const result = {
      scenarioName,
      scenario,
      results,
      duration: totalDuration,
      timestamp: new Date().toISOString()
    };
    
    this.results.set(scenarioName, result);
    return result;
  }
  
  // Simulate user behavior
  async simulateUser(apiClient, endpoints, duration, userId) {
    const userResults = [];
    const startTime = Date.now();
    
    while (Date.now() - startTime < duration) {
      try {
        const endpoint = endpoints[Math.floor(Math.random() * endpoints.length)];
        const requestStart = Date.now();
        
        const response = await this.makeRequest(apiClient, endpoint);
        
        const requestEnd = Date.now();
        const responseTime = requestEnd - requestStart;
        
        userResults.push({
          userId,
          endpoint: endpoint.path,
          method: endpoint.method,
          status: response.status,
          responseTime,
          timestamp: new Date().toISOString()
        });
        
        // Simulate think time
        const thinkTime = Math.floor(Math.random() * 1000) + 500;
        await new Promise(resolve => setTimeout(resolve, thinkTime));
        
      } catch (error) {
        userResults.push({
          userId,
          endpoint: 'unknown',
          method: 'unknown',
          status: 'error',
          responseTime: 0,
          error: error.message,
          timestamp: new Date().toISOString()
        });
      }
    }
    
    return userResults;
  }
  
  // Make request
  async makeRequest(apiClient, endpoint) {
    const { method, path, data } = endpoint;
    
    switch (method.toLowerCase()) {
      case 'get':
        return await apiClient.get(path);
      case 'post':
        return await apiClient.post(path).send(data);
      case 'put':
        return await apiClient.put(path).send(data);
      case 'delete':
        return await apiClient.delete(path);
      default:
        throw new Error(`Unsupported method: ${method}`);
    }
  }
  
  // Parse duration string
  parseDuration(duration) {
    const match = duration.match(/(\d+)([smhd])/);
    if (!match) return 30000; // Default 30 seconds
    
    const value = parseInt(match[1]);
    const unit = match[2];
    
    switch (unit) {
      case 's': return value * 1000;
      case 'm': return value * 60 * 1000;
      case 'h': return value * 60 * 60 * 1000;
      case 'd': return value * 24 * 60 * 60 * 1000;
      default: return 30000;
    }
  }
  
  // Get test results
  getResults(scenarioName) {
    return this.results.get(scenarioName);
  }
  
  // Get all results
  getAllResults() {
    return Object.fromEntries(this.results);
  }
  
  // Clear results
  clearResults() {
    this.results.clear();
  }
}

// API client setup
const request = supertest("https://gorest.co.in/public-api/");
import dotenv from "dotenv";
dotenv.config();
const TOKEN = process.env.GOREST_API_TOKEN || process.env.API_TOKEN || "";

// Test endpoints configuration
const testEndpoints = [
  { method: 'GET', path: '/users', data: null },
  { method: 'GET', path: '/users/1', data: null },
  { method: 'POST', path: '/users', data: { name: 'Test User', email: 'test@example.com', gender: 'male', status: 'active' } },
  { method: 'PUT', path: '/users/1', data: { name: 'Updated User' } },
  { method: 'DELETE', path: '/users/1', data: null }
];

// Exercises and Tests
describe("K6 Load Testing", () => {
  let scenarioBuilder;
  let metricsAnalyzer;
  let loadTestExecutor;
  
  beforeEach(() => {
    scenarioBuilder = new K6ScenarioBuilder();
    metricsAnalyzer = new PerformanceMetricsAnalyzer();
    loadTestExecutor = new LoadTestExecutor();
  });
  
  it("should create smoke test scenario", () => {
    const scenario = scenarioBuilder.createSmokeTest({ vus: 2, duration: '1m' });
    
    expect(scenario.name).to.equal('smoke_test');
    expect(scenario.executor).to.equal('constant-vus');
    expect(scenario.vus).to.equal(2);
    expect(scenario.duration).to.equal('1m');
  });
  
  it("should create load test scenario", () => {
    const scenario = scenarioBuilder.createLoadTest({ vus: 20, duration: '10m' });
    
    expect(scenario.name).to.equal('load_test');
    expect(scenario.executor).to.equal('constant-vus');
    expect(scenario.vus).to.equal(20);
    expect(scenario.duration).to.equal('10m');
  });
  
  it("should create stress test scenario", () => {
    const scenario = scenarioBuilder.createStressTest({
      startVUs: 1,
      stages: [
        { duration: '1m', target: 10 },
        { duration: '2m', target: 10 },
        { duration: '1m', target: 0 }
      ]
    });
    
    expect(scenario.name).to.equal('stress_test');
    expect(scenario.executor).to.equal('ramping-vus');
    expect(scenario.startVUs).to.equal(1);
    expect(scenario.stages).to.have.length(3);
  });
  
  it("should create spike test scenario", () => {
    const scenario = scenarioBuilder.createSpikeTest();
    
    expect(scenario.name).to.equal('spike_test');
    expect(scenario.executor).to.equal('ramping-vus');
    expect(scenario.stages).to.have.length(7);
  });
  
  it("should add performance thresholds", () => {
    const thresholds = {
      'http_req_duration': ['p(95)<2000'],
      'http_req_failed': ['rate<0.1'],
      'http_reqs': ['rate>10']
    };
    
    scenarioBuilder.addThresholds(thresholds);
    const config = scenarioBuilder.generateConfig();
    
    expect(config.thresholds).to.deep.equal(thresholds);
  });
  
  it("should analyze response time metrics", () => {
    const testData = [
      { responseTime: 100 },
      { responseTime: 200 },
      { responseTime: 300 },
      { responseTime: 400 },
      { responseTime: 500 }
    ];
    
    const analysis = metricsAnalyzer.analyzeResponseTime(testData);
    
    expect(analysis.min).to.equal(100);
    expect(analysis.max).to.equal(500);
    expect(analysis.avg).to.equal(300);
    expect(analysis.median).to.equal(300);
    expect(analysis.p90).to.equal(450);
    expect(analysis.p95).to.equal(500);
    expect(analysis.p99).to.equal(500);
  });
  
  it("should analyze throughput metrics", () => {
    const testData = [
      { status: 200 },
      { status: 201 },
      { status: 400 },
      { status: 200 },
      { status: 500 }
    ];
    
    const analysis = metricsAnalyzer.analyzeThroughput(testData, 5000);
    
    expect(analysis.totalRequests).to.equal(5);
    expect(analysis.successfulRequests).to.equal(3);
    expect(analysis.failedRequests).to.equal(2);
    expect(analysis.successRate).to.equal(60);
    expect(analysis.requestsPerSecond).to.equal(1);
  });
  
  it("should analyze error rates", () => {
    const testData = [
      { status: 200 },
      { status: 400 },
      { status: 500 },
      { status: 200 },
      { status: 400 }
    ];
    
    const analysis = metricsAnalyzer.analyzeErrorRates(testData);
    
    expect(analysis.totalErrors).to.equal(3);
    expect(analysis.errorRate).to.equal(60);
    expect(analysis.errorTypes).to.have.property('400');
    expect(analysis.errorTypes).to.have.property('500');
  });
  
  it("should generate performance report", () => {
    const testData = [
      { responseTime: 100, status: 200 },
      { responseTime: 200, status: 200 },
      { responseTime: 300, status: 400 },
      { responseTime: 400, status: 200 },
      { responseTime: 500, status: 200 }
    ];
    
    const report = metricsAnalyzer.generateReport('test_api', testData, 5000);
    
    expect(report).to.have.property('testName');
    expect(report).to.have.property('metrics');
    expect(report).to.have.property('comparison');
    expect(report).to.have.property('summary');
    
    expect(report.metrics).to.have.property('responseTime');
    expect(report.metrics).to.have.property('throughput');
    expect(report.metrics).to.have.property('errorRates');
  });
  
  it("should execute smoke test", async () => {
    const result = await loadTestExecutor.executeSmokeTest(request, testEndpoints);
    
    expect(result).to.have.property('scenarioName');
    expect(result).to.have.property('results');
    expect(result).to.have.property('duration');
    expect(result.scenarioName).to.equal('smoke_test');
  });
  
  it("should execute load test", async () => {
    const result = await loadTestExecutor.executeLoadTest(request, testEndpoints, {
      vus: 5,
      duration: '30s'
    });
    
    expect(result).to.have.property('scenarioName');
    expect(result).to.have.property('results');
    expect(result).to.have.property('duration');
    expect(result.scenarioName).to.equal('load_test');
  });
  
  it("should compare performance with baseline", () => {
    const testData = [
      { responseTime: 100, status: 200 },
      { responseTime: 200, status: 200 }
    ];
    
    // First run - creates baseline
    const firstReport = metricsAnalyzer.generateReport('baseline_test', testData, 2000);
    expect(firstReport.comparison.status).to.equal('baseline_created');
    
    // Second run - compares with baseline
    const secondReport = metricsAnalyzer.generateReport('baseline_test', testData, 2000);
    expect(secondReport.comparison.status).to.equal('compared');
    expect(secondReport.comparison.comparison).to.have.property('responseTime');
  });
});

// Integration Tests
describe("K6 Load Testing Integration", () => {
  let loadTestExecutor;
  let metricsAnalyzer;
  
  beforeEach(() => {
    loadTestExecutor = new LoadTestExecutor();
    metricsAnalyzer = new PerformanceMetricsAnalyzer();
  });
  
  it("should execute complete performance test suite", async () => {
    const testSuite = [
      { name: 'smoke', executor: () => loadTestExecutor.executeSmokeTest(request, testEndpoints) },
      { name: 'load', executor: () => loadTestExecutor.executeLoadTest(request, testEndpoints, { vus: 3, duration: '20s' }) }
    ];
    
    const results = [];
    
    for (const test of testSuite) {
      const result = await test.executor();
      const report = metricsAnalyzer.generateReport(test.name, result.results, result.duration);
      results.push(report);
    }
    
    expect(results).to.have.length(2);
    results.forEach(result => {
      expect(result).to.have.property('metrics');
      expect(result).to.have.property('summary');
    });
  });
  
  it("should identify performance bottlenecks", async () => {
    const result = await loadTestExecutor.executeLoadTest(request, testEndpoints, {
      vus: 10,
      duration: '30s'
    });
    
    const report = metricsAnalyzer.generateReport('bottleneck_test', result.results, result.duration);
    
    // Check for performance issues
    if (report.summary.status === 'needs_attention') {
      expect(report.summary.issues).to.be.an('array');
      expect(report.summary.recommendations).to.be.an('array');
    }
  });
});

export { 
  K6ScenarioBuilder, 
  PerformanceMetricsAnalyzer, 
  LoadTestExecutor 
};





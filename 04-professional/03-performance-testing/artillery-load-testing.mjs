/**
 * PHASE 4: PROFESSIONAL LEVEL
 * Module 8: Performance Testing
 * Lesson 1: Artillery Load Testing
 * 
 * Learning Objectives:
 * - Implement Artillery load testing scenarios
 * - Create comprehensive performance test suites
 * - Analyze load test results and metrics
 * - Optimize API performance based on results
 */

import { expect } from "chai";
import { spawn } from "child_process";
import fs from "fs";
import path from "path";

console.log("=== ARTILLERY LOAD TESTING ===");

// Artillery Test Configuration Builder
class ArtilleryConfigBuilder {
  constructor() {
    this.config = {
      config: {
        target: '',
        phases: [],
        defaults: {
          headers: {},
          variables: {}
        }
      },
      scenarios: []
    };
  }
  
  // Set target URL
  target(url) {
    this.config.config.target = url;
    return this;
  }
  
  // Add load phase
  addPhase(duration, arrivalRate, name = null) {
    const phase = {
      duration,
      arrivalRate
    };
    
    if (name) {
      phase.name = name;
    }
    
    this.config.config.phases.push(phase);
    return this;
  }
  
  // Add ramp-up phase
  addRampUpPhase(duration, fromRate, toRate, name = null) {
    const phase = {
      duration,
      arrivalRate: `${fromRate} to ${toRate}`
    };
    
    if (name) {
      phase.name = name;
    }
    
    this.config.config.phases.push(phase);
    return this;
  }
  
  // Set default headers
  setHeaders(headers) {
    this.config.config.defaults.headers = { ...this.config.config.defaults.headers, ...headers };
    return this;
  }
  
  // Set default variables
  setVariables(variables) {
    this.config.config.defaults.variables = { ...this.config.config.defaults.variables, ...variables };
    return this;
  }
  
  // Add scenario
  addScenario(name, weight = 1) {
    const scenario = {
      name,
      weight,
      flow: []
    };
    
    this.config.scenarios.push(scenario);
    return this;
  }
  
  // Add request to current scenario
  addRequest(method, url, options = {}) {
    if (this.config.scenarios.length === 0) {
      throw new Error('Must add a scenario first');
    }
    
    const currentScenario = this.config.scenarios[this.config.scenarios.length - 1];
    const request = {
      [method.toLowerCase()]: {
        url,
        ...options
      }
    };
    
    currentScenario.flow.push(request);
    return this;
  }
  
  // Add think time
  addThinkTime(seconds) {
    if (this.config.scenarios.length === 0) {
      throw new Error('Must add a scenario first');
    }
    
    const currentScenario = this.config.scenarios[this.config.scenarios.length - 1];
    currentScenario.flow.push({ think: seconds });
    return this;
  }
  
  // Add function to scenario
  addFunction(functionName, args = {}) {
    if (this.config.scenarios.length === 0) {
      throw new Error('Must add a scenario first');
    }
    
    const currentScenario = this.config.scenarios[this.config.scenarios.length - 1];
    currentScenario.flow.push({ function: functionName, args });
    return this;
  }
  
  // Add capture to scenario
  addCapture(jsonPath, as) {
    if (this.config.scenarios.length === 0) {
      throw new Error('Must add a scenario first');
    }
    
    const currentScenario = this.config.scenarios[this.config.scenarios.length - 1];
    const lastRequest = currentScenario.flow[currentScenario.flow.length - 1];
    
    if (lastRequest && typeof lastRequest === 'object') {
      const method = Object.keys(lastRequest)[0];
      if (!lastRequest[method].capture) {
        lastRequest[method].capture = [];
      }
      lastRequest[method].capture.push({ json: jsonPath, as });
    }
    
    return this;
  }
  
  // Add before scenario hook
  beforeScenario(hook) {
    this.config.config.before = hook;
    return this;
  }
  
  // Add after scenario hook
  afterScenario(hook) {
    this.config.config.after = hook;
    return this;
  }
  
  // Build configuration
  build() {
    return this.config;
  }
  
  // Save configuration to file
  saveToFile(filename) {
    const configPath = path.join(process.cwd(), 'artillery-configs', filename);
    const configDir = path.dirname(configPath);
    
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }
    
    fs.writeFileSync(configPath, JSON.stringify(this.config, null, 2));
    return configPath;
  }
}

// Artillery Test Executor
class ArtilleryTestExecutor {
  constructor() {
    this.results = new Map();
    this.isRunning = false;
  }
  
  // Run Artillery test
  async runTest(configPath, options = {}) {
    return new Promise((resolve, reject) => {
      const args = ['run', configPath];
      
      if (options.output) {
        args.push('--output', options.output);
      }
      
      if (options.quiet) {
        args.push('--quiet');
      }
      
      const artillery = spawn('artillery', args);
      let stdout = '';
      let stderr = '';
      
      artillery.stdout.on('data', (data) => {
        stdout += data.toString();
      });
      
      artillery.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      
      artillery.on('close', (code) => {
        if (code === 0) {
          resolve({ stdout, stderr, exitCode: code });
        } else {
          reject(new Error(`Artillery test failed with exit code ${code}: ${stderr}`));
        }
      });
      
      artillery.on('error', (error) => {
        reject(error);
      });
    });
  }
  
  // Run test with JSON output
  async runTestWithOutput(configPath, outputPath) {
    return await this.runTest(configPath, { output: outputPath });
  }
  
  // Run multiple tests in sequence
  async runTestSuite(tests) {
    const results = [];
    
    for (const test of tests) {
      try {
        const result = await this.runTest(test.configPath, test.options);
        results.push({ test: test.name, result, success: true });
      } catch (error) {
        results.push({ test: test.name, error: error.message, success: false });
      }
    }
    
    return results;
  }
  
  // Run tests in parallel
  async runTestsInParallel(tests) {
    const promises = tests.map(async (test) => {
      try {
        const result = await this.runTest(test.configPath, test.options);
        return { test: test.name, result, success: true };
      } catch (error) {
        return { test: test.name, error: error.message, success: false };
      }
    });
    
    return await Promise.all(promises);
  }
}

// Artillery Results Analyzer
class ArtilleryResultsAnalyzer {
  constructor() {
    this.metrics = new Map();
  }
  
  // Parse Artillery JSON results
  parseResults(jsonPath) {
    const results = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
    return this.analyzeResults(results);
  }
  
  // Analyze results
  analyzeResults(results) {
    const analysis = {
      summary: this.analyzeSummary(results.summary),
      latencies: this.analyzeLatencies(results.latencies),
      rates: this.analyzeRates(results.rates),
      counters: this.analyzeCounters(results.counters),
      scenarios: this.analyzeScenarios(results.scenarios),
      recommendations: []
    };
    
    analysis.recommendations = this.generateRecommendations(analysis);
    
    return analysis;
  }
  
  // Analyze summary
  analyzeSummary(summary) {
    return {
      duration: summary.duration,
      totalRequests: summary.counters['http.requests'],
      totalErrors: summary.counters['http.codes.4xx'] + summary.counters['http.codes.5xx'],
      successRate: this.calculateSuccessRate(summary.counters),
      averageResponseTime: summary.latencies.mean,
      p95ResponseTime: summary.latencies.p95,
      p99ResponseTime: summary.latencies.p99,
      requestsPerSecond: summary.rates['http.requests']
    };
  }
  
  // Analyze latencies
  analyzeLatencies(latencies) {
    return {
      min: latencies.min,
      max: latencies.max,
      mean: latencies.mean,
      median: latencies.median,
      p90: latencies.p90,
      p95: latencies.p95,
      p99: latencies.p99,
      p999: latencies.p999
    };
  }
  
  // Analyze rates
  analyzeRates(rates) {
    return {
      requestsPerSecond: rates['http.requests'],
      errorsPerSecond: rates['http.codes.4xx'] + rates['http.codes.5xx'],
      successPerSecond: rates['http.codes.2xx'] + rates['http.codes.3xx']
    };
  }
  
  // Analyze counters
  analyzeCounters(counters) {
    return {
      totalRequests: counters['http.requests'],
      successfulRequests: counters['http.codes.2xx'] + counters['http.codes.3xx'],
      clientErrors: counters['http.codes.4xx'],
      serverErrors: counters['http.codes.5xx'],
      timeouts: counters['http.request_timeout'] || 0,
      connectionErrors: counters['http.connection_error'] || 0
    };
  }
  
  // Analyze scenarios
  analyzeScenarios(scenarios) {
    return scenarios.map(scenario => ({
      name: scenario.name,
      duration: scenario.duration,
      requests: scenario.counters['http.requests'],
      errors: scenario.counters['http.codes.4xx'] + scenario.counters['http.codes.5xx'],
      averageResponseTime: scenario.latencies.mean,
      successRate: this.calculateSuccessRate(scenario.counters)
    }));
  }
  
  // Calculate success rate
  calculateSuccessRate(counters) {
    const total = counters['http.requests'];
    const successful = counters['http.codes.2xx'] + counters['http.codes.3xx'];
    return total > 0 ? (successful / total) * 100 : 0;
  }
  
  // Generate recommendations
  generateRecommendations(analysis) {
    const recommendations = [];
    
    // Response time recommendations
    if (analysis.latencies.p95 > 2000) {
      recommendations.push({
        type: 'performance',
        severity: 'high',
        message: '95th percentile response time is too high (>2s)',
        suggestion: 'Consider optimizing database queries, implementing caching, or scaling resources'
      });
    }
    
    // Success rate recommendations
    if (analysis.summary.successRate < 95) {
      recommendations.push({
        type: 'reliability',
        severity: 'high',
        message: `Success rate is too low (${analysis.summary.successRate.toFixed(2)}%)`,
        suggestion: 'Investigate error patterns and improve error handling'
      });
    }
    
    // Error rate recommendations
    if (analysis.rates.errorsPerSecond > 10) {
      recommendations.push({
        type: 'stability',
        severity: 'medium',
        message: 'High error rate detected',
        suggestion: 'Review error logs and implement better error handling'
      });
    }
    
    // Throughput recommendations
    if (analysis.rates.requestsPerSecond < 100) {
      recommendations.push({
        type: 'scalability',
        severity: 'medium',
        message: 'Low throughput detected',
        suggestion: 'Consider horizontal scaling or performance optimization'
      });
    }
    
    return recommendations;
  }
  
  // Compare results
  compareResults(baseline, current) {
    const comparison = {
      summary: this.compareSummary(baseline.summary, current.summary),
      latencies: this.compareLatencies(baseline.latencies, current.latencies),
      rates: this.compareRates(baseline.rates, current.rates),
      counters: this.compareCounters(baseline.counters, current.counters)
    };
    
    return comparison;
  }
  
  // Compare summary
  compareSummary(baseline, current) {
    return {
      duration: { baseline: baseline.duration, current: current.duration },
      totalRequests: { baseline: baseline.totalRequests, current: current.totalRequests },
      successRate: { 
        baseline: baseline.successRate, 
        current: current.successRate,
        change: current.successRate - baseline.successRate
      },
      averageResponseTime: {
        baseline: baseline.averageResponseTime,
        current: current.averageResponseTime,
        change: current.averageResponseTime - baseline.averageResponseTime
      }
    };
  }
  
  // Compare latencies
  compareLatencies(baseline, current) {
    return {
      p95: {
        baseline: baseline.p95,
        current: current.p95,
        change: current.p95 - baseline.p95
      },
      p99: {
        baseline: baseline.p99,
        current: current.p99,
        change: current.p99 - baseline.p99
      }
    };
  }
  
  // Compare rates
  compareRates(baseline, current) {
    return {
      requestsPerSecond: {
        baseline: baseline.requestsPerSecond,
        current: current.requestsPerSecond,
        change: current.requestsPerSecond - baseline.requestsPerSecond
      }
    };
  }
  
  // Compare counters
  compareCounters(baseline, current) {
    return {
      totalRequests: {
        baseline: baseline.totalRequests,
        current: current.totalRequests,
        change: current.totalRequests - baseline.totalRequests
      },
      errors: {
        baseline: baseline.clientErrors + baseline.serverErrors,
        current: current.clientErrors + current.serverErrors,
        change: (current.clientErrors + current.serverErrors) - (baseline.clientErrors + baseline.serverErrors)
      }
    };
  }
}

// Performance Test Suite
class PerformanceTestSuite {
  constructor() {
    this.configBuilder = new ArtilleryConfigBuilder();
    this.executor = new ArtilleryTestExecutor();
    this.analyzer = new ArtilleryResultsAnalyzer();
    this.tests = [];
  }
  
  // Add smoke test
  addSmokeTest(target, endpoint) {
    const config = this.configBuilder
      .target(target)
      .addPhase('30s', 1, 'smoke-test')
      .addScenario('smoke-test')
      .addRequest('GET', endpoint)
      .build();
    
    const configPath = this.configBuilder.saveToFile('smoke-test.json');
    
    this.tests.push({
      name: 'smoke-test',
      type: 'smoke',
      configPath,
      config
    });
    
    return this;
  }
  
  // Add load test
  addLoadTest(target, endpoint, duration = '5m', rate = 10) {
    const config = this.configBuilder
      .target(target)
      .addPhase(duration, rate, 'load-test')
      .addScenario('load-test')
      .addRequest('GET', endpoint)
      .build();
    
    const configPath = this.configBuilder.saveToFile('load-test.json');
    
    this.tests.push({
      name: 'load-test',
      type: 'load',
      configPath,
      config
    });
    
    return this;
  }
  
  // Add stress test
  addStressTest(target, endpoint) {
    const config = this.configBuilder
      .target(target)
      .addRampUpPhase('2m', 1, 50, 'ramp-up')
      .addPhase('5m', 50, 'sustained-load')
      .addRampUpPhase('2m', 50, 0, 'ramp-down')
      .addScenario('stress-test')
      .addRequest('GET', endpoint)
      .build();
    
    const configPath = this.configBuilder.saveToFile('stress-test.json');
    
    this.tests.push({
      name: 'stress-test',
      type: 'stress',
      configPath,
      config
    });
    
    return this;
  }
  
  // Add spike test
  addSpikeTest(target, endpoint) {
    const config = this.configBuilder
      .target(target)
      .addPhase('1m', 10, 'baseline')
      .addPhase('30s', 100, 'spike')
      .addPhase('1m', 10, 'recovery')
      .addScenario('spike-test')
      .addRequest('GET', endpoint)
      .build();
    
    const configPath = this.configBuilder.saveToFile('spike-test.json');
    
    this.tests.push({
      name: 'spike-test',
      type: 'spike',
      configPath,
      config
    });
    
    return this;
  }
  
  // Add volume test
  addVolumeTest(target, endpoint, duration = '10m', rate = 50) {
    const config = this.configBuilder
      .target(target)
      .addPhase(duration, rate, 'volume-test')
      .addScenario('volume-test')
      .addRequest('GET', endpoint)
      .build();
    
    const configPath = this.configBuilder.saveToFile('volume-test.json');
    
    this.tests.push({
      name: 'volume-test',
      type: 'volume',
      configPath,
      config
    });
    
    return this;
  }
  
  // Run all tests
  async runAllTests() {
    const results = [];
    
    for (const test of this.tests) {
      try {
        const outputPath = `artillery-results/${test.name}-${Date.now()}.json`;
        const result = await this.executor.runTestWithOutput(test.configPath, outputPath);
        const analysis = this.analyzer.parseResults(outputPath);
        
        results.push({
          test: test.name,
          type: test.type,
          result,
          analysis,
          success: true
        });
      } catch (error) {
        results.push({
          test: test.name,
          type: test.type,
          error: error.message,
          success: false
        });
      }
    }
    
    return results;
  }
  
  // Run specific test
  async runTest(testName) {
    const test = this.tests.find(t => t.name === testName);
    if (!test) {
      throw new Error(`Test not found: ${testName}`);
    }
    
    const outputPath = `artillery-results/${test.name}-${Date.now()}.json`;
    const result = await this.executor.runTestWithOutput(test.configPath, outputPath);
    const analysis = this.analyzer.parseResults(outputPath);
    
    return {
      test: test.name,
      type: test.type,
      result,
      analysis
    };
  }
  
  // Get test summary
  getTestSummary() {
    return {
      totalTests: this.tests.length,
      testTypes: [...new Set(this.tests.map(t => t.type))],
      tests: this.tests.map(t => ({
        name: t.name,
        type: t.type,
        configPath: t.configPath
      }))
    };
  }
}

// Exercises and Tests
describe("Artillery Load Testing", () => {
  let configBuilder;
  let executor;
  let analyzer;
  let testSuite;
  
  beforeEach(() => {
    configBuilder = new ArtilleryConfigBuilder();
    executor = new ArtilleryTestExecutor();
    analyzer = new ArtilleryResultsAnalyzer();
    testSuite = new PerformanceTestSuite();
  });
  
  it("should build Artillery configuration", () => {
    const config = configBuilder
      .target('https://api.example.com')
      .addPhase('5m', 10, 'load-test')
      .setHeaders({ 'Authorization': 'Bearer token' })
      .addScenario('user-journey')
      .addRequest('GET', '/users')
      .addThinkTime(1)
      .addRequest('POST', '/users', { json: { name: 'Test User' } })
      .build();
    
    expect(config.config.target).to.equal('https://api.example.com');
    expect(config.config.phases).to.have.length(1);
    expect(config.config.phases[0].duration).to.equal('5m');
    expect(config.config.phases[0].arrivalRate).to.equal(10);
    expect(config.scenarios).to.have.length(1);
    expect(config.scenarios[0].flow).to.have.length(3);
  });
  
  it("should create smoke test configuration", () => {
    const config = configBuilder
      .target('https://api.example.com')
      .addPhase('30s', 1, 'smoke-test')
      .addScenario('smoke-test')
      .addRequest('GET', '/health')
      .build();
    
    expect(config.config.phases[0].duration).to.equal('30s');
    expect(config.config.phases[0].arrivalRate).to.equal(1);
  });
  
  it("should create stress test configuration", () => {
    const config = configBuilder
      .target('https://api.example.com')
      .addRampUpPhase('2m', 1, 50, 'ramp-up')
      .addPhase('5m', 50, 'sustained-load')
      .addRampUpPhase('2m', 50, 0, 'ramp-down')
      .addScenario('stress-test')
      .addRequest('GET', '/users')
      .build();
    
    expect(config.config.phases).to.have.length(3);
    expect(config.config.phases[0].arrivalRate).to.equal('1 to 50');
    expect(config.config.phases[1].arrivalRate).to.equal(50);
    expect(config.config.phases[2].arrivalRate).to.equal('50 to 0');
  });
  
  it("should add request capture", () => {
    const config = configBuilder
      .target('https://api.example.com')
      .addPhase('1m', 1)
      .addScenario('capture-test')
      .addRequest('POST', '/users', { json: { name: 'Test User' } })
      .addCapture('$.id', 'userId')
      .build();
    
    const request = config.scenarios[0].flow[0];
    expect(request.post.capture).to.have.length(1);
    expect(request.post.capture[0].json).to.equal('$.id');
    expect(request.post.capture[0].as).to.equal('userId');
  });
  
  it("should save configuration to file", () => {
    const config = configBuilder
      .target('https://api.example.com')
      .addPhase('1m', 1)
      .addScenario('test')
      .addRequest('GET', '/users')
      .build();
    
    const configPath = configBuilder.saveToFile('test-config.json');
    expect(configPath).to.include('test-config.json');
    expect(fs.existsSync(configPath)).to.be.true;
  });
  
  it("should analyze Artillery results", () => {
    const mockResults = {
      summary: {
        duration: 60,
        counters: {
          'http.requests': 100,
          'http.codes.2xx': 95,
          'http.codes.4xx': 3,
          'http.codes.5xx': 2
        },
        latencies: {
          min: 50,
          max: 2000,
          mean: 500,
          median: 450,
          p90: 800,
          p95: 1000,
          p99: 1500
        }
      },
      rates: {
        'http.requests': 1.67,
        'http.codes.2xx': 1.58,
        'http.codes.4xx': 0.05,
        'http.codes.5xx': 0.03
      },
      counters: {
        'http.requests': 100,
        'http.codes.2xx': 95,
        'http.codes.3xx': 0,
        'http.codes.4xx': 3,
        'http.codes.5xx': 2
      },
      scenarios: []
    };
    
    const analysis = analyzer.analyzeResults(mockResults);
    
    expect(analysis.summary.totalRequests).to.equal(100);
    expect(analysis.summary.successRate).to.equal(95);
    expect(analysis.summary.averageResponseTime).to.equal(500);
    expect(analysis.latencies.p95).to.equal(1000);
    expect(analysis.rates.requestsPerSecond).to.equal(1.67);
  });
  
  it("should generate performance recommendations", () => {
    const mockResults = {
      summary: {
        duration: 60,
        counters: {
          'http.requests': 100,
          'http.codes.2xx': 90,
          'http.codes.4xx': 5,
          'http.codes.5xx': 5
        },
        latencies: {
          min: 50,
          max: 5000,
          mean: 1000,
          median: 800,
          p90: 1500,
          p95: 2500,
          p99: 4000
        }
      },
      rates: {
        'http.requests': 1.67,
        'http.codes.2xx': 1.5,
        'http.codes.4xx': 0.08,
        'http.codes.5xx': 0.08
      },
      counters: {
        'http.requests': 100,
        'http.codes.2xx': 90,
        'http.codes.3xx': 0,
        'http.codes.4xx': 5,
        'http.codes.5xx': 5
      },
      scenarios: []
    };
    
    const analysis = analyzer.analyzeResults(mockResults);
    
    expect(analysis.recommendations).to.be.an('array');
    expect(analysis.recommendations.length).to.be.greaterThan(0);
    
    const performanceRec = analysis.recommendations.find(r => r.type === 'performance');
    expect(performanceRec).to.exist;
    expect(performanceRec.severity).to.equal('high');
  });
  
  it("should create performance test suite", () => {
    testSuite
      .addSmokeTest('https://api.example.com', '/health')
      .addLoadTest('https://api.example.com', '/users', '5m', 10)
      .addStressTest('https://api.example.com', '/users')
      .addSpikeTest('https://api.example.com', '/users')
      .addVolumeTest('https://api.example.com', '/users', '10m', 50);
    
    const summary = testSuite.getTestSummary();
    
    expect(summary.totalTests).to.equal(5);
    expect(summary.testTypes).to.include('smoke');
    expect(summary.testTypes).to.include('load');
    expect(summary.testTypes).to.include('stress');
    expect(summary.testTypes).to.include('spike');
    expect(summary.testTypes).to.include('volume');
  });
  
  it("should compare performance results", () => {
    const baseline = {
      summary: {
        duration: 60,
        totalRequests: 100,
        successRate: 95,
        averageResponseTime: 500
      },
      latencies: { p95: 800, p99: 1200 },
      rates: { requestsPerSecond: 1.67 },
      counters: { totalRequests: 100, clientErrors: 3, serverErrors: 2 }
    };
    
    const current = {
      summary: {
        duration: 60,
        totalRequests: 120,
        successRate: 98,
        averageResponseTime: 400
      },
      latencies: { p95: 600, p99: 900 },
      rates: { requestsPerSecond: 2.0 },
      counters: { totalRequests: 120, clientErrors: 2, serverErrors: 0 }
    };
    
    const comparison = analyzer.compareResults(baseline, current);
    
    expect(comparison.summary.successRate.change).to.equal(3);
    expect(comparison.summary.averageResponseTime.change).to.equal(-100);
    expect(comparison.latencies.p95.change).to.equal(-200);
    expect(comparison.rates.requestsPerSecond.change).to.equal(0.33);
  });
});

export { 
  ArtilleryConfigBuilder, 
  ArtilleryTestExecutor, 
  ArtilleryResultsAnalyzer, 
  PerformanceTestSuite 
};




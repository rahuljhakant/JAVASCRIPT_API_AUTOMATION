/**
 * PHASE 4: PROFESSIONAL LEVEL
 * Module 4: Parallel Automation
 * Lesson 1: Parallel Execution
 * 
 * Learning Objectives:
 * - Implement parallel test execution
 * - Optimize test performance
 * - Handle parallel execution challenges
 * - Monitor parallel test execution
 */

import { expect } from "chai";
import supertest from "supertest";
import cluster from "cluster";
import os from "os";

console.log("=== PARALLEL AUTOMATION ===");

// Parallel Execution Manager
class ParallelExecutionManager {
  constructor(options = {}) {
    this.maxWorkers = options.maxWorkers || os.cpus().length;
    this.timeout = options.timeout || 30000;
    this.retries = options.retries || 3;
    this.workers = [];
    this.results = [];
    this.errors = [];
  }
  
  // Execute tests in parallel using worker threads
  async executeParallel(tests) {
    console.log(`Starting parallel execution with ${this.maxWorkers} workers`);
    
    const chunks = this.chunkArray(tests, Math.ceil(tests.length / this.maxWorkers));
    
    const promises = chunks.map((chunk, index) => 
      this.executeChunk(chunk, index)
    );
    
    const results = await Promise.allSettled(promises);
    
    return this.processResults(results);
  }
  
  // Execute a chunk of tests
  async executeChunk(chunk, workerId) {
    console.log(`Worker ${workerId} executing ${chunk.length} tests`);
    
    const results = [];
    
    for (const test of chunk) {
      try {
        const startTime = Date.now();
        const result = await this.executeTest(test);
        const endTime = Date.now();
        
        results.push({
          test: test.name,
          status: 'passed',
          duration: endTime - startTime,
          result: result,
          workerId: workerId
        });
      } catch (error) {
        results.push({
          test: test.name,
          status: 'failed',
          error: error.message,
          workerId: workerId
        });
      }
    }
    
    return results;
  }
  
  // Execute individual test
  async executeTest(test) {
    const timeoutPromise = new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Test timeout')), this.timeout)
    );
    
    const testPromise = test.function();
    
    return Promise.race([testPromise, timeoutPromise]);
  }
  
  // Chunk array for parallel processing
  chunkArray(array, chunkSize) {
    const chunks = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
  }
  
  // Process results from all workers
  processResults(results) {
    const allResults = [];
    const allErrors = [];
    
    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        allResults.push(...result.value);
      } else {
        allErrors.push({
          worker: index,
          error: result.reason
        });
      }
    });
    
    return {
      results: allResults,
      errors: allErrors,
      summary: this.generateSummary(allResults, allErrors)
    };
  }
  
  // Generate execution summary
  generateSummary(results, errors) {
    const passed = results.filter(r => r.status === 'passed').length;
    const failed = results.filter(r => r.status === 'failed').length;
    const totalDuration = results.reduce((sum, r) => sum + (r.duration || 0), 0);
    const averageDuration = results.length > 0 ? totalDuration / results.length : 0;
    
    return {
      total: results.length,
      passed,
      failed,
      errors: errors.length,
      totalDuration,
      averageDuration: Math.round(averageDuration),
      successRate: results.length > 0 ? (passed / results.length) * 100 : 0
    };
  }
}

// Test Suite for Parallel Execution
class ParallelTestSuite {
  constructor() {
    this.request = supertest("https://jsonplaceholder.typicode.com");
    this.tests = [];
  }
  
  // Add test to suite
  addTest(name, testFunction) {
    this.tests.push({ name, function: testFunction });
  }
  
  // Generate test data
  generateTestData(count) {
    const tests = [];
    
    for (let i = 1; i <= count; i++) {
      tests.push({
        name: `Test User ${i}`,
        function: async () => {
          const response = await this.request.get(`/users/${i}`);
          expect(response.status).to.equal(200);
          expect(response.body).to.have.property('id');
          return response.body;
        }
      });
    }
    
    return tests;
  }
  
  // CRUD operations tests
  generateCRUDTests() {
    return [
      {
        name: 'Create User Test',
        function: async () => {
          const userData = {
            name: 'Test User',
            email: 'test@example.com',
            username: 'testuser'
          };
          
          const response = await this.request
            .post('/users')
            .send(userData);
          
          expect(response.status).to.equal(201);
          expect(response.body).to.have.property('id');
          return response.body;
        }
      },
      {
        name: 'Read User Test',
        function: async () => {
          const response = await this.request.get('/users/1');
          expect(response.status).to.equal(200);
          expect(response.body.id).to.equal(1);
          return response.body;
        }
      },
      {
        name: 'Update User Test',
        function: async () => {
          const updateData = { name: 'Updated User' };
          const response = await this.request
            .put('/users/1')
            .send(updateData);
          
          expect(response.status).to.equal(200);
          expect(response.body.name).to.equal('Updated User');
          return response.body;
        }
      },
      {
        name: 'Delete User Test',
        function: async () => {
          const response = await this.request.delete('/users/1');
          expect(response.status).to.equal(200);
          return response.body;
        }
      }
    ];
  }
  
  // Performance tests
  generatePerformanceTests() {
    return [
      {
        name: 'Response Time Test',
        function: async () => {
          const startTime = Date.now();
          const response = await this.request.get('/posts/1');
          const endTime = Date.now();
          
          const responseTime = endTime - startTime;
          expect(responseTime).to.be.lessThan(5000);
          
          return { responseTime, status: response.status };
        }
      },
      {
        name: 'Concurrent Request Test',
        function: async () => {
          const promises = Array.from({ length: 5 }, (_, i) => 
            this.request.get(`/posts/${i + 1}`)
          );
          
          const responses = await Promise.all(promises);
          responses.forEach(response => {
            expect(response.status).to.equal(200);
          });
          
          return { concurrentRequests: responses.length };
        }
      }
    ];
  }
}

// Exercises and Tests
describe("Parallel Execution", () => {
  let parallelManager;
  let testSuite;
  
  beforeEach(() => {
    parallelManager = new ParallelExecutionManager({
      maxWorkers: 4,
      timeout: 10000
    });
    testSuite = new ParallelTestSuite();
  });
  
  it("should execute tests in parallel", async () => {
    const tests = testSuite.generateTestData(10);
    const results = await parallelManager.executeParallel(tests);
    
    expect(results.results).to.have.length(10);
    expect(results.errors).to.have.length(0);
    expect(results.summary.successRate).to.be.greaterThan(0);
    
    console.log("Parallel Execution Summary:", results.summary);
  });
  
  it("should execute CRUD operations in parallel", async () => {
    const crudTests = testSuite.generateCRUDTests();
    const results = await parallelManager.executeParallel(crudTests);
    
    expect(results.results).to.have.length(4);
    expect(results.summary.passed).to.be.greaterThan(0);
    
    // Verify each operation type was executed
    const testNames = results.results.map(r => r.name);
    expect(testNames).to.include('Create User Test');
    expect(testNames).to.include('Read User Test');
  });
  
  it("should handle performance tests in parallel", async () => {
    const performanceTests = testSuite.generatePerformanceTests();
    const results = await parallelManager.executeParallel(performanceTests);
    
    expect(results.results).to.have.length(2);
    
    const responseTimeTest = results.results.find(r => r.name === 'Response Time Test');
    expect(responseTimeTest).to.exist;
    expect(responseTimeTest.status).to.equal('passed');
  });
  
  it("should handle errors gracefully in parallel execution", async () => {
    const errorTests = [
      {
        name: 'Valid Test',
        function: async () => {
          const response = await testSuite.request.get('/users/1');
          expect(response.status).to.equal(200);
          return response.body;
        }
      },
      {
        name: 'Invalid Test',
        function: async () => {
          const response = await testSuite.request.get('/invalid-endpoint');
          expect(response.status).to.equal(200); // This will fail
          return response.body;
        }
      }
    ];
    
    const results = await parallelManager.executeParallel(errorTests);
    
    expect(results.results).to.have.length(2);
    expect(results.summary.failed).to.be.greaterThan(0);
    
    const failedTest = results.results.find(r => r.status === 'failed');
    expect(failedTest).to.exist;
    expect(failedTest.name).to.equal('Invalid Test');
  });
  
  it("should optimize execution time with parallel processing", async () => {
    const tests = testSuite.generateTestData(20);
    
    // Sequential execution
    const sequentialStart = Date.now();
    const sequentialResults = [];
    for (const test of tests) {
      const result = await parallelManager.executeTest(test);
      sequentialResults.push(result);
    }
    const sequentialEnd = Date.now();
    const sequentialDuration = sequentialEnd - sequentialStart;
    
    // Parallel execution
    const parallelStart = Date.now();
    const parallelResults = await parallelManager.executeParallel(tests);
    const parallelEnd = Date.now();
    const parallelDuration = parallelEnd - parallelStart;
    
    console.log(`Sequential Duration: ${sequentialDuration}ms`);
    console.log(`Parallel Duration: ${parallelDuration}ms`);
    console.log(`Performance Improvement: ${((sequentialDuration - parallelDuration) / sequentialDuration * 100).toFixed(2)}%`);
    
    expect(parallelDuration).to.be.lessThan(sequentialDuration);
    expect(parallelResults.results).to.have.length(tests.length);
  });
});

// Advanced Parallel Patterns
describe("Advanced Parallel Patterns", () => {
  it("should implement worker pool pattern", async () => {
    class WorkerPool {
      constructor(size) {
        this.size = size;
        this.workers = [];
        this.queue = [];
        this.active = 0;
      }
      
      async execute(task) {
        return new Promise((resolve, reject) => {
          this.queue.push({ task, resolve, reject });
          this.process();
        });
      }
      
      async process() {
        if (this.active >= this.size || this.queue.length === 0) {
          return;
        }
        
        this.active++;
        const { task, resolve, reject } = this.queue.shift();
        
        try {
          const result = await task();
          resolve(result);
        } catch (error) {
          reject(error);
        } finally {
          this.active--;
          this.process();
        }
      }
    }
    
    const pool = new WorkerPool(3);
    const tasks = Array.from({ length: 10 }, (_, i) => 
      () => testSuite.request.get(`/users/${i + 1}`)
    );
    
    const results = await Promise.all(
      tasks.map(task => pool.execute(task))
    );
    
    expect(results).to.have.length(10);
    results.forEach(result => {
      expect(result.status).to.equal(200);
    });
  });
  
  it("should implement batch processing pattern", async () => {
    class BatchProcessor {
      constructor(batchSize, delay) {
        this.batchSize = batchSize;
        this.delay = delay;
        this.batches = [];
      }
      
      async processBatches(items, processor) {
        const batches = this.createBatches(items);
        const results = [];
        
        for (let i = 0; i < batches.length; i++) {
          const batch = batches[i];
          const batchResults = await Promise.all(
            batch.map(item => processor(item))
          );
          
          results.push(...batchResults);
          
          // Add delay between batches to avoid overwhelming the API
          if (i < batches.length - 1) {
            await new Promise(resolve => setTimeout(resolve, this.delay));
          }
        }
        
        return results;
      }
      
      createBatches(items) {
        const batches = [];
        for (let i = 0; i < items.length; i += this.batchSize) {
          batches.push(items.slice(i, i + this.batchSize));
        }
        return batches;
      }
    }
    
    const processor = new BatchProcessor(5, 100);
    const userIds = Array.from({ length: 20 }, (_, i) => i + 1);
    
    const results = await processor.processBatches(userIds, async (userId) => {
      const response = await testSuite.request.get(`/users/${userId}`);
      return { userId, status: response.status, name: response.body.name };
    });
    
    expect(results).to.have.length(20);
    results.forEach(result => {
      expect(result.status).to.equal(200);
      expect(result.name).to.be.a('string');
    });
  });
});

// Monitoring and Metrics
describe("Parallel Execution Monitoring", () => {
  it("should collect execution metrics", async () => {
    const metrics = {
      startTime: Date.now(),
      testsExecuted: 0,
      testsPassed: 0,
      testsFailed: 0,
      totalDuration: 0,
      averageDuration: 0,
      throughput: 0
    };
    
    const tests = testSuite.generateTestData(15);
    const results = await parallelManager.executeParallel(tests);
    
    metrics.endTime = Date.now();
    metrics.totalDuration = metrics.endTime - metrics.startTime;
    metrics.testsExecuted = results.results.length;
    metrics.testsPassed = results.summary.passed;
    metrics.testsFailed = results.summary.failed;
    metrics.averageDuration = results.summary.averageDuration;
    metrics.throughput = (metrics.testsExecuted / metrics.totalDuration) * 1000; // tests per second
    
    console.log("Execution Metrics:", metrics);
    
    expect(metrics.testsExecuted).to.equal(15);
    expect(metrics.throughput).to.be.greaterThan(0);
    expect(metrics.averageDuration).to.be.greaterThan(0);
  });
});

export { 
  ParallelExecutionManager, 
  ParallelTestSuite 
};

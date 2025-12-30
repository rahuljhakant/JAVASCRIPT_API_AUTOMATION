/**
 * PHASE 2.5: DESIGN PATTERNS
 * Module 3: Behavioral Patterns
 * Lesson 2: Strategy Pattern
 * 
 * Learning Objectives:
 * - Understand the Strategy pattern for test execution
 * - Implement different testing strategies
 * - Switch between strategies dynamically
 * - Build flexible test frameworks
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== STRATEGY PATTERN FOR TESTING ===");

// Strategy Interface
class TestStrategy {
  execute(test) {
    throw new Error("execute() must be implemented");
  }
}

// Concrete Strategies
class SequentialTestStrategy extends TestStrategy {
  async execute(tests) {
    const results = [];
    
    for (const test of tests) {
      try {
        const startTime = Date.now();
        const result = await test.run();
        const duration = Date.now() - startTime;
        
        results.push({
          name: test.name,
          status: 'passed',
          duration,
          result
        });
      } catch (error) {
        results.push({
          name: test.name,
          status: 'failed',
          error: error.message
        });
      }
    }
    
    return results;
  }
}

class ParallelTestStrategy extends TestStrategy {
  async execute(tests) {
    const promises = tests.map(async (test) => {
      try {
        const startTime = Date.now();
        const result = await test.run();
        const duration = Date.now() - startTime;
        
        return {
          name: test.name,
          status: 'passed',
          duration,
          result
        };
      } catch (error) {
        return {
          name: test.name,
          status: 'failed',
          error: error.message
        };
      }
    });
    
    return await Promise.all(promises);
  }
}

class RetryTestStrategy extends TestStrategy {
  constructor(maxRetries = 3) {
    super();
    this.maxRetries = maxRetries;
  }
  
  async execute(tests) {
    const results = [];
    
    for (const test of tests) {
      let lastError = null;
      let success = false;
      
      for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
        try {
          const startTime = Date.now();
          const result = await test.run();
          const duration = Date.now() - startTime;
          
          results.push({
            name: test.name,
            status: 'passed',
            duration,
            attempts: attempt,
            result
          });
          
          success = true;
          break;
        } catch (error) {
          lastError = error;
          
          if (attempt < this.maxRetries) {
            // Wait before retry (exponential backoff)
            await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
          }
        }
      }
      
      if (!success) {
        results.push({
          name: test.name,
          status: 'failed',
          attempts: this.maxRetries,
          error: lastError.message
        });
      }
    }
    
    return results;
  }
}

class PriorityTestStrategy extends TestStrategy {
  async execute(tests) {
    // Sort tests by priority
    const sortedTests = [...tests].sort((a, b) => {
      const priorityA = a.priority || 0;
      const priorityB = b.priority || 0;
      return priorityB - priorityA; // Higher priority first
    });
    
    const results = [];
    
    for (const test of sortedTests) {
      try {
        const startTime = Date.now();
        const result = await test.run();
        const duration = Date.now() - startTime;
        
        results.push({
          name: test.name,
          status: 'passed',
          duration,
          priority: test.priority,
          result
        });
      } catch (error) {
        results.push({
          name: test.name,
          status: 'failed',
          priority: test.priority,
          error: error.message
        });
      }
    }
    
    return results;
  }
}

// Test Context
class TestContext {
  constructor(strategy) {
    this.strategy = strategy;
  }
  
  setStrategy(strategy) {
    if (!(strategy instanceof TestStrategy)) {
      throw new Error("Strategy must implement TestStrategy interface");
    }
    this.strategy = strategy;
  }
  
  async runTests(tests) {
    if (!this.strategy) {
      throw new Error("No strategy set");
    }
    return await this.strategy.execute(tests);
  }
}

// Test Class
class ApiTest {
  constructor(name, testFunction, options = {}) {
    this.name = name;
    this.testFunction = testFunction;
    this.priority = options.priority || 0;
    this.timeout = options.timeout || 5000;
  }
  
  async run() {
    return await this.testFunction();
  }
}

// Exercises and Tests
describe("Strategy Pattern for Testing", () => {
  let context;
  
  beforeEach(() => {
    context = new TestContext(new SequentialTestStrategy());
  });
  
  it("should execute tests sequentially", async () => {
    const request = supertest("https://jsonplaceholder.typicode.com");
    
    const tests = [
      new ApiTest("Get Post 1", async () => {
        const response = await request.get("/posts/1");
        expect(response.status).to.equal(200);
        return response.body;
      }),
      new ApiTest("Get Post 2", async () => {
        const response = await request.get("/posts/2");
        expect(response.status).to.equal(200);
        return response.body;
      })
    ];
    
    const results = await context.runTests(tests);
    
    expect(results.length).to.equal(2);
    expect(results[0].status).to.equal('passed');
    expect(results[1].status).to.equal('passed');
  });
  
  it("should execute tests in parallel", async () => {
    context.setStrategy(new ParallelTestStrategy());
    
    const request = supertest("https://jsonplaceholder.typicode.com");
    
    const tests = [
      new ApiTest("Get Post 1", async () => {
        const response = await request.get("/posts/1");
        expect(response.status).to.equal(200);
        return response.body;
      }),
      new ApiTest("Get Post 2", async () => {
        const response = await request.get("/posts/2");
        expect(response.status).to.equal(200);
        return response.body;
      }),
      new ApiTest("Get Post 3", async () => {
        const response = await request.get("/posts/3");
        expect(response.status).to.equal(200);
        return response.body;
      })
    ];
    
    const startTime = Date.now();
    const results = await context.runTests(tests);
    const duration = Date.now() - startTime;
    
    expect(results.length).to.equal(3);
    expect(results.every(r => r.status === 'passed')).to.be.true;
    // Parallel execution should be faster
    expect(duration).to.be.lessThan(5000);
  });
  
  it("should retry failed tests", async () => {
    context.setStrategy(new RetryTestStrategy(3));
    
    let attemptCount = 0;
    const tests = [
      new ApiTest("Failing Test", async () => {
        attemptCount++;
        if (attemptCount < 3) {
          throw new Error("Test failed");
        }
        return { success: true };
      })
    ];
    
    const results = await context.runTests(tests);
    
    expect(results.length).to.equal(1);
    expect(results[0].status).to.equal('passed');
    expect(results[0].attempts).to.equal(3);
  });
  
  it("should execute tests by priority", async () => {
    context.setStrategy(new PriorityTestStrategy());
    
    const request = supertest("https://jsonplaceholder.typicode.com");
    const executionOrder = [];
    
    const tests = [
      new ApiTest("Low Priority", async () => {
        executionOrder.push("low");
        const response = await request.get("/posts/1");
        return response.body;
      }, { priority: 1 }),
      new ApiTest("High Priority", async () => {
        executionOrder.push("high");
        const response = await request.get("/posts/2");
        return response.body;
      }, { priority: 10 }),
      new ApiTest("Medium Priority", async () => {
        executionOrder.push("medium");
        const response = await request.get("/posts/3");
        return response.body;
      }, { priority: 5 })
    ];
    
    const results = await context.runTests(tests);
    
    expect(results.length).to.equal(3);
    expect(executionOrder[0]).to.equal("high");
    expect(executionOrder[1]).to.equal("medium");
    expect(executionOrder[2]).to.equal("low");
  });
  
  it("should switch strategies dynamically", async () => {
    const request = supertest("https://jsonplaceholder.typicode.com");
    
    // Start with sequential
    context.setStrategy(new SequentialTestStrategy());
    const tests1 = [
      new ApiTest("Test 1", async () => {
        const response = await request.get("/posts/1");
        return response.body;
      })
    ];
    
    let results1 = await context.runTests(tests1);
    expect(results1.length).to.equal(1);
    
    // Switch to parallel
    context.setStrategy(new ParallelTestStrategy());
    const tests2 = [
      new ApiTest("Test 2", async () => {
        const response = await request.get("/posts/2");
        return response.body;
      }),
      new ApiTest("Test 3", async () => {
        const response = await request.get("/posts/3");
        return response.body;
      })
    ];
    
    const results2 = await context.runTests(tests2);
    expect(results2.length).to.equal(2);
  });
});

// Advanced Strategy Patterns
describe("Advanced Strategy Patterns", () => {
  it("should combine strategies", async () => {
    class CombinedStrategy extends TestStrategy {
      constructor(strategies) {
        super();
        this.strategies = strategies;
      }
      
      async execute(tests) {
        let results = tests;
        
        for (const strategy of this.strategies) {
          // Convert results to test format for next strategy
          const testResults = results.map(r => ({
            name: r.name || r.test?.name,
            test: r.test || r,
            priority: r.priority || r.test?.priority
          }));
          
          results = await strategy.execute(testResults);
        }
        
        return results;
      }
    }
    
    const priorityStrategy = new PriorityTestStrategy();
    const retryStrategy = new RetryTestStrategy(2);
    const combined = new CombinedStrategy([priorityStrategy, retryStrategy]);
    
    const context = new TestContext(combined);
    const request = supertest("https://jsonplaceholder.typicode.com");
    
    const tests = [
      new ApiTest("Low Priority", async () => {
        const response = await request.get("/posts/1");
        return response.body;
      }, { priority: 1 }),
      new ApiTest("High Priority", async () => {
        const response = await request.get("/posts/2");
        return response.body;
      }, { priority: 10 })
    ];
    
    const results = await context.runTests(tests);
    expect(results.length).to.equal(2);
  });
  
  it("should implement conditional strategy selection", () => {
    class ConditionalStrategy extends TestStrategy {
      constructor(condition, strategy1, strategy2) {
        super();
        this.condition = condition;
        this.strategy1 = strategy1;
        this.strategy2 = strategy2;
      }
      
      async execute(tests) {
        const strategy = this.condition(tests) ? this.strategy1 : this.strategy2;
        return await strategy.execute(tests);
      }
    }
    
    const conditional = new ConditionalStrategy(
      (tests) => tests.length > 5, // If more than 5 tests, use parallel
      new ParallelTestStrategy(),
      new SequentialTestStrategy()
    );
    
    const context = new TestContext(conditional);
    
    // Small test suite - sequential
    const smallTests = Array.from({ length: 3 }, (_, i) => 
      new ApiTest(`Test ${i}`, async () => ({ success: true }))
    );
    
    // Large test suite - parallel
    const largeTests = Array.from({ length: 10 }, (_, i) => 
      new ApiTest(`Test ${i}`, async () => ({ success: true }))
    );
    
    expect(conditional.condition(smallTests)).to.be.false;
    expect(conditional.condition(largeTests)).to.be.true;
  });
});

export { 
  TestStrategy,
  SequentialTestStrategy,
  ParallelTestStrategy,
  RetryTestStrategy,
  PriorityTestStrategy,
  TestContext,
  ApiTest
};


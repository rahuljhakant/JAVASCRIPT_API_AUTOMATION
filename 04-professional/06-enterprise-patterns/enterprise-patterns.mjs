/**
 * PHASE 4: PROFESSIONAL LEVEL
 * Module 6: Enterprise Patterns
 * Lesson 1: Enterprise Testing Patterns
 * 
 * Learning Objectives:
 * - Implement enterprise-level testing patterns
 * - Create scalable test architectures
 * - Implement test data management strategies
 * - Design for multi-tenant and distributed systems
 */

import { expect } from "chai";
import supertest from "supertest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== ENTERPRISE PATTERNS ===");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = getApiToken();

// Test Data Management Service
class TestDataManagementService {
  constructor() {
    this.testData = new Map();
    this.dataGenerators = new Map();
  }

  registerGenerator(dataType, generator) {
    this.dataGenerators.set(dataType, generator);
  }

  generateTestData(dataType, count = 1) {
    const generator = this.dataGenerators.get(dataType);
    if (!generator) {
      throw new Error(`No generator registered for type: ${dataType}`);
    }

    const data = [];
    for (let i = 0; i < count; i++) {
      data.push(generator(i));
    }

    return data;
  }

  storeTestData(key, data) {
    this.testData.set(key, {
      data,
      timestamp: Date.now(),
      used: false
    });
  }

  retrieveTestData(key) {
    const stored = this.testData.get(key);
    if (stored) {
      stored.used = true;
      return stored.data;
    }
    return null;
  }

  cleanupTestData(olderThan = 3600000) { // 1 hour default
    const now = Date.now();
    for (const [key, value] of this.testData.entries()) {
      if (now - value.timestamp > olderThan) {
        this.testData.delete(key);
      }
    }
  }
}

// Multi-Tenant Test Manager
class MultiTenantTestManager {
  constructor(apiClient, authToken) {
    this.apiClient = apiClient;
    this.authToken = authToken;
    this.tenants = new Map();
  }

  createTenantContext(tenantId, config = {}) {
    const context = {
      tenantId,
      baseUrl: config.baseUrl || "https://gorest.co.in/public-api/",
      authToken: config.authToken || this.authToken,
      headers: {
        "X-Tenant-ID": tenantId,
        ...config.headers
      },
      createdAt: Date.now()
    };

    this.tenants.set(tenantId, context);
    return context;
  }

  async executeForTenant(tenantId, testFunction) {
    const context = this.tenants.get(tenantId);
    if (!context) {
      throw new Error(`Tenant context not found: ${tenantId}`);
    }

    const tenantClient = supertest(context.baseUrl);
    
    return await testFunction(tenantClient, context);
  }

  async executeForAllTenants(testFunction) {
    const results = new Map();
    
    for (const [tenantId, context] of this.tenants.entries()) {
      try {
        const result = await this.executeForTenant(tenantId, testFunction);
        results.set(tenantId, { success: true, result });
      } catch (error) {
        results.set(tenantId, { success: false, error: error.message });
      }
    }

    return results;
  }
}

// Distributed Test Coordinator
class DistributedTestCoordinator {
  constructor() {
    this.testNodes = new Map();
    this.testQueue = [];
    this.results = [];
  }

  registerNode(nodeId, nodeConfig) {
    this.testNodes.set(nodeId, {
      ...nodeConfig,
      status: "available",
      lastHeartbeat: Date.now()
    });
  }

  enqueueTest(testConfig) {
    this.testQueue.push({
      ...testConfig,
      status: "pending",
      queuedAt: Date.now()
    });
  }

  assignTestToNode(nodeId, testId) {
    const node = this.testNodes.get(nodeId);
    const test = this.testQueue.find(t => t.id === testId);

    if (node && test && node.status === "available") {
      node.status = "busy";
      test.status = "assigned";
      test.assignedTo = nodeId;
      test.assignedAt = Date.now();
      return true;
    }

    return false;
  }

  recordResult(testId, result) {
    const test = this.testQueue.find(t => t.id === testId);
    if (test) {
      test.status = "completed";
      test.result = result;
      test.completedAt = Date.now();
      this.results.push({ testId, ...result });
    }
  }

  getTestStatus() {
    return {
      total: this.testQueue.length,
      pending: this.testQueue.filter(t => t.status === "pending").length,
      assigned: this.testQueue.filter(t => t.status === "assigned").length,
      completed: this.testQueue.filter(t => t.status === "completed").length,
      nodes: {
        total: this.testNodes.size,
        available: Array.from(this.testNodes.values()).filter(n => n.status === "available").length,
        busy: Array.from(this.testNodes.values()).filter(n => n.status === "busy").length
      }
    };
  }
}

// Test Execution Strategy
class TestExecutionStrategy {
  static SEQUENTIAL = "sequential";
  static PARALLEL = "parallel";
  static BATCH = "batch";
  static PRIORITY = "priority";

  constructor(strategy = TestExecutionStrategy.SEQUENTIAL) {
    this.strategy = strategy;
  }

  async execute(tests, executor) {
    switch (this.strategy) {
      case TestExecutionStrategy.SEQUENTIAL:
        return await this.executeSequential(tests, executor);
      case TestExecutionStrategy.PARALLEL:
        return await this.executeParallel(tests, executor);
      case TestExecutionStrategy.BATCH:
        return await this.executeBatch(tests, executor);
      case TestExecutionStrategy.PRIORITY:
        return await this.executePriority(tests, executor);
      default:
        return await this.executeSequential(tests, executor);
    }
  }

  async executeSequential(tests, executor) {
    const results = [];
    for (const test of tests) {
      const result = await executor(test);
      results.push(result);
    }
    return results;
  }

  async executeParallel(tests, executor) {
    const promises = tests.map(test => executor(test));
    return await Promise.all(promises);
  }

  async executeBatch(tests, executor, batchSize = 5) {
    const results = [];
    for (let i = 0; i < tests.length; i += batchSize) {
      const batch = tests.slice(i, i + batchSize);
      const batchResults = await Promise.all(batch.map(test => executor(test)));
      results.push(...batchResults);
    }
    return results;
  }

  async executePriority(tests, executor) {
    const sorted = tests.sort((a, b) => (b.priority || 0) - (a.priority || 0));
    return await this.executeSequential(sorted, executor);
  }
}

// Test Scenarios
async function testDataManagement() {
  console.log("\n📝 Test 1: Test Data Management");
  
  const dataService = new TestDataManagementService();
  
  // Register data generator
  dataService.registerGenerator("user", (index) => ({
    name: `Test User ${index}`,
    email: `testuser${index}${Date.now()}@example.com`,
    gender: index % 2 === 0 ? "male" : "female",
    status: "active"
  }));
  
  // Generate test data
  const users = dataService.generateTestData("user", 3);
  expect(users.length).to.equal(3);
  
  // Store test data
  dataService.storeTestData("test-users", users);
  
  // Retrieve test data
  const retrieved = dataService.retrieveTestData("test-users");
  expect(retrieved).to.deep.equal(users);
  
  console.log("✅ Test data management test passed");
}

async function testMultiTenant() {
  console.log("\n📝 Test 2: Multi-Tenant Testing");
  
  const manager = new MultiTenantTestManager(request, TOKEN);
  
  // Create tenant contexts
  manager.createTenantContext("tenant-1");
  manager.createTenantContext("tenant-2");
  
  // Execute test for specific tenant
  const result = await manager.executeForTenant("tenant-1", async (client, context) => {
    const response = await client
      .get("/users")
      .set("Authorization", `Bearer ${context.authToken}`)
      .set(context.headers);
    
    return { status: response.status, count: response.body.data?.length || 0 };
  });
  
  expect(result).to.have.property("status");
  
  console.log("✅ Multi-tenant test passed");
}

async function testDistributedExecution() {
  console.log("\n📝 Test 3: Distributed Test Execution");
  
  const coordinator = new DistributedTestCoordinator();
  
  // Register test nodes
  coordinator.registerNode("node-1", { capacity: 10 });
  coordinator.registerNode("node-2", { capacity: 10 });
  
  // Enqueue tests
  coordinator.enqueueTest({ id: "test-1", name: "Test 1" });
  coordinator.enqueueTest({ id: "test-2", name: "Test 2" });
  
  // Assign tests
  coordinator.assignTestToNode("node-1", "test-1");
  coordinator.assignTestToNode("node-2", "test-2");
  
  // Record results
  coordinator.recordResult("test-1", { passed: true });
  coordinator.recordResult("test-2", { passed: true });
  
  const status = coordinator.getTestStatus();
  expect(status.completed).to.equal(2);
  
  console.log("📊 Test Status:", status);
  console.log("✅ Distributed execution test passed");
}

async function testExecutionStrategies() {
  console.log("\n📝 Test 4: Test Execution Strategies");
  
  const tests = [
    { id: 1, name: "Test 1" },
    { id: 2, name: "Test 2" },
    { id: 3, name: "Test 3", priority: 10 }
  ];
  
  const executor = async (test) => {
    return { testId: test.id, result: "passed" };
  };
  
  // Test sequential strategy
  const sequential = new TestExecutionStrategy(TestExecutionStrategy.SEQUENTIAL);
  const sequentialResults = await sequential.execute(tests, executor);
  expect(sequentialResults.length).to.equal(3);
  
  // Test parallel strategy
  const parallel = new TestExecutionStrategy(TestExecutionStrategy.PARALLEL);
  const parallelResults = await parallel.execute(tests, executor);
  expect(parallelResults.length).to.equal(3);
  
  // Test priority strategy
  const priority = new TestExecutionStrategy(TestExecutionStrategy.PRIORITY);
  const priorityResults = await priority.execute(tests, executor);
  expect(priorityResults[0].testId).to.equal(3); // Priority test first
  
  console.log("✅ Execution strategies test passed");
}

// Run all tests
(async () => {
  try {
    await testDataManagement();
    await testMultiTenant();
    await testDistributedExecution();
    await testExecutionStrategies();
    
    console.log("\n✅ All enterprise patterns tests completed!");
  } catch (error) {
    console.error("❌ Enterprise pattern test failed:", error.message);
    process.exit(1);
  }
})();


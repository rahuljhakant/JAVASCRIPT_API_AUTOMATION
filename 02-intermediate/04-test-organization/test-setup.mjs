/**
 * PHASE 2: INTERMEDIATE LEVEL
 * Module 4: Test Organization
 * Lesson 2: Test Setup and Configuration
 * 
 * Learning Objectives:
 * - Configure test environment
 * - Set up test utilities
 * - Organize test structure
 * - Create reusable test helpers
 */

import { expect } from "chai";
import supertest from "supertest";
import dotenv from "dotenv";

console.log("=== TEST SETUP AND CONFIGURATION ===");

// Load environment variables
dotenv.config();

// Test configuration
const TEST_CONFIG = {
  baseUrl: process.env.API_BASE_URL || "https://jsonplaceholder.typicode.com",
  timeout: parseInt(process.env.TEST_TIMEOUT || "30000", 10),
  retries: parseInt(process.env.TEST_RETRIES || "2", 10),
  parallel: process.env.TEST_PARALLEL === "true"
};

// API client setup
const request = supertest(TEST_CONFIG.baseUrl);

// Test Setup Class
class TestSetup {
  constructor(config = {}) {
    this.config = { ...TEST_CONFIG, ...config };
    this.apiClient = supertest(this.config.baseUrl);
    this.testData = {};
    this.cleanupTasks = [];
  }
  
  async initialize() {
    console.log("Initializing test setup...");
    console.log("Base URL:", this.config.baseUrl);
    console.log("Timeout:", this.config.timeout);
    
    // Load initial test data
    await this.loadTestData();
  }
  
  async loadTestData() {
    try {
      const [users, posts] = await Promise.all([
        this.apiClient.get("/users").then(r => r.body),
        this.apiClient.get("/posts").then(r => r.body)
      ]);
      
      this.testData.users = users;
      this.testData.posts = posts;
      
      console.log(`Loaded ${users.length} users and ${posts.length} posts`);
    } catch (error) {
      console.error("Failed to load test data:", error.message);
    }
  }
  
  registerCleanup(task) {
    this.cleanupTasks.push(task);
  }
  
  async cleanup() {
    console.log("Running cleanup tasks...");
    
    for (const task of this.cleanupTasks) {
      try {
        await task();
      } catch (error) {
        console.error("Cleanup task failed:", error.message);
      }
    }
    
    this.cleanupTasks = [];
  }
  
  getTestUser(index = 0) {
    return this.testData.users?.[index] || null;
  }
  
  getTestPost(index = 0) {
    return this.testData.posts?.[index] || null;
  }
}

// Global test setup instance
let globalTestSetup;

// Setup before all tests
before(async () => {
  globalTestSetup = new TestSetup();
  await globalTestSetup.initialize();
});

// Cleanup after all tests
after(async () => {
  if (globalTestSetup) {
    await globalTestSetup.cleanup();
  }
});

// Exercises and Tests
describe("Test Setup and Configuration", () => {
  it("should have test setup initialized", () => {
    expect(globalTestSetup).to.exist;
    expect(globalTestSetup.config).to.have.property('baseUrl');
  });

  it("should load test data", () => {
    expect(globalTestSetup.testData).to.have.property('users');
    expect(globalTestSetup.testData).to.have.property('posts');
    expect(globalTestSetup.testData.users.length).to.be.greaterThan(0);
  });

  it("should get test user", () => {
    const user = globalTestSetup.getTestUser(0);
    expect(user).to.exist;
    expect(user).to.have.property('id');
    expect(user).to.have.property('name');
  });

  it("should get test post", () => {
    const post = globalTestSetup.getTestPost(0);
    expect(post).to.exist;
    expect(post).to.have.property('id');
    expect(post).to.have.property('title');
  });

  it("should register cleanup tasks", async () => {
    let cleanupCalled = false;
    
    globalTestSetup.registerCleanup(() => {
      cleanupCalled = true;
    });
    
    await globalTestSetup.cleanup();
    expect(cleanupCalled).to.be.true;
  });
});

// Test Utilities
class TestUtilities {
  static async retry(fn, maxRetries = 3, delay = 1000) {
    let lastError;
    
    for (let i = 0; i < maxRetries; i++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error;
        if (i < maxRetries - 1) {
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }
    
    throw lastError;
  }
  
  static async waitForCondition(condition, timeout = 5000, interval = 100) {
    const startTime = Date.now();
    
    while (Date.now() - startTime < timeout) {
      if (await condition()) {
        return true;
      }
      await new Promise(resolve => setTimeout(resolve, interval));
    }
    
    return false;
  }
  
  static generateTestData(type) {
    const generators = {
      user: () => ({
        name: `Test User ${Date.now()}`,
        email: `test${Date.now()}@example.com`,
        username: `testuser${Date.now()}`
      }),
      post: () => ({
        title: `Test Post ${Date.now()}`,
        body: `Test body content ${Date.now()}`,
        userId: 1
      })
    };
    
    return generators[type] ? generators[type]() : null;
  }
}

// Advanced Setup Examples
describe("Advanced Test Setup", () => {
  it("should use retry utility", async () => {
    let attempts = 0;
    
    const result = await TestUtilities.retry(async () => {
      attempts++;
      if (attempts < 3) {
        throw new Error("Temporary failure");
      }
      return "success";
    });
    
    expect(result).to.equal("success");
    expect(attempts).to.equal(3);
  });

  it("should generate test data", () => {
    const userData = TestUtilities.generateTestData('user');
    expect(userData).to.have.property('name');
    expect(userData).to.have.property('email');
    
    const postData = TestUtilities.generateTestData('post');
    expect(postData).to.have.property('title');
    expect(postData).to.have.property('body');
  });
});

// Export functions and classes
export { 
  TestSetup, 
  TestUtilities, 
  TEST_CONFIG 
};


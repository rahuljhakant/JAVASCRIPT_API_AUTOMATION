/**
 * PHASE 2: INTERMEDIATE LEVEL
 * Module 4: Test Organization
 * Lesson 1: Test Hooks (before, after, beforeEach, afterEach)
 * 
 * Learning Objectives:
 * - Understand test hooks
 * - Use before/after hooks for setup/teardown
 * - Use beforeEach/afterEach for test isolation
 * - Organize test structure
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== TEST HOOKS ===");

// API client setup
const request = supertest("https://jsonplaceholder.typicode.com");

// Test data that will be set up in hooks
let testUser;
let testPost;
let createdResources = [];

// Setup before all tests
before(async () => {
  console.log("Setting up test environment...");
  
  // Create test data that will be used across tests
  const userResponse = await request.get("/users/1");
  testUser = userResponse.body;
  
  const postResponse = await request.get("/posts/1");
  testPost = postResponse.body;
  
  console.log("Test environment ready");
});

// Cleanup after all tests
after(async () => {
  console.log("Cleaning up test environment...");
  
  // Clean up any created resources
  for (const resource of createdResources) {
    try {
      await request.delete(`/posts/${resource.id}`);
    } catch (error) {
      console.log(`Failed to cleanup resource ${resource.id}:`, error.message);
    }
  }
  
  createdResources = [];
  console.log("Cleanup complete");
});

// Setup before each test
beforeEach(() => {
  console.log("Preparing for next test...");
  // Reset test state if needed
});

// Cleanup after each test
afterEach(() => {
  console.log("Test completed, cleaning up...");
  // Clean up test-specific data if needed
});

// Exercises and Tests
describe("Test Hooks - User Operations", () => {
  it("should use test data from before hook", () => {
    expect(testUser).to.exist;
    expect(testUser).to.have.property('id');
    expect(testUser).to.have.property('name');
  });

  it("should access shared test data", () => {
    expect(testUser.id).to.equal(1);
    expect(testPost).to.exist;
  });

  it("should create and track resources", async () => {
    const newPost = {
      title: "Test Post",
      body: "Test Body",
      userId: testUser.id
    };
    
    const response = await request.post("/posts").send(newPost);
    
    expect(response.status).to.equal(201);
    expect(response.body).to.have.property('id');
    
    // Track for cleanup
    createdResources.push(response.body);
  });
});

describe("Test Hooks - Post Operations", () => {
  it("should use beforeEach hook for isolation", () => {
    // Each test in this suite gets fresh state
    expect(testPost).to.exist;
  });

  it("should maintain test isolation", () => {
    // This test should not be affected by previous tests
    expect(testPost.id).to.equal(1);
  });
});

// Advanced Hook Patterns
describe("Advanced Hook Patterns", () => {
  let suiteLevelData;
  
  before(() => {
    suiteLevelData = {
      timestamp: Date.now(),
      testRun: "advanced-hooks"
    };
  });
  
  beforeEach(() => {
    suiteLevelData.testCount = (suiteLevelData.testCount || 0) + 1;
  });
  
  it("should track test execution", () => {
    expect(suiteLevelData.testCount).to.be.greaterThan(0);
  });
  
  it("should maintain suite-level data", () => {
    expect(suiteLevelData.timestamp).to.exist;
    expect(suiteLevelData.testRun).to.equal("advanced-hooks");
  });
});

// Hook Utilities
class TestHooks {
  static async setupTestData() {
    const [userResponse, postResponse] = await Promise.all([
      request.get("/users/1"),
      request.get("/posts/1")
    ]);
    
    return {
      user: userResponse.body,
      post: postResponse.body
    };
  }
  
  static async cleanupResources(resources) {
    const cleanupPromises = resources.map(resource => 
      request.delete(`/posts/${resource.id}`).catch(() => {})
    );
    
    await Promise.all(cleanupPromises);
  }
  
  static createTestContext() {
    return {
      startTime: Date.now(),
      resources: [],
      errors: []
    };
  }
}

// Export functions and classes
export { 
  TestHooks 
};


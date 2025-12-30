/**
 * PHASE 3: ADVANCED LEVEL
 * Module 1: Complex Scenarios
 * Lesson 1: Bulk Operations
 * 
 * Learning Objectives:
 * - Handle bulk create, update, and delete operations
 * - Implement batch processing with error handling
 * - Optimize bulk operations for performance
 * - Manage partial failures in bulk operations
 */

import { expect } from "chai";
import supertest from "supertest";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== BULK OPERATIONS ===");

// API client setup
const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = getApiToken();

// Bulk Operations Service
class BulkOperationsService {
  constructor(apiClient, authToken) {
    this.apiClient = apiClient;
    this.authToken = authToken;
  }
  
  async bulkCreate(resources, options = {}) {
    const { batchSize = 10, delay = 100, stopOnError = false } = options;
    const results = [];
    const errors = [];
    
    // Process in batches
    for (let i = 0; i < resources.length; i += batchSize) {
      const batch = resources.slice(i, i + batchSize);
      
      const batchPromises = batch.map(async (resource, index) => {
        try {
          const response = await this.apiClient
            .post("/users")
            .set("Authorization", `Bearer ${this.authToken}`)
            .send(resource);
          
          return {
            index: i + index,
            success: response.status === 201,
            data: response.body.data,
            status: response.status,
            error: null
          };
        } catch (error) {
          const errorResult = {
            index: i + index,
            success: false,
            data: null,
            status: error.status || 500,
            error: error.message
          };
          
          if (stopOnError) {
            throw error;
          }
          
          return errorResult;
        }
      });
      
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
      
      // Separate successes and errors
      batchResults.forEach(result => {
        if (result.success) {
          results.push(result);
        } else {
          errors.push(result);
        }
      });
      
      // Delay between batches
      if (i + batchSize < resources.length && delay > 0) {
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    
    return {
      total: resources.length,
      successful: results.filter(r => r.success).length,
      failed: errors.length,
      results,
      errors
    };
  }
  
  async bulkUpdate(updates, options = {}) {
    const { batchSize = 10, delay = 100 } = options;
    const results = [];
    const errors = [];
    
    for (let i = 0; i < updates.length; i += batchSize) {
      const batch = updates.slice(i, i + batchSize);
      
      const batchPromises = batch.map(async (update) => {
        try {
          const response = await this.apiClient
            .patch(`/users/${update.id}`)
            .set("Authorization", `Bearer ${this.authToken}`)
            .send(update.data);
          
          return {
            id: update.id,
            success: response.status === 200,
            data: response.body.data,
            status: response.status,
            error: null
          };
        } catch (error) {
          return {
            id: update.id,
            success: false,
            data: null,
            status: error.status || 500,
            error: error.message
          };
        }
      });
      
      const batchResults = await Promise.all(batchPromises);
      
      batchResults.forEach(result => {
        if (result.success) {
          results.push(result);
        } else {
          errors.push(result);
        }
      });
      
      if (i + batchSize < updates.length && delay > 0) {
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    
    return {
      total: updates.length,
      successful: results.length,
      failed: errors.length,
      results,
      errors
    };
  }
  
  async bulkDelete(ids, options = {}) {
    const { batchSize = 10, delay = 100 } = options;
    const results = [];
    const errors = [];
    
    for (let i = 0; i < ids.length; i += batchSize) {
      const batch = ids.slice(i, i + batchSize);
      
      const batchPromises = batch.map(async (id) => {
        try {
          const response = await this.apiClient
            .delete(`/users/${id}`)
            .set("Authorization", `Bearer ${this.authToken}`);
          
          return {
            id,
            success: response.status === 200 || response.status === 204,
            status: response.status,
            error: null
          };
        } catch (error) {
          return {
            id,
            success: false,
            status: error.status || 500,
            error: error.message
          };
        }
      });
      
      const batchResults = await Promise.all(batchPromises);
      
      batchResults.forEach(result => {
        if (result.success) {
          results.push(result);
        } else {
          errors.push(result);
        }
      });
      
      if (i + batchSize < ids.length && delay > 0) {
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    
    return {
      total: ids.length,
      successful: results.length,
      failed: errors.length,
      results,
      errors
    };
  }
  
  async bulkCreateConcurrent(resources, concurrency = 5) {
    const results = [];
    const errors = [];
    
    // Process with limited concurrency
    for (let i = 0; i < resources.length; i += concurrency) {
      const batch = resources.slice(i, i + concurrency);
      
      const batchPromises = batch.map(async (resource, index) => {
        try {
          const response = await this.apiClient
            .post("/users")
            .set("Authorization", `Bearer ${this.authToken}`)
            .send(resource);
          
          return {
            index: i + index,
            success: response.status === 201,
            data: response.body.data,
            status: response.status,
            error: null
          };
        } catch (error) {
          return {
            index: i + index,
            success: false,
            data: null,
            status: error.status || 500,
            error: error.message
          };
        }
      });
      
      const batchResults = await Promise.all(batchPromises);
      
      batchResults.forEach(result => {
        if (result.success) {
          results.push(result);
        } else {
          errors.push(result);
        }
      });
    }
    
    return {
      total: resources.length,
      successful: results.length,
      failed: errors.length,
      results,
      errors
    };
  }
}

// Test Data Generator
class BulkTestDataGenerator {
  static generateUsers(count) {
    return Array.from({ length: count }, (_, i) => ({
      name: `Bulk User ${i + 1} ${Math.floor(Math.random() * 10000)}`,
      email: `bulkuser${i + 1}${Math.floor(Math.random() * 10000)}@example.com`,
      gender: i % 2 === 0 ? "male" : "female",
      status: "active"
    }));
  }
  
  static generateUpdates(users) {
    return users.map(user => ({
      id: user.id,
      data: {
        name: `Updated ${user.name}`,
        status: "inactive"
      }
    }));
  }
}

// Exercises and Tests
describe("Bulk Operations", () => {
  let bulkService;
  let createdUserIds = [];
  
  beforeEach(() => {
    bulkService = new BulkOperationsService(request, TOKEN);
  });
  
  afterEach(async () => {
    // Cleanup created users
    if (createdUserIds.length > 0) {
      const deleteResult = await bulkService.bulkDelete(createdUserIds);
      console.log(`Cleaned up ${deleteResult.successful} users`);
      createdUserIds = [];
    }
  });
  
  it("should create multiple users in bulk", async () => {
    const users = BulkTestDataGenerator.generateUsers(5);
    const result = await bulkService.bulkCreate(users, { batchSize: 2 });
    
    expect(result.total).to.equal(5);
    expect(result.successful).to.be.greaterThan(0);
    
    // Store created user IDs for cleanup
    result.results.forEach(r => {
      if (r.success && r.data && r.data.id) {
        createdUserIds.push(r.data.id);
      }
    });
    
    console.log(`Bulk create: ${result.successful} successful, ${result.failed} failed`);
  });
  
  it("should handle bulk create with errors", async () => {
    const users = BulkTestDataGenerator.generateUsers(3);
    // Add an invalid user
    users.push({
      name: "", // Invalid: empty name
      email: "invalid-email",
      gender: "invalid",
      status: "invalid"
    });
    
    const result = await bulkService.bulkCreate(users, { stopOnError: false });
    
    expect(result.total).to.equal(4);
    expect(result.failed).to.be.greaterThan(0);
    expect(result.errors.length).to.be.greaterThan(0);
    
    console.log(`Bulk create with errors: ${result.successful} successful, ${result.failed} failed`);
  });
  
  it("should update multiple users in bulk", async () => {
    // First create users
    const users = BulkTestDataGenerator.generateUsers(3);
    const createResult = await bulkService.bulkCreate(users);
    
    const createdUsers = createResult.results
      .filter(r => r.success && r.data)
      .map(r => r.data);
    
    if (createdUsers.length === 0) {
      this.skip();
      return;
    }
    
    createdUserIds.push(...createdUsers.map(u => u.id));
    
    // Update users
    const updates = BulkTestDataGenerator.generateUpdates(createdUsers);
    const updateResult = await bulkService.bulkUpdate(updates);
    
    expect(updateResult.total).to.equal(createdUsers.length);
    expect(updateResult.successful).to.be.greaterThan(0);
    
    console.log(`Bulk update: ${updateResult.successful} successful`);
  });
  
  it("should delete multiple users in bulk", async () => {
    // First create users
    const users = BulkTestDataGenerator.generateUsers(3);
    const createResult = await bulkService.bulkCreate(users);
    
    const userIds = createResult.results
      .filter(r => r.success && r.data)
      .map(r => r.data.id);
    
    if (userIds.length === 0) {
      this.skip();
      return;
    }
    
    // Delete users
    const deleteResult = await bulkService.bulkDelete(userIds);
    
    expect(deleteResult.total).to.equal(userIds.length);
    expect(deleteResult.successful).to.be.greaterThan(0);
    
    console.log(`Bulk delete: ${deleteResult.successful} successful`);
  });
  
  it("should handle bulk operations with concurrency control", async () => {
    const users = BulkTestDataGenerator.generateUsers(10);
    const result = await bulkService.bulkCreateConcurrent(users, 3);
    
    expect(result.total).to.equal(10);
    expect(result.successful).to.be.greaterThan(0);
    
    // Store for cleanup
    result.results.forEach(r => {
      if (r.success && r.data && r.data.id) {
        createdUserIds.push(r.data.id);
      }
    });
    
    console.log(`Concurrent bulk create: ${result.successful} successful`);
  });
  
  it("should measure bulk operation performance", async () => {
    const users = BulkTestDataGenerator.generateUsers(5);
    const startTime = Date.now();
    
    const result = await bulkService.bulkCreate(users, { batchSize: 2 });
    
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    expect(result.successful).to.be.greaterThan(0);
    expect(duration).to.be.lessThan(30000); // Should complete within 30 seconds
    
    // Store for cleanup
    result.results.forEach(r => {
      if (r.success && r.data && r.data.id) {
        createdUserIds.push(r.data.id);
      }
    });
    
    console.log(`Bulk operation took ${duration}ms for ${result.total} items`);
    console.log(`Average: ${(duration / result.total).toFixed(2)}ms per item`);
  });
  
  it("should handle partial failures gracefully", async () => {
    const users = BulkTestDataGenerator.generateUsers(5);
    // Add some invalid users
    users.push({
      name: "",
      email: "invalid",
      gender: "invalid",
      status: "invalid"
    });
    users.push({
      name: "",
      email: "invalid2",
      gender: "invalid",
      status: "invalid"
    });
    
    const result = await bulkService.bulkCreate(users, { stopOnError: false });
    
    expect(result.total).to.equal(7);
    expect(result.successful).to.be.greaterThan(0);
    expect(result.failed).to.be.greaterThan(0);
    
    // Store successful for cleanup
    result.results.forEach(r => {
      if (r.success && r.data && r.data.id) {
        createdUserIds.push(r.data.id);
      }
    });
    
    console.log(`Partial failure handled: ${result.successful} successful, ${result.failed} failed`);
  });
  
  it("should retry failed bulk operations", async () => {
    const users = BulkTestDataGenerator.generateUsers(3);
    
    // First attempt
    let result = await bulkService.bulkCreate(users);
    
    // Retry failed operations
    const failedResources = result.errors.map((error, index) => 
      users[error.index]
    ).filter(Boolean);
    
    if (failedResources.length > 0) {
      const retryResult = await bulkService.bulkCreate(failedResources);
      result.successful += retryResult.successful;
      result.failed = retryResult.failed;
    }
    
    // Store for cleanup
    result.results.forEach(r => {
      if (r.success && r.data && r.data.id) {
        createdUserIds.push(r.data.id);
      }
    });
    
    expect(result.successful).to.be.greaterThan(0);
    console.log(`With retry: ${result.successful} successful`);
  });
});

// Advanced Bulk Operations
describe("Advanced Bulk Operations", () => {
  let bulkService;
  
  beforeEach(() => {
    bulkService = new BulkOperationsService(request, TOKEN);
  });
  
  it("should handle large bulk operations", async function() {
    this.timeout(60000); // 60 seconds timeout
    
    const users = BulkTestDataGenerator.generateUsers(20);
    const result = await bulkService.bulkCreate(users, { 
      batchSize: 5,
      delay: 200 
    });
    
    expect(result.total).to.equal(20);
    expect(result.successful).to.be.greaterThan(0);
    
    // Cleanup
    const userIds = result.results
      .filter(r => r.success && r.data)
      .map(r => r.data.id);
    
    if (userIds.length > 0) {
      await bulkService.bulkDelete(userIds);
    }
    
    console.log(`Large bulk operation: ${result.successful} successful`);
  });
  
  it("should optimize batch size for performance", async () => {
    const users = BulkTestDataGenerator.generateUsers(15);
    
    const batchSizes = [1, 5, 10];
    const results = [];
    
    for (const batchSize of batchSizes) {
      const startTime = Date.now();
      const result = await bulkService.bulkCreate(users, { batchSize });
      const endTime = Date.now();
      
      results.push({
        batchSize,
        duration: endTime - startTime,
        successful: result.successful
      });
      
      // Cleanup
      const userIds = result.results
        .filter(r => r.success && r.data)
        .map(r => r.data.id);
      
      if (userIds.length > 0) {
        await bulkService.bulkDelete(userIds);
      }
    }
    
    console.log("Batch size performance comparison:", results);
    expect(results.length).to.equal(batchSizes.length);
  });
  
  it("should handle rate limiting in bulk operations", async () => {
    const users = BulkTestDataGenerator.generateUsers(10);
    
    // Use smaller batch size and longer delay to avoid rate limiting
    const result = await bulkService.bulkCreate(users, {
      batchSize: 2,
      delay: 500 // 500ms delay between batches
    });
    
    expect(result.total).to.equal(10);
    
    // Cleanup
    const userIds = result.results
      .filter(r => r.success && r.data)
      .map(r => r.data.id);
    
    if (userIds.length > 0) {
      await bulkService.bulkDelete(userIds);
    }
    
    console.log(`Rate-limited bulk operation: ${result.successful} successful`);
  });
});

export { 
  BulkOperationsService, 
  BulkTestDataGenerator 
};


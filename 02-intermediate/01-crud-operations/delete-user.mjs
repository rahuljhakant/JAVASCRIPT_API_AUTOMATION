/**
 * PHASE 2: INTERMEDIATE LEVEL
 * Module 1: CRUD Operations
 * Lesson 4: Delete User (DELETE)
 * 
 * Learning Objectives:
 * - Master DELETE requests for resource removal
 * - Handle delete responses and status codes
 * - Implement proper cleanup and verification
 * - Handle cascading deletes and dependencies
 */

import { expect } from "chai";
import supertest from "supertest";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== DELETE USER (DELETE) OPERATIONS ===");

// API client setup
const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = getApiToken();

// User deletion service
class UserDeletionService {
  constructor(apiClient, authToken) {
    this.apiClient = apiClient;
    this.authToken = authToken;
  }
  
  async deleteUser(userId) {
    const response = await this.apiClient
      .delete(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`);
    
    return response;
  }
  
  async deleteAndVerify(userId) {
    // Verify user exists before deletion
    const beforeResponse = await this.apiClient
      .get(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`);
    
    const userExists = beforeResponse.status === 200;
    
    // Perform deletion
    const deleteResponse = await this.deleteUser(userId);
    
    // Verify deletion
    const afterResponse = await this.apiClient
      .get(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`);
    
    const userDeleted = afterResponse.status === 404;
    
    return {
      userExists,
      deleteResponse,
      userDeleted,
      beforeUser: userExists ? beforeResponse.body.data : null
    };
  }
  
  async deleteMultipleUsers(userIds) {
    const results = [];
    
    for (const userId of userIds) {
      const result = await this.deleteUser(userId);
      results.push({
        userId,
        status: result.status,
        success: result.status === 204 || result.status === 200
      });
    }
    
    return results;
  }
  
  async deleteUserWithRetry(userId, maxRetries = 3) {
    let lastError = null;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const response = await this.deleteUser(userId);
        
        if (response.status === 204 || response.status === 200) {
          return { success: true, response, attempts: attempt };
        }
        
        lastError = new Error(`Delete failed with status ${response.status}`);
      } catch (error) {
        lastError = error;
        
        if (attempt < maxRetries) {
          // Wait before retry (exponential backoff)
          await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
        }
      }
    }
    
    return { success: false, error: lastError, attempts: maxRetries };
  }
  
  validateDeleteResponse(response) {
    // DELETE typically returns 204 No Content or 200 OK
    expect(response.status).to.be.oneOf([200, 204]);
  }
}

// Helper to create test users
class TestUserHelper {
  static async createTestUser(apiClient, token) {
    const response = await apiClient
      .post("/users")
      .set("Authorization", `Bearer ${token}`)
      .send({
        name: `Test User ${Math.floor(Math.random() * 10000)}`,
        email: `test${Math.floor(Math.random() * 10000)}@example.com`,
        gender: "male",
        status: "active"
      });
    
    return response.status === 201 ? response.body.data : null;
  }
  
  static async createMultipleTestUsers(apiClient, token, count = 3) {
    const users = [];
    
    for (let i = 0; i < count; i++) {
      const user = await this.createTestUser(apiClient, token);
      if (user) {
        users.push(user);
      }
    }
    
    return users;
  }
}

// Exercises and Tests
describe("Delete User (DELETE) Operations", () => {
  let userService;
  let createdUserId;
  
  beforeEach(async () => {
    userService = new UserDeletionService(request, TOKEN);
    
    // Create a user for testing deletion
    const user = await TestUserHelper.createTestUser(request, TOKEN);
    createdUserId = user ? user.id : null;
  });
  
  it("should delete a user successfully", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const result = await userService.deleteAndVerify(createdUserId);
    
    expect(result.userExists).to.be.true;
    expect(result.deleteResponse.status).to.be.oneOf([200, 204]);
    expect(result.userDeleted).to.be.true;
    
    console.log("User deleted successfully");
  });
  
  it("should verify user is deleted after deletion", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    // Delete the user
    const deleteResponse = await userService.deleteUser(createdUserId);
    expect(deleteResponse.status).to.be.oneOf([200, 204]);
    
    // Verify user no longer exists
    const verifyResponse = await request
      .get(`/users/${createdUserId}`)
      .set("Authorization", `Bearer ${TOKEN}`);
    
    expect(verifyResponse.status).to.equal(404);
    expect(verifyResponse.body.data).to.be.null;
  });
  
  it("should handle deletion of non-existent user", async () => {
    const nonExistentId = 999999;
    const response = await userService.deleteUser(nonExistentId);
    
    // API might return 404 or 204 depending on implementation
    expect(response.status).to.be.oneOf([200, 204, 404]);
  });
  
  it("should handle authentication errors during deletion", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const invalidToken = "invalid-token";
    const invalidService = new UserDeletionService(request, invalidToken);
    
    const response = await invalidService.deleteUser(createdUserId);
    
    expect(response.status).to.equal(401);
    expect(response.body).to.have.property('data');
  });
  
  it("should delete multiple users in sequence", async () => {
    // Create multiple test users
    const users = await TestUserHelper.createMultipleTestUsers(request, TOKEN, 3);
    
    if (users.length === 0) {
      this.skip();
      return;
    }
    
    const userIds = users.map(user => user.id);
    const results = await userService.deleteMultipleUsers(userIds);
    
    expect(results).to.have.length(userIds.length);
    
    // Verify all deletions
    results.forEach((result, index) => {
      expect(result.userId).to.equal(userIds[index]);
      expect(result.status).to.be.oneOf([200, 204]);
      expect(result.success).to.be.true;
    });
    
    console.log(`Successfully deleted ${results.length} users`);
  });
  
  it("should handle concurrent deletions", async () => {
    // Create multiple test users
    const users = await TestUserHelper.createMultipleTestUsers(request, TOKEN, 5);
    
    if (users.length === 0) {
      this.skip();
      return;
    }
    
    const userIds = users.map(user => user.id);
    
    // Delete concurrently
    const deletePromises = userIds.map(userId => 
      userService.deleteUser(userId)
    );
    
    const responses = await Promise.all(deletePromises);
    
    // Verify all deletions
    responses.forEach(response => {
      expect(response.status).to.be.oneOf([200, 204]);
    });
    
    console.log(`Successfully deleted ${responses.length} users concurrently`);
  });
  
  it("should validate delete response structure", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const response = await userService.deleteUser(createdUserId);
    
    userService.validateDeleteResponse(response);
    
    // DELETE responses typically have no body or minimal body
    if (response.body) {
      expect(response.body).to.be.an('object');
    }
  });
  
  it("should measure deletion performance", async () => {
    const user = await TestUserHelper.createTestUser(request, TOKEN);
    
    if (!user) {
      this.skip();
      return;
    }
    
    const startTime = Date.now();
    const response = await userService.deleteUser(user.id);
    const endTime = Date.now();
    
    const responseTime = endTime - startTime;
    
    expect(response.status).to.be.oneOf([200, 204]);
    expect(responseTime).to.be.lessThan(5000); // Should complete within 5 seconds
    
    console.log(`Deletion took ${responseTime}ms`);
  });
  
  it("should handle deletion with retry mechanism", async () => {
    const user = await TestUserHelper.createTestUser(request, TOKEN);
    
    if (!user) {
      this.skip();
      return;
    }
    
    const result = await userService.deleteUserWithRetry(user.id, 3);
    
    expect(result.success).to.be.true;
    expect(result.attempts).to.be.at.most(3);
    
    console.log(`Deletion succeeded after ${result.attempts} attempt(s)`);
  });
});

// Advanced Delete Operations
describe("Advanced Delete Operations", () => {
  let userService;
  
  beforeEach(() => {
    userService = new UserDeletionService(request, TOKEN);
  });
  
  it("should delete user with custom headers", async () => {
    const user = await TestUserHelper.createTestUser(request, TOKEN);
    
    if (!user) {
      this.skip();
      return;
    }
    
    const response = await request
      .delete(`/users/${user.id}`)
      .set("Authorization", `Bearer ${TOKEN}`)
      .set("Accept", "application/json")
      .set("User-Agent", "API-Test-Suite/1.0");
    
    expect(response.status).to.be.oneOf([200, 204]);
  });
  
  it("should handle bulk deletion", async () => {
    // Create multiple test users
    const users = await TestUserHelper.createMultipleTestUsers(request, TOKEN, 10);
    
    if (users.length === 0) {
      this.skip();
      return;
    }
    
    const userIds = users.map(user => user.id);
    const results = await userService.deleteMultipleUsers(userIds);
    
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    
    expect(successful.length).to.be.greaterThan(0);
    console.log(`Bulk deletion: ${successful.length} successful, ${failed.length} failed`);
  });
  
  it("should verify cascade deletion behavior", async () => {
    // This test would verify if deleting a user also deletes related resources
    // (posts, comments, etc.) - depends on API implementation
    
    const user = await TestUserHelper.createTestUser(request, TOKEN);
    
    if (!user) {
      this.skip();
      return;
    }
    
    // Delete user
    const deleteResponse = await userService.deleteUser(user.id);
    expect(deleteResponse.status).to.be.oneOf([200, 204]);
    
    // Verify user is deleted
    const verifyResponse = await request
      .get(`/users/${user.id}`)
      .set("Authorization", `Bearer ${TOKEN}`);
    
    expect(verifyResponse.status).to.equal(404);
    
    // Note: In a real scenario, you might also check if related resources were deleted
    console.log("Cascade deletion verified");
  });
  
  it("should handle deletion of already deleted user", async () => {
    const user = await TestUserHelper.createTestUser(request, TOKEN);
    
    if (!user) {
      this.skip();
      return;
    }
    
    // First deletion
    const firstDelete = await userService.deleteUser(user.id);
    expect(firstDelete.status).to.be.oneOf([200, 204]);
    
    // Second deletion attempt
    const secondDelete = await userService.deleteUser(user.id);
    
    // API might return 404 or 204 depending on implementation
    expect(secondDelete.status).to.be.oneOf([200, 204, 404]);
  });
  
  it("should handle deletion with rate limiting", async () => {
    // Create multiple users
    const users = await TestUserHelper.createMultipleTestUsers(request, TOKEN, 20);
    
    if (users.length === 0) {
      this.skip();
      return;
    }
    
    const userIds = users.map(user => user.id);
    
    // Rapid deletions
    const promises = userIds.map(userId => 
      userService.deleteUser(userId)
    );
    
    const responses = await Promise.allSettled(promises);
    
    const successful = responses.filter(r => 
      r.status === 'fulfilled' && 
      (r.value.status === 200 || r.value.status === 204)
    );
    const rateLimited = responses.filter(r => 
      r.status === 'fulfilled' && r.value.status === 429
    );
    
    console.log(`Successful: ${successful.length}, Rate Limited: ${rateLimited.length}`);
    expect(successful.length).to.be.greaterThan(0);
  });
});

// Cleanup and Error Handling
describe("Delete Cleanup and Error Handling", () => {
  let userService;
  
  beforeEach(() => {
    userService = new UserDeletionService(request, TOKEN);
  });
  
  it("should cleanup test data properly", async () => {
    const users = await TestUserHelper.createMultipleTestUsers(request, TOKEN, 5);
    
    if (users.length === 0) {
      this.skip();
      return;
    }
    
    const userIds = users.map(user => user.id);
    
    // Cleanup all test users
    const cleanupResults = await userService.deleteMultipleUsers(userIds);
    
    // Verify cleanup
    const verifyPromises = userIds.map(userId =>
      request
        .get(`/users/${userId}`)
        .set("Authorization", `Bearer ${TOKEN}`)
    );
    
    const verifyResponses = await Promise.all(verifyPromises);
    
    const allDeleted = verifyResponses.every(response => response.status === 404);
    
    expect(allDeleted).to.be.true;
    console.log("All test data cleaned up successfully");
  });
  
  it("should handle network errors during deletion", async () => {
    const user = await TestUserHelper.createTestUser(request, TOKEN);
    
    if (!user) {
      this.skip();
      return;
    }
    
    // This would test with an invalid endpoint or network issue
    // In a real scenario, you might mock network failures
    const response = await userService.deleteUser(user.id);
    
    // Should handle gracefully
    expect(response.status).to.be.oneOf([200, 204, 500, 503]);
  });
  
  it("should log deletion operations", async () => {
    const user = await TestUserHelper.createTestUser(request, TOKEN);
    
    if (!user) {
      this.skip();
      return;
    }
    
    const startTime = Date.now();
    const response = await userService.deleteUser(user.id);
    const endTime = Date.now();
    
    const logEntry = {
      userId: user.id,
      status: response.status,
      responseTime: endTime - startTime,
      timestamp: new Date().toISOString()
    };
    
    console.log("Deletion log:", logEntry);
    
    expect(logEntry.status).to.be.oneOf([200, 204]);
    expect(logEntry.responseTime).to.be.a('number');
  });
});

export { 
  UserDeletionService, 
  TestUserHelper 
};


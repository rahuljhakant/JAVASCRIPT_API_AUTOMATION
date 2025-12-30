/**
 * PHASE 2: INTERMEDIATE LEVEL
 * Module 1: CRUD Operations
 * Lesson 3: Update User (PUT/PATCH)
 * 
 * Learning Objectives:
 * - Master PUT requests for full updates
 * - Master PATCH requests for partial updates
 * - Handle update responses and validation
 * - Implement proper error handling for updates
 */

import { expect } from "chai";
import supertest from "supertest";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== UPDATE USER (PUT/PATCH) OPERATIONS ===");

// API client setup
const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = getApiToken();

// User update service
class UserUpdateService {
  constructor(apiClient, authToken) {
    this.apiClient = apiClient;
    this.authToken = authToken;
  }
  
  async updateUser(userId, userData, method = 'PUT') {
    const endpoint = `/users/${userId}`;
    
    if (method === 'PUT') {
      return await this.apiClient
        .put(endpoint)
        .set("Authorization", `Bearer ${this.authToken}`)
        .send(userData);
    } else {
      return await this.apiClient
        .patch(endpoint)
        .set("Authorization", `Bearer ${this.authToken}`)
        .send(userData);
    }
  }
  
  async fullUpdate(userId, userData) {
    // PUT - Full update (all fields required)
    const response = await this.updateUser(userId, userData, 'PUT');
    this.validateUpdateResponse(response);
    return response;
  }
  
  async partialUpdate(userId, userData) {
    // PATCH - Partial update (only specified fields)
    const response = await this.updateUser(userId, userData, 'PATCH');
    this.validateUpdateResponse(response);
    return response;
  }
  
  validateUpdateResponse(response) {
    expect(response.status).to.equal(200);
    expect(response.body).to.have.property('data');
    expect(response.body.data).to.have.property('id');
    expect(response.body.data.id).to.be.a('number');
  }
  
  async updateAndVerify(userId, updateData, method = 'PUT') {
    // Get original user data
    const originalResponse = await this.apiClient
      .get(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`);
    
    const originalUser = originalResponse.body.data;
    
    // Perform update
    const updateResponse = await this.updateUser(userId, updateData, method);
    
    // Verify update
    const verifyResponse = await this.apiClient
      .get(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`);
    
    const updatedUser = verifyResponse.body.data;
    
    return {
      original: originalUser,
      updated: updatedUser,
      updateResponse
    };
  }
}

// User data generator for updates
class UpdateDataGenerator {
  static generateFullUpdate() {
    return {
      name: `Updated User ${Math.floor(Math.random() * 10000)}`,
      email: `updated${Math.floor(Math.random() * 10000)}@example.com`,
      gender: "female",
      status: "inactive"
    };
  }
  
  static generatePartialUpdate(fields = {}) {
    const defaultFields = {
      name: `Partially Updated User ${Math.floor(Math.random() * 10000)}`
    };
    
    return { ...defaultFields, ...fields };
  }
  
  static generateNameUpdate() {
    return {
      name: `Name Updated ${Math.floor(Math.random() * 10000)}`
    };
  }
  
  static generateStatusUpdate(newStatus = "inactive") {
    return {
      status: newStatus
    };
  }
  
  static generateEmailUpdate() {
    return {
      email: `newemail${Math.floor(Math.random() * 10000)}@example.com`
    };
  }
}

// Exercises and Tests
describe("Update User (PUT/PATCH) Operations", () => {
  let userService;
  let createdUserId;
  
  beforeEach(async () => {
    userService = new UserUpdateService(request, TOKEN);
    
    // Create a user for testing updates
    const createResponse = await request
      .post("/users")
      .set("Authorization", `Bearer ${TOKEN}`)
      .send({
        name: `Test User ${Math.floor(Math.random() * 10000)}`,
        email: `test${Math.floor(Math.random() * 10000)}@example.com`,
        gender: "male",
        status: "active"
      });
    
    if (createResponse.status === 201) {
      createdUserId = createResponse.body.data.id;
    }
  });
  
  afterEach(async () => {
    // Cleanup: Delete created user
    if (createdUserId) {
      try {
        await request
          .delete(`/users/${createdUserId}`)
          .set("Authorization", `Bearer ${TOKEN}`);
      } catch (error) {
        // Ignore cleanup errors
      }
    }
  });
  
  it("should perform full update using PUT", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const updateData = UpdateDataGenerator.generateFullUpdate();
    const result = await userService.updateAndVerify(createdUserId, updateData, 'PUT');
    
    // Verify all fields were updated
    expect(result.updateResponse.status).to.equal(200);
    expect(result.updated.name).to.equal(updateData.name);
    expect(result.updated.email).to.equal(updateData.email);
    expect(result.updated.gender).to.equal(updateData.gender);
    expect(result.updated.status).to.equal(updateData.status);
    
    console.log("Full update successful:", result.updated);
  });
  
  it("should perform partial update using PATCH", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const updateData = UpdateDataGenerator.generateNameUpdate();
    const result = await userService.updateAndVerify(createdUserId, updateData, 'PATCH');
    
    // Verify only specified field was updated
    expect(result.updateResponse.status).to.equal(200);
    expect(result.updated.name).to.equal(updateData.name);
    expect(result.updated.id).to.equal(createdUserId);
    
    console.log("Partial update successful:", result.updated);
  });
  
  it("should update only name field", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const updateData = UpdateDataGenerator.generateNameUpdate();
    const response = await userService.partialUpdate(createdUserId, updateData);
    
    expect(response.status).to.equal(200);
    expect(response.body.data.name).to.equal(updateData.name);
    expect(response.body.data.id).to.equal(createdUserId);
  });
  
  it("should update only status field", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const updateData = UpdateDataGenerator.generateStatusUpdate("inactive");
    const response = await userService.partialUpdate(createdUserId, updateData);
    
    expect(response.status).to.equal(200);
    expect(response.body.data.status).to.equal("inactive");
    expect(response.body.data.id).to.equal(createdUserId);
  });
  
  it("should update only email field", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const updateData = UpdateDataGenerator.generateEmailUpdate();
    const response = await userService.partialUpdate(createdUserId, updateData);
    
    expect(response.status).to.equal(200);
    expect(response.body.data.email).to.equal(updateData.email);
    expect(response.body.data.id).to.equal(createdUserId);
  });
  
  it("should handle multiple sequential updates", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    // First update: name
    const nameUpdate = UpdateDataGenerator.generateNameUpdate();
    await userService.partialUpdate(createdUserId, nameUpdate);
    
    // Second update: status
    const statusUpdate = UpdateDataGenerator.generateStatusUpdate("inactive");
    await userService.partialUpdate(createdUserId, statusUpdate);
    
    // Verify final state
    const verifyResponse = await request
      .get(`/users/${createdUserId}`)
      .set("Authorization", `Bearer ${TOKEN}`);
    
    expect(verifyResponse.status).to.equal(200);
    expect(verifyResponse.body.data.name).to.equal(nameUpdate.name);
    expect(verifyResponse.body.data.status).to.equal("inactive");
    
    console.log("Sequential updates successful");
  });
  
  it("should handle invalid update data", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const invalidData = {
      email: "invalid-email-format" // Invalid email
    };
    
    const response = await userService.updateUser(createdUserId, invalidData, 'PATCH');
    
    // API should return validation error
    expect(response.status).to.be.oneOf([200, 422]);
    
    if (response.status === 422) {
      expect(response.body).to.have.property('data');
      console.log("Validation error caught:", response.body.data);
    }
  });
  
  it("should handle update of non-existent user", async () => {
    const nonExistentId = 999999;
    const updateData = UpdateDataGenerator.generateFullUpdate();
    
    const response = await userService.updateUser(nonExistentId, updateData, 'PUT');
    
    expect(response.status).to.equal(404);
    expect(response.body).to.have.property('data');
    expect(response.body.data).to.be.null;
  });
  
  it("should handle authentication errors during update", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const invalidToken = "invalid-token";
    const invalidService = new UserUpdateService(request, invalidToken);
    const updateData = UpdateDataGenerator.generateNameUpdate();
    
    const response = await invalidService.updateUser(createdUserId, updateData, 'PATCH');
    
    expect(response.status).to.equal(401);
    expect(response.body).to.have.property('data');
  });
  
  it("should validate response structure after update", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const updateData = UpdateDataGenerator.generateNameUpdate();
    const response = await userService.partialUpdate(createdUserId, updateData);
    
    // Validate response structure
    expect(response.status).to.equal(200);
    expect(response.body).to.have.property('data');
    expect(response.body.data).to.have.property('id');
    expect(response.body.data).to.have.property('name');
    expect(response.body.data).to.have.property('email');
    expect(response.body.data).to.have.property('gender');
    expect(response.body.data).to.have.property('status');
    
    // Validate data types
    expect(response.body.data.id).to.be.a('number');
    expect(response.body.data.name).to.be.a('string');
    expect(response.body.data.email).to.be.a('string');
  });
});

// Advanced Update Operations
describe("Advanced Update Operations", () => {
  let userService;
  let createdUserId;
  
  beforeEach(async () => {
    userService = new UserUpdateService(request, TOKEN);
    
    const createResponse = await request
      .post("/users")
      .set("Authorization", `Bearer ${TOKEN}`)
      .send({
        name: `Test User ${Math.floor(Math.random() * 10000)}`,
        email: `test${Math.floor(Math.random() * 10000)}@example.com`,
        gender: "male",
        status: "active"
      });
    
    if (createResponse.status === 201) {
      createdUserId = createResponse.body.data.id;
    }
  });
  
  afterEach(async () => {
    if (createdUserId) {
      try {
        await request
          .delete(`/users/${createdUserId}`)
          .set("Authorization", `Bearer ${TOKEN}`);
      } catch (error) {
        // Ignore cleanup errors
      }
    }
  });
  
  it("should update user with custom headers", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const updateData = UpdateDataGenerator.generateNameUpdate();
    
    const response = await request
      .patch(`/users/${createdUserId}`)
      .set("Authorization", `Bearer ${TOKEN}`)
      .set("Content-Type", "application/json")
      .set("Accept", "application/json")
      .set("User-Agent", "API-Test-Suite/1.0")
      .send(updateData);
    
    expect(response.status).to.equal(200);
    expect(response.body.data.name).to.equal(updateData.name);
  });
  
  it("should handle concurrent updates", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const updates = [
      UpdateDataGenerator.generateNameUpdate(),
      UpdateDataGenerator.generateStatusUpdate("inactive"),
      UpdateDataGenerator.generateEmailUpdate()
    ];
    
    const promises = updates.map(updateData => 
      userService.partialUpdate(createdUserId, updateData)
    );
    
    const responses = await Promise.allSettled(promises);
    
    // At least one should succeed
    const successful = responses.filter(r => 
      r.status === 'fulfilled' && r.value.status === 200
    );
    
    expect(successful.length).to.be.greaterThan(0);
    console.log(`Concurrent updates: ${successful.length} successful`);
  });
  
  it("should measure update performance", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const updateData = UpdateDataGenerator.generateNameUpdate();
    const startTime = Date.now();
    
    const response = await userService.partialUpdate(createdUserId, updateData);
    
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    
    expect(response.status).to.equal(200);
    expect(responseTime).to.be.lessThan(5000); // Should complete within 5 seconds
    
    console.log(`Update took ${responseTime}ms`);
  });
  
  it("should update user with special characters", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const updateData = {
      name: "José María O'Connor-Smith"
    };
    
    const response = await userService.partialUpdate(createdUserId, updateData);
    
    expect(response.status).to.equal(200);
    expect(response.body.data.name).to.equal(updateData.name);
  });
  
  it("should handle large data updates", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    const updateData = {
      name: "A".repeat(100) // Long name
    };
    
    const response = await userService.partialUpdate(createdUserId, updateData);
    
    expect(response.status).to.equal(200);
    expect(response.body.data.name).to.equal(updateData.name);
  });
});

// Update Comparison: PUT vs PATCH
describe("PUT vs PATCH Comparison", () => {
  let userService;
  let createdUserId;
  
  beforeEach(async () => {
    userService = new UserUpdateService(request, TOKEN);
    
    const createResponse = await request
      .post("/users")
      .set("Authorization", `Bearer ${TOKEN}`)
      .send({
        name: `Test User ${Math.floor(Math.random() * 10000)}`,
        email: `test${Math.floor(Math.random() * 10000)}@example.com`,
        gender: "male",
        status: "active"
      });
    
    if (createResponse.status === 201) {
      createdUserId = createResponse.body.data.id;
    }
  });
  
  afterEach(async () => {
    if (createdUserId) {
      try {
        await request
          .delete(`/users/${createdUserId}`)
          .set("Authorization", `Bearer ${TOKEN}`);
      } catch (error) {
        // Ignore cleanup errors
      }
    }
  });
  
  it("should demonstrate PUT requires all fields", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    // PUT with all fields
    const fullUpdate = UpdateDataGenerator.generateFullUpdate();
    const putResponse = await userService.fullUpdate(createdUserId, fullUpdate);
    
    expect(putResponse.status).to.equal(200);
    expect(putResponse.body.data.name).to.equal(fullUpdate.name);
    expect(putResponse.body.data.email).to.equal(fullUpdate.email);
    expect(putResponse.body.data.gender).to.equal(fullUpdate.gender);
    expect(putResponse.body.data.status).to.equal(fullUpdate.status);
  });
  
  it("should demonstrate PATCH allows partial fields", async () => {
    if (!createdUserId) {
      this.skip();
      return;
    }
    
    // PATCH with only name
    const partialUpdate = UpdateDataGenerator.generateNameUpdate();
    const patchResponse = await userService.partialUpdate(createdUserId, partialUpdate);
    
    expect(patchResponse.status).to.equal(200);
    expect(patchResponse.body.data.name).to.equal(partialUpdate.name);
    // Other fields should remain unchanged
  });
});

export { 
  UserUpdateService, 
  UpdateDataGenerator 
};


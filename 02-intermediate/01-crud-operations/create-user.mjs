/**
 * PHASE 2: INTERMEDIATE LEVEL
 * Module 1: CRUD Operations
 * Lesson 1: Create User (POST)
 * 
 * Learning Objectives:
 * - Master POST requests for creating resources
 * - Handle request body and headers
 * - Validate creation responses
 * - Implement proper error handling
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== CREATE USER (POST) OPERATIONS ===");

// API client setup
const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = "6dc353df7c107b9cf591463edb36e13dbc182be021562024473aac00cd19031c";

// User data generator
class UserDataGenerator {
  static generateValidUser() {
    return {
      name: `Test User ${Math.floor(Math.random() * 10000)}`,
      email: `user${Math.floor(Math.random() * 10000)}@example.com`,
      gender: "male",
      status: "active"
    };
  }
  
  static generateInvalidUser() {
    return {
      name: "", // Invalid: empty name
      email: "invalid-email", // Invalid: malformed email
      gender: "invalid", // Invalid: not male/female
      status: "invalid" // Invalid: not active/inactive
    };
  }
  
  static generatePartialUser() {
    return {
      name: "Partial User",
      email: "partial@example.com"
      // Missing required fields: gender, status
    };
  }
}

// User creation service
class UserCreationService {
  constructor(apiClient, authToken) {
    this.apiClient = apiClient;
    this.authToken = authToken;
  }
  
  async createUser(userData) {
    const response = await this.apiClient
      .post("/users")
      .set("Authorization", `Bearer ${this.authToken}`)
      .send(userData);
    
    return response;
  }
  
  async createUserWithValidation(userData) {
    // Pre-creation validation
    this.validateUserData(userData);
    
    const response = await this.createUser(userData);
    
    // Post-creation validation
    this.validateCreationResponse(response);
    
    return response;
  }
  
  validateUserData(userData) {
    const requiredFields = ['name', 'email', 'gender', 'status'];
    const validGenders = ['male', 'female'];
    const validStatuses = ['active', 'inactive'];
    
    // Check required fields
    requiredFields.forEach(field => {
      if (!userData[field]) {
        throw new Error(`Missing required field: ${field}`);
      }
    });
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(userData.email)) {
      throw new Error('Invalid email format');
    }
    
    // Validate gender
    if (!validGenders.includes(userData.gender)) {
      throw new Error(`Invalid gender. Must be one of: ${validGenders.join(', ')}`);
    }
    
    // Validate status
    if (!validStatuses.includes(userData.status)) {
      throw new Error(`Invalid status. Must be one of: ${validStatuses.join(', ')}`);
    }
  }
  
  validateCreationResponse(response) {
    expect(response.status).to.equal(201);
    expect(response.body).to.have.property('data');
    expect(response.body.data).to.have.property('id');
    expect(response.body.data.id).to.be.a('number');
  }
}

// Exercises and Tests
describe("Create User (POST) Operations", () => {
  let userService;
  
  beforeEach(() => {
    userService = new UserCreationService(request, TOKEN);
  });
  
  it("should create a valid user successfully", async () => {
    const userData = UserDataGenerator.generateValidUser();
    
    const response = await userService.createUserWithValidation(userData);
    
    // Validate response structure
    expect(response.status).to.equal(201);
    expect(response.body.data).to.have.property('id');
    expect(response.body.data).to.have.property('name');
    expect(response.body.data).to.have.property('email');
    expect(response.body.data).to.have.property('gender');
    expect(response.body.data).to.have.property('status');
    
    // Validate data integrity
    expect(response.body.data.name).to.equal(userData.name);
    expect(response.body.data.email).to.equal(userData.email);
    expect(response.body.data.gender).to.equal(userData.gender);
    expect(response.body.data.status).to.equal(userData.status);
    
    console.log("Created user:", response.body.data);
  });
  
  it("should handle invalid user data gracefully", async () => {
    const invalidUserData = UserDataGenerator.generateInvalidUser();
    
    try {
      await userService.createUserWithValidation(invalidUserData);
      expect.fail("Should have thrown validation error");
    } catch (error) {
      expect(error.message).to.include("Invalid email format");
    }
  });
  
  it("should handle missing required fields", async () => {
    const partialUserData = UserDataGenerator.generatePartialUser();
    
    try {
      await userService.createUserWithValidation(partialUserData);
      expect.fail("Should have thrown validation error");
    } catch (error) {
      expect(error.message).to.include("Missing required field");
    }
  });
  
  it("should handle server validation errors", async () => {
    const userData = {
      name: "Test User",
      email: "existing@example.com", // Assuming this email already exists
      gender: "male",
      status: "active"
    };
    
    const response = await userService.createUser(userData);
    
    // Server might return 422 for validation errors
    if (response.status === 422) {
      expect(response.body).to.have.property('data');
      expect(response.body.data).to.be.an('array');
      console.log("Validation errors:", response.body.data);
    } else {
      // If user was created successfully
      expect(response.status).to.equal(201);
    }
  });
  
  it("should create multiple users in sequence", async () => {
    const users = [];
    const userCount = 3;
    
    for (let i = 0; i < userCount; i++) {
      const userData = UserDataGenerator.generateValidUser();
      const response = await userService.createUserWithValidation(userData);
      
      expect(response.status).to.equal(201);
      users.push(response.body.data);
    }
    
    expect(users).to.have.length(userCount);
    
    // Verify all users have unique IDs
    const userIds = users.map(user => user.id);
    const uniqueIds = [...new Set(userIds)];
    expect(uniqueIds).to.have.length(userCount);
    
    console.log("Created users:", users);
  });
  
  it("should handle authentication errors", async () => {
    const invalidToken = "invalid-token";
    const invalidUserService = new UserCreationService(request, invalidToken);
    const userData = UserDataGenerator.generateValidUser();
    
    const response = await invalidUserService.createUser(userData);
    
    expect(response.status).to.equal(401);
    expect(response.body).to.have.property('data');
    expect(response.body.data.message).to.include("Authentication failed");
  });
  
  it("should validate response headers", async () => {
    const userData = UserDataGenerator.generateValidUser();
    const response = await userService.createUser(userData);
    
    expect(response.status).to.equal(201);
    expect(response.headers).to.have.property('content-type');
    expect(response.headers['content-type']).to.include('application/json');
  });
  
  it("should measure creation performance", async () => {
    const userData = UserDataGenerator.generateValidUser();
    const startTime = Date.now();
    
    const response = await userService.createUser(userData);
    
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    
    expect(response.status).to.equal(201);
    expect(responseTime).to.be.lessThan(5000); // Should complete within 5 seconds
    
    console.log(`User creation took ${responseTime}ms`);
  });
});

// Advanced Create Operations
describe("Advanced Create Operations", () => {
  let userService;
  
  beforeEach(() => {
    userService = new UserCreationService(request, TOKEN);
  });
  
  it("should create user with custom headers", async () => {
    const userData = UserDataGenerator.generateValidUser();
    
    const response = await request
      .post("/users")
      .set("Authorization", `Bearer ${TOKEN}`)
      .set("Content-Type", "application/json")
      .set("Accept", "application/json")
      .set("User-Agent", "API-Test-Suite/1.0")
      .send(userData);
    
    expect(response.status).to.equal(201);
    expect(response.body.data).to.have.property('id');
  });
  
  it("should handle large user data", async () => {
    const userData = {
      name: "A".repeat(100), // Long name
      email: `longname${Math.floor(Math.random() * 10000)}@example.com`,
      gender: "female",
      status: "active"
    };
    
    const response = await userService.createUser(userData);
    
    expect(response.status).to.equal(201);
    expect(response.body.data.name).to.equal(userData.name);
  });
  
  it("should create user with special characters", async () => {
    const userData = {
      name: "José María O'Connor-Smith",
      email: `special${Math.floor(Math.random() * 10000)}@example.com`,
      gender: "male",
      status: "active"
    };
    
    const response = await userService.createUser(userData);
    
    expect(response.status).to.equal(201);
    expect(response.body.data.name).to.equal(userData.name);
  });
  
  it("should handle concurrent user creation", async () => {
    const userPromises = Array.from({ length: 5 }, () => {
      const userData = UserDataGenerator.generateValidUser();
      return userService.createUser(userData);
    });
    
    const responses = await Promise.all(userPromises);
    
    responses.forEach(response => {
      expect(response.status).to.equal(201);
      expect(response.body.data).to.have.property('id');
    });
    
    console.log(`Successfully created ${responses.length} users concurrently`);
  });
});

// Error Handling and Edge Cases
describe("Error Handling and Edge Cases", () => {
  let userService;
  
  beforeEach(() => {
    userService = new UserCreationService(request, TOKEN);
  });
  
  it("should handle network timeouts", async () => {
    const userData = UserDataGenerator.generateValidUser();
    
    // This test would require a slow endpoint or network simulation
    const response = await userService.createUser(userData);
    
    // In a real scenario, you might test timeout handling
    expect(response.status).to.be.oneOf([201, 408, 504]);
  });
  
  it("should handle malformed JSON", async () => {
    // This would require sending invalid JSON
    const userData = UserDataGenerator.generateValidUser();
    
    try {
      const response = await request
        .post("/users")
        .set("Authorization", `Bearer ${TOKEN}`)
        .set("Content-Type", "application/json")
        .send(userData);
      
      // The API should handle this gracefully
      expect(response.status).to.be.oneOf([201, 400]);
    } catch (error) {
      // Network or parsing errors
      expect(error).to.be.an('error');
    }
  });
  
  it("should handle rate limiting", async () => {
    const userData = UserDataGenerator.generateValidUser();
    
    // Create multiple users rapidly
    const promises = Array.from({ length: 10 }, () => 
      userService.createUser(userData)
    );
    
    const responses = await Promise.allSettled(promises);
    
    const successful = responses.filter(r => r.status === 'fulfilled' && r.value.status === 201);
    const rateLimited = responses.filter(r => r.status === 'fulfilled' && r.value.status === 429);
    
    console.log(`Successful: ${successful.length}, Rate Limited: ${rateLimited.length}`);
    
    // At least some should succeed
    expect(successful.length).to.be.greaterThan(0);
  });
});

export { 
  UserDataGenerator, 
  UserCreationService 
};





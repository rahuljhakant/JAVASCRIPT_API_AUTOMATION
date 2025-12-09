/**
 * PHASE 2: INTERMEDIATE LEVEL
 * Module 1: CRUD Operations
 * Lesson 2: Read User (GET)
 * 
 * Learning Objectives:
 * - Master GET requests for retrieving data
 * - Handle query parameters and filtering
 * - Implement pagination and sorting
 * - Validate response data structure
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== READ USER (GET) OPERATIONS ===");

// API client setup
const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = "6dc353df7c107b9cf591463edb36e13dbc182be021562024473aac00cd19031c";

// User retrieval service
class UserRetrievalService {
  constructor(apiClient, authToken) {
    this.apiClient = apiClient;
    this.authToken = authToken;
  }
  
  async getAllUsers(params = {}) {
    const response = await this.apiClient
      .get("/users")
      .set("Authorization", `Bearer ${this.authToken}`)
      .query(params);
    
    return response;
  }
  
  async getUserById(userId) {
    const response = await this.apiClient
      .get(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`);
    
    return response;
  }
  
  async searchUsers(criteria) {
    const response = await this.apiClient
      .get("/users")
      .set("Authorization", `Bearer ${this.authToken}`)
      .query(criteria);
    
    return response;
  }
  
  async getUsersWithPagination(page = 1, limit = 10) {
    const response = await this.apiClient
      .get("/users")
      .set("Authorization", `Bearer ${this.authToken}`)
      .query({ page, per_page: limit });
    
    return response;
  }
  
  async getUsersByGender(gender) {
    const response = await this.apiClient
      .get("/users")
      .set("Authorization", `Bearer ${this.authToken}`)
      .query({ gender });
    
    return response;
  }
  
  async getUsersByStatus(status) {
    const response = await this.apiClient
      .get("/users")
      .set("Authorization", `Bearer ${this.authToken}`)
      .query({ status });
    
    return response;
  }
  
  validateUserResponse(response) {
    expect(response.status).to.equal(200);
    expect(response.body).to.have.property('data');
    expect(response.body.data).to.be.an('array');
    
    if (response.body.data.length > 0) {
      const user = response.body.data[0];
      expect(user).to.have.property('id');
      expect(user).to.have.property('name');
      expect(user).to.have.property('email');
      expect(user).to.have.property('gender');
      expect(user).to.have.property('status');
    }
  }
  
  validateSingleUserResponse(response) {
    expect(response.status).to.equal(200);
    expect(response.body).to.have.property('data');
    expect(response.body.data).to.be.an('object');
    expect(response.body.data).to.have.property('id');
    expect(response.body.data).to.have.property('name');
    expect(response.body.data).to.have.property('email');
  }
}

// Query parameter builder
class QueryBuilder {
  constructor() {
    this.params = {};
  }
  
  page(pageNumber) {
    this.params.page = pageNumber;
    return this;
  }
  
  limit(limitNumber) {
    this.params.per_page = limitNumber;
    return this;
  }
  
  gender(genderType) {
    this.params.gender = genderType;
    return this;
  }
  
  status(statusType) {
    this.params.status = statusType;
    return this;
  }
  
  search(searchTerm) {
    this.params.name = searchTerm;
    return this;
  }
  
  build() {
    return this.params;
  }
}

// Data validation utilities
class DataValidator {
  static validateUser(user) {
    const requiredFields = ['id', 'name', 'email', 'gender', 'status'];
    
    requiredFields.forEach(field => {
      expect(user).to.have.property(field);
    });
    
    expect(user.id).to.be.a('number');
    expect(user.name).to.be.a('string');
    expect(user.email).to.be.a('string');
    expect(user.gender).to.be.oneOf(['male', 'female']);
    expect(user.status).to.be.oneOf(['active', 'inactive']);
  }
  
  static validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
  
  static validatePaginationResponse(response, expectedPage, expectedLimit) {
    expect(response.body).to.have.property('meta');
    expect(response.body.meta).to.have.property('pagination');
    
    const pagination = response.body.meta.pagination;
    expect(pagination).to.have.property('page');
    expect(pagination).to.have.property('per_page');
    expect(pagination).to.have.property('total');
    expect(pagination).to.have.property('pages');
    
    expect(pagination.page).to.equal(expectedPage);
    expect(pagination.per_page).to.equal(expectedLimit);
  }
}

// Exercises and Tests
describe("Read User (GET) Operations", () => {
  let userService;
  
  beforeEach(() => {
    userService = new UserRetrievalService(request, TOKEN);
  });
  
  it("should retrieve all users", async () => {
    const response = await userService.getAllUsers();
    
    userService.validateUserResponse(response);
    
    expect(response.body.data.length).to.be.greaterThan(0);
    console.log(`Retrieved ${response.body.data.length} users`);
  });
  
  it("should retrieve a specific user by ID", async () => {
    // First get a user ID from the list
    const allUsersResponse = await userService.getAllUsers();
    const userId = allUsersResponse.body.data[0].id;
    
    const response = await userService.getUserById(userId);
    
    userService.validateSingleUserResponse(response);
    expect(response.body.data.id).to.equal(userId);
    
    console.log("Retrieved user:", response.body.data);
  });
  
  it("should handle non-existent user ID", async () => {
    const nonExistentId = 999999;
    const response = await userService.getUserById(nonExistentId);
    
    expect(response.status).to.equal(404);
    expect(response.body).to.have.property('data');
    expect(response.body.data).to.be.null;
  });
  
  it("should retrieve users with pagination", async () => {
    const page = 1;
    const limit = 5;
    
    const response = await userService.getUsersWithPagination(page, limit);
    
    userService.validateUserResponse(response);
    DataValidator.validatePaginationResponse(response, page, limit);
    
    expect(response.body.data.length).to.be.lessThanOrEqual(limit);
    console.log(`Page ${page}: ${response.body.data.length} users`);
  });
  
  it("should filter users by gender", async () => {
    const gender = "female";
    const response = await userService.getUsersByGender(gender);
    
    userService.validateUserResponse(response);
    
    // Verify all returned users have the correct gender
    response.body.data.forEach(user => {
      expect(user.gender).to.equal(gender);
    });
    
    console.log(`Found ${response.body.data.length} ${gender} users`);
  });
  
  it("should filter users by status", async () => {
    const status = "active";
    const response = await userService.getUsersByStatus(status);
    
    userService.validateUserResponse(response);
    
    // Verify all returned users have the correct status
    response.body.data.forEach(user => {
      expect(user.status).to.equal(status);
    });
    
    console.log(`Found ${response.body.data.length} ${status} users`);
  });
  
  it("should combine multiple filters", async () => {
    const criteria = {
      gender: "male",
      status: "active",
      page: 1,
      per_page: 10
    };
    
    const response = await userService.searchUsers(criteria);
    
    userService.validateUserResponse(response);
    
    // Verify all returned users match the criteria
    response.body.data.forEach(user => {
      expect(user.gender).to.equal("male");
      expect(user.status).to.equal("active");
    });
    
    console.log(`Found ${response.body.data.length} active male users`);
  });
  
  it("should validate user data structure", async () => {
    const response = await userService.getAllUsers();
    
    userService.validateUserResponse(response);
    
    // Validate each user's data structure
    response.body.data.forEach(user => {
      DataValidator.validateUser(user);
      expect(DataValidator.validateEmail(user.email)).to.be.true;
    });
  });
  
  it("should handle query parameter edge cases", async () => {
    // Test with very large page number
    const response = await userService.getUsersWithPagination(999, 10);
    
    expect(response.status).to.equal(200);
    expect(response.body.data).to.be.an('array');
    
    // Test with zero limit
    const zeroLimitResponse = await userService.getUsersWithPagination(1, 0);
    expect(zeroLimitResponse.status).to.equal(200);
  });
});

// Advanced Read Operations
describe("Advanced Read Operations", () => {
  let userService;
  let queryBuilder;
  
  beforeEach(() => {
    userService = new UserRetrievalService(request, TOKEN);
    queryBuilder = new QueryBuilder();
  });
  
  it("should use query builder for complex queries", async () => {
    const query = queryBuilder
      .page(1)
      .limit(5)
      .gender("female")
      .status("active")
      .build();
    
    const response = await userService.searchUsers(query);
    
    userService.validateUserResponse(response);
    
    response.body.data.forEach(user => {
      expect(user.gender).to.equal("female");
      expect(user.status).to.equal("active");
    });
  });
  
  it("should retrieve users with custom headers", async () => {
    const response = await request
      .get("/users")
      .set("Authorization", `Bearer ${TOKEN}`)
      .set("Accept", "application/json")
      .set("User-Agent", "API-Test-Suite/1.0")
      .query({ page: 1, per_page: 3 });
    
    expect(response.status).to.equal(200);
    expect(response.body.data).to.be.an('array');
  });
  
  it("should handle response caching headers", async () => {
    const response = await userService.getAllUsers();
    
    expect(response.status).to.equal(200);
    
    // Check for caching headers
    const headers = response.headers;
    console.log("Response headers:", Object.keys(headers));
    
    // Some APIs might include caching headers
    if (headers['cache-control']) {
      expect(headers['cache-control']).to.be.a('string');
    }
  });
  
  it("should measure response time for different query sizes", async () => {
    const testCases = [
      { limit: 1, description: "Single user" },
      { limit: 10, description: "Small batch" },
      { limit: 50, description: "Medium batch" }
    ];
    
    const results = [];
    
    for (const testCase of testCases) {
      const startTime = Date.now();
      const response = await userService.getUsersWithPagination(1, testCase.limit);
      const endTime = Date.now();
      
      const responseTime = endTime - startTime;
      
      expect(response.status).to.equal(200);
      results.push({
        limit: testCase.limit,
        description: testCase.description,
        responseTime,
        userCount: response.body.data.length
      });
    }
    
    console.log("Response time analysis:", results);
    
    // Response time should generally increase with larger limits
    results.forEach(result => {
      expect(result.responseTime).to.be.lessThan(10000); // Should complete within 10 seconds
    });
  });
  
  it("should handle concurrent read requests", async () => {
    const requests = Array.from({ length: 5 }, (_, i) => 
      userService.getUsersWithPagination(i + 1, 5)
    );
    
    const responses = await Promise.all(requests);
    
    responses.forEach((response, index) => {
      expect(response.status).to.equal(200);
      expect(response.body.data).to.be.an('array');
      console.log(`Request ${index + 1}: ${response.body.data.length} users`);
    });
  });
});

// Error Handling and Edge Cases
describe("Error Handling and Edge Cases", () => {
  let userService;
  
  beforeEach(() => {
    userService = new UserRetrievalService(request, TOKEN);
  });
  
  it("should handle invalid query parameters", async () => {
    const invalidParams = {
      gender: "invalid_gender",
      status: "invalid_status",
      page: -1,
      per_page: -5
    };
    
    const response = await userService.searchUsers(invalidParams);
    
    // API should handle invalid parameters gracefully
    expect(response.status).to.be.oneOf([200, 400, 422]);
    
    if (response.status === 200) {
      // If it returns 200, it might ignore invalid parameters
      expect(response.body.data).to.be.an('array');
    }
  });
  
  it("should handle malformed user ID", async () => {
    const malformedIds = ["abc", "123abc", "", null];
    
    for (const id of malformedIds) {
      try {
        const response = await userService.getUserById(id);
        expect(response.status).to.be.oneOf([200, 400, 404]);
      } catch (error) {
        // Some malformed IDs might cause network errors
        expect(error).to.be.an('error');
      }
    }
  });
  
  it("should handle authentication errors", async () => {
    const invalidToken = "invalid-token";
    const invalidUserService = new UserRetrievalService(request, invalidToken);
    
    const response = await invalidUserService.getAllUsers();
    
    expect(response.status).to.equal(401);
    expect(response.body).to.have.property('data');
  });
  
  it("should handle rate limiting", async () => {
    // Make multiple rapid requests
    const promises = Array.from({ length: 20 }, () => 
      userService.getAllUsers()
    );
    
    const responses = await Promise.allSettled(promises);
    
    const successful = responses.filter(r => r.status === 'fulfilled' && r.value.status === 200);
    const rateLimited = responses.filter(r => r.status === 'fulfilled' && r.value.status === 429);
    
    console.log(`Successful: ${successful.length}, Rate Limited: ${rateLimited.length}`);
    
    // At least some should succeed
    expect(successful.length).to.be.greaterThan(0);
  });
});

// Data Analysis and Reporting
describe("Data Analysis and Reporting", () => {
  let userService;
  
  beforeEach(() => {
    userService = new UserRetrievalService(request, TOKEN);
  });
  
  it("should analyze user distribution by gender", async () => {
    const maleResponse = await userService.getUsersByGender("male");
    const femaleResponse = await userService.getUsersByGender("female");
    
    const maleCount = maleResponse.body.data.length;
    const femaleCount = femaleResponse.body.data.length;
    const totalCount = maleCount + femaleCount;
    
    console.log(`Gender Distribution:`);
    console.log(`Male: ${maleCount} (${(maleCount/totalCount*100).toFixed(1)}%)`);
    console.log(`Female: ${femaleCount} (${(femaleCount/totalCount*100).toFixed(1)}%)`);
    
    expect(totalCount).to.be.greaterThan(0);
  });
  
  it("should analyze user distribution by status", async () => {
    const activeResponse = await userService.getUsersByStatus("active");
    const inactiveResponse = await userService.getUsersByStatus("inactive");
    
    const activeCount = activeResponse.body.data.length;
    const inactiveCount = inactiveResponse.body.data.length;
    const totalCount = activeCount + inactiveCount;
    
    console.log(`Status Distribution:`);
    console.log(`Active: ${activeCount} (${(activeCount/totalCount*100).toFixed(1)}%)`);
    console.log(`Inactive: ${inactiveCount} (${(inactiveCount/totalCount*100).toFixed(1)}%)`);
    
    expect(totalCount).to.be.greaterThan(0);
  });
  
  it("should generate user statistics report", async () => {
    const response = await userService.getAllUsers();
    const users = response.body.data;
    
    const stats = {
      totalUsers: users.length,
      uniqueEmails: new Set(users.map(u => u.email)).size,
      genderDistribution: {},
      statusDistribution: {},
      averageNameLength: 0
    };
    
    // Calculate gender distribution
    users.forEach(user => {
      stats.genderDistribution[user.gender] = (stats.genderDistribution[user.gender] || 0) + 1;
      stats.statusDistribution[user.status] = (stats.statusDistribution[user.status] || 0) + 1;
    });
    
    // Calculate average name length
    const totalNameLength = users.reduce((sum, user) => sum + user.name.length, 0);
    stats.averageNameLength = Math.round(totalNameLength / users.length);
    
    console.log("User Statistics:", stats);
    
    expect(stats.totalUsers).to.be.greaterThan(0);
    expect(stats.uniqueEmails).to.equal(stats.totalUsers); // All emails should be unique
  });
});

export { 
  UserRetrievalService, 
  QueryBuilder, 
  DataValidator 
};





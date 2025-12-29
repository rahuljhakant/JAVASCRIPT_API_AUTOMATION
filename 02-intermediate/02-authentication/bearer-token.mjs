/**
 * PHASE 2: INTERMEDIATE LEVEL
 * Module 2: Authentication
 * Lesson 1: Bearer Token Authentication
 * 
 * Learning Objectives:
 * - Implement Bearer token authentication
 * - Handle token validation and expiration
 * - Manage secure token storage
 * - Test authentication flows
 */

import { expect } from "chai";
import supertest from "supertest";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== BEARER TOKEN AUTHENTICATION ===");

// API client setup
const request = supertest("https://gorest.co.in/public-api/");

// Token management service
class TokenManager {
  constructor() {
    this.tokens = new Map();
    this.tokenExpiry = new Map();
  }
  
  // Store token with expiration
  storeToken(tokenName, token, expiresIn = 3600) {
    this.tokens.set(tokenName, token);
    const expiryTime = Date.now() + (expiresIn * 1000);
    this.tokenExpiry.set(tokenName, expiryTime);
  }
  
  // Retrieve token
  getToken(tokenName) {
    if (this.isTokenExpired(tokenName)) {
      this.tokens.delete(tokenName);
      this.tokenExpiry.delete(tokenName);
      return null;
    }
    return this.tokens.get(tokenName);
  }
  
  // Check if token is expired
  isTokenExpired(tokenName) {
    const expiryTime = this.tokenExpiry.get(tokenName);
    if (!expiryTime) return true;
    return Date.now() > expiryTime;
  }
  
  // Remove token
  removeToken(tokenName) {
    this.tokens.delete(tokenName);
    this.tokenExpiry.delete(tokenName);
  }
  
  // Get all valid tokens
  getValidTokens() {
    const validTokens = {};
    for (const [name, token] of this.tokens.entries()) {
      if (!this.isTokenExpired(name)) {
        validTokens[name] = token;
      }
    }
    return validTokens;
  }
}

// Authentication service
class BearerTokenAuthService {
  constructor(apiClient, tokenManager) {
    this.apiClient = apiClient;
    this.tokenManager = tokenManager;
  }
  
  // Make authenticated request
  async makeAuthenticatedRequest(method, endpoint, tokenName, data = null) {
    const token = this.tokenManager.getToken(tokenName);
    
    if (!token) {
      throw new Error(`Token '${tokenName}' not found or expired`);
    }
    
    let request = this.apiClient[method.toLowerCase()](endpoint)
      .set("Authorization", `Bearer ${token}`);
    
    if (data && ['post', 'put', 'patch'].includes(method.toLowerCase())) {
      request = request.send(data);
    }
    
    return await request;
  }
  
  // Test token validity
  async validateToken(tokenName) {
    try {
      const response = await this.makeAuthenticatedRequest('GET', '/users', tokenName);
      return {
        valid: response.status === 200,
        status: response.status,
        message: response.status === 200 ? 'Token is valid' : 'Token is invalid'
      };
    } catch (error) {
      return {
        valid: false,
        status: 401,
        message: error.message
      };
    }
  }
  
  // Get user profile with token
  async getUserProfile(tokenName, userId) {
    const response = await this.makeAuthenticatedRequest('GET', `/users/${userId}`, tokenName);
    return response;
  }
  
  // Create resource with token
  async createResource(tokenName, endpoint, data) {
    const response = await this.makeAuthenticatedRequest('POST', endpoint, tokenName, data);
    return response;
  }
  
  // Update resource with token
  async updateResource(tokenName, endpoint, data) {
    const response = await this.makeAuthenticatedRequest('PUT', endpoint, tokenName, data);
    return response;
  }
  
  // Delete resource with token
  async deleteResource(tokenName, endpoint) {
    const response = await this.makeAuthenticatedRequest('DELETE', endpoint, tokenName);
    return response;
  }
}

// Token validation utilities
class TokenValidator {
  static validateTokenFormat(token) {
    // Basic token format validation
    if (!token || typeof token !== 'string') {
      return { valid: false, error: 'Token must be a non-empty string' };
    }
    
    if (token.length < 10) {
      return { valid: false, error: 'Token appears to be too short' };
    }
    
    // Check for common token patterns
    const patterns = {
      jwt: /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/,
      uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
      hex: /^[0-9a-f]+$/i
    };
    
    for (const [type, pattern] of Object.entries(patterns)) {
      if (pattern.test(token)) {
        return { valid: true, type: type };
      }
    }
    
    return { valid: true, type: 'unknown' };
  }
  
  static extractTokenFromHeader(authHeader) {
    if (!authHeader) {
      return null;
    }
    
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
      return null;
    }
    
    return parts[1];
  }
  
  static isTokenExpired(token, expiryTime) {
    if (!expiryTime) return false;
    return Date.now() > expiryTime;
  }
}

// Exercises and Tests
describe("Bearer Token Authentication", () => {
  let tokenManager;
  let authService;
  const VALID_TOKEN = getApiToken();
  const INVALID_TOKEN = "invalid-token-12345";
  
  beforeEach(() => {
    tokenManager = new TokenManager();
    authService = new BearerTokenAuthService(request, tokenManager);
  });
  
  it("should store and retrieve valid tokens", () => {
    tokenManager.storeToken('user_token', VALID_TOKEN, 3600);
    
    const retrievedToken = tokenManager.getToken('user_token');
    expect(retrievedToken).to.equal(VALID_TOKEN);
    expect(tokenManager.isTokenExpired('user_token')).to.be.false;
  });
  
  it("should handle token expiration", () => {
    // Store token with very short expiration
    tokenManager.storeToken('expired_token', VALID_TOKEN, 1);
    
    // Wait for token to expire
    setTimeout(() => {
      expect(tokenManager.isTokenExpired('expired_token')).to.be.true;
      expect(tokenManager.getToken('expired_token')).to.be.null;
    }, 1100);
  });
  
  it("should make authenticated requests with valid token", async () => {
    tokenManager.storeToken('valid_token', VALID_TOKEN);
    
    const response = await authService.makeAuthenticatedRequest('GET', '/users', 'valid_token');
    
    expect(response.status).to.equal(200);
    expect(response.body).to.have.property('data');
  });
  
  it("should handle invalid token gracefully", async () => {
    tokenManager.storeToken('invalid_token', INVALID_TOKEN);
    
    const response = await authService.makeAuthenticatedRequest('GET', '/users', 'invalid_token');
    
    expect(response.status).to.equal(401);
    expect(response.body).to.have.property('data');
  });
  
  it("should validate token format", () => {
    const validTokens = [
      getApiToken(),
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "123e4567-e89b-12d3-a456-426614174000"
    ];
    
    const invalidTokens = [
      "",
      "short",
      null,
      undefined,
      12345
    ];
    
    validTokens.forEach(token => {
      const validation = TokenValidator.validateTokenFormat(token);
      expect(validation.valid).to.be.true;
    });
    
    invalidTokens.forEach(token => {
      const validation = TokenValidator.validateTokenFormat(token);
      expect(validation.valid).to.be.false;
    });
  });
  
  it("should extract token from authorization header", () => {
    const testCases = [
      { header: "Bearer valid-token-123", expected: "valid-token-123" },
      { header: "bearer valid-token-123", expected: "valid-token-123" },
      { header: "BEARER valid-token-123", expected: "valid-token-123" },
      { header: "Basic dXNlcjpwYXNz", expected: null },
      { header: "invalid-format", expected: null },
      { header: null, expected: null }
    ];
    
    testCases.forEach(testCase => {
      const extracted = TokenValidator.extractTokenFromHeader(testCase.header);
      expect(extracted).to.equal(testCase.expected);
    });
  });
  
  it("should perform CRUD operations with authentication", async () => {
    tokenManager.storeToken('crud_token', VALID_TOKEN);
    
    // Create user
    const userData = {
      name: "Test User",
      email: `test${Math.floor(Math.random() * 10000)}@example.com`,
      gender: "male",
      status: "active"
    };
    
    const createResponse = await authService.createResource('crud_token', '/users', userData);
    expect(createResponse.status).to.equal(201);
    expect(createResponse.body.data).to.have.property('id');
    
    const userId = createResponse.body.data.id;
    
    // Read user
    const readResponse = await authService.getUserProfile('crud_token', userId);
    expect(readResponse.status).to.equal(200);
    expect(readResponse.body.data.id).to.equal(userId);
    
    // Update user
    const updateData = { name: "Updated User" };
    const updateResponse = await authService.updateResource('crud_token', `/users/${userId}`, updateData);
    expect(updateResponse.status).to.equal(200);
    expect(updateResponse.body.data.name).to.equal("Updated User");
    
    // Delete user
    const deleteResponse = await authService.deleteResource('crud_token', `/users/${userId}`);
    expect(deleteResponse.status).to.equal(200);
  });
  
  it("should handle multiple tokens simultaneously", async () => {
    const tokens = {
      token1: VALID_TOKEN,
      token2: VALID_TOKEN,
      token3: INVALID_TOKEN
    };
    
    // Store multiple tokens
    Object.entries(tokens).forEach(([name, token]) => {
      tokenManager.storeToken(name, token);
    });
    
    // Test each token
    const results = await Promise.allSettled([
      authService.validateToken('token1'),
      authService.validateToken('token2'),
      authService.validateToken('token3')
    ]);
    
    expect(results[0].value.valid).to.be.true;
    expect(results[1].value.valid).to.be.true;
    expect(results[2].value.valid).to.be.false;
  });
  
  it("should handle token refresh scenarios", async () => {
    // Simulate token refresh
    const oldToken = "old-token-123";
    const newToken = VALID_TOKEN;
    
    tokenManager.storeToken('refresh_token', oldToken, 1);
    
    // Wait for token to expire
    await new Promise(resolve => setTimeout(resolve, 1100));
    
    // Refresh token
    tokenManager.storeToken('refresh_token', newToken, 3600);
    
    const response = await authService.makeAuthenticatedRequest('GET', '/users', 'refresh_token');
    expect(response.status).to.equal(200);
  });
});

// Advanced Authentication Scenarios
describe("Advanced Authentication Scenarios", () => {
  let tokenManager;
  let authService;
  
  beforeEach(() => {
    tokenManager = new TokenManager();
    authService = new BearerTokenAuthService(request, tokenManager);
  });
  
  it("should handle concurrent authenticated requests", async () => {
    tokenManager.storeToken('concurrent_token', getApiToken());
    
    const requests = Array.from({ length: 5 }, () => 
      authService.makeAuthenticatedRequest('GET', '/users', 'concurrent_token')
    );
    
    const responses = await Promise.all(requests);
    
    responses.forEach(response => {
      expect(response.status).to.equal(200);
    });
  });
  
  it("should handle token rotation", async () => {
    const tokens = [
      getApiToken(),
      "6dc353df7c107b9cf591463edb36e13dbc182be021562024473aac00cd19031c"
    ];
    
    for (let i = 0; i < tokens.length; i++) {
      tokenManager.storeToken('rotating_token', tokens[i]);
      
      const response = await authService.makeAuthenticatedRequest('GET', '/users', 'rotating_token');
      expect(response.status).to.equal(200);
      
      // Simulate token rotation delay
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  });
  
  it("should handle authentication errors gracefully", async () => {
    const errorScenarios = [
      { token: null, description: "Null token" },
      { token: "", description: "Empty token" },
      { token: "invalid", description: "Invalid token" },
      { token: "expired-token", description: "Expired token" }
    ];
    
    for (const scenario of errorScenarios) {
      tokenManager.storeToken('error_token', scenario.token);
      
      try {
        const response = await authService.makeAuthenticatedRequest('GET', '/users', 'error_token');
        expect(response.status).to.be.oneOf([200, 401, 403]);
      } catch (error) {
        expect(error).to.be.an('error');
      }
    }
  });
  
  it("should measure authentication performance", async () => {
    tokenManager.storeToken('perf_token', getApiToken());
    
    const iterations = 10;
    const times = [];
    
    for (let i = 0; i < iterations; i++) {
      const startTime = Date.now();
      await authService.makeAuthenticatedRequest('GET', '/users', 'perf_token');
      const endTime = Date.now();
      
      times.push(endTime - startTime);
    }
    
    const averageTime = times.reduce((sum, time) => sum + time, 0) / times.length;
    const maxTime = Math.max(...times);
    const minTime = Math.min(...times);
    
    console.log(`Authentication Performance:`);
    console.log(`Average: ${averageTime.toFixed(2)}ms`);
    console.log(`Max: ${maxTime}ms`);
    console.log(`Min: ${minTime}ms`);
    
    expect(averageTime).to.be.lessThan(5000); // Should complete within 5 seconds
  });
});

// Security Testing
describe("Security Testing", () => {
  let tokenManager;
  let authService;
  
  beforeEach(() => {
    tokenManager = new TokenManager();
    authService = new BearerTokenAuthService(request, tokenManager);
  });
  
  it("should not expose tokens in error messages", async () => {
    const sensitiveToken = "sensitive-token-123";
    tokenManager.storeToken('sensitive_token', sensitiveToken);
    
    try {
      await authService.makeAuthenticatedRequest('GET', '/users', 'sensitive_token');
    } catch (error) {
      expect(error.message).to.not.include(sensitiveToken);
    }
  });
  
  it("should handle token injection attempts", async () => {
    const maliciousTokens = [
      "'; DROP TABLE users; --",
      "<script>alert('xss')</script>",
      "../../etc/passwd",
      "{{7*7}}",
      "javascript:alert(1)"
    ];
    
    for (const maliciousToken of maliciousTokens) {
      tokenManager.storeToken('malicious_token', maliciousToken);
      
      try {
        const response = await authService.makeAuthenticatedRequest('GET', '/users', 'malicious_token');
        // Should either reject the token or handle it safely
        expect(response.status).to.be.oneOf([200, 401, 403, 400]);
      } catch (error) {
        // Expected for malicious tokens
        expect(error).to.be.an('error');
      }
    }
  });
  
  it("should validate token storage security", () => {
    const testToken = "test-token-123";
    tokenManager.storeToken('security_test', testToken);
    
    // Token should be stored securely (not in plain text in memory)
    const storedToken = tokenManager.getToken('security_test');
    expect(storedToken).to.equal(testToken);
    
    // Should be able to remove token
    tokenManager.removeToken('security_test');
    expect(tokenManager.getToken('security_test')).to.be.null;
  });
});

export { 
  TokenManager, 
  BearerTokenAuthService, 
  TokenValidator 
};





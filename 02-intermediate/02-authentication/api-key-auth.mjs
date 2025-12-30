/**
 * PHASE 2: INTERMEDIATE LEVEL
 * Module 2: Authentication
 * Lesson 2: API Key Authentication
 * 
 * Learning Objectives:
 * - Understand API key authentication
 * - Implement API key in headers and query parameters
 * - Handle API key validation and errors
 * - Manage multiple API keys and rotation
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== API KEY AUTHENTICATION ===");

// API client setup - using a public API that supports API keys
// Note: This example uses httpbin.org which simulates API key auth
const request = supertest("https://httpbin.org");

// API Key Authentication Service
class ApiKeyAuthService {
  constructor(apiClient) {
    this.apiClient = apiClient;
  }
  
  async requestWithApiKeyInHeader(apiKey, endpoint = "/get") {
    return await this.apiClient
      .get(endpoint)
      .set("X-API-Key", apiKey);
  }
  
  async requestWithApiKeyInQuery(apiKey, endpoint = "/get") {
    return await this.apiClient
      .get(endpoint)
      .query({ api_key: apiKey });
  }
  
  async requestWithApiKeyCustomHeader(apiKey, headerName, endpoint = "/get") {
    return await this.apiClient
      .get(endpoint)
      .set(headerName, apiKey);
  }
  
  async requestWithMultipleApiKeys(apiKeys, endpoint = "/get") {
    const headers = {};
    apiKeys.forEach((key, index) => {
      headers[`X-API-Key-${index + 1}`] = key;
    });
    
    return await this.apiClient
      .get(endpoint)
      .set(headers);
  }
  
  validateApiKeyResponse(response, expectedKey = null) {
    expect(response.status).to.equal(200);
    expect(response.body).to.exist;
    
    if (expectedKey) {
      // Verify API key was sent (httpbin returns request headers)
      const headers = response.body.headers || {};
      const apiKeyHeader = headers['X-Api-Key'] || headers['X-API-Key'];
      
      if (apiKeyHeader) {
        expect(apiKeyHeader).to.equal(expectedKey);
      }
    }
  }
}

// API Key Manager
class ApiKeyManager {
  constructor() {
    this.keys = new Map();
  }
  
  addKey(name, key, metadata = {}) {
    this.keys.set(name, {
      key,
      createdAt: new Date(),
      lastUsed: null,
      metadata,
      active: true
    });
  }
  
  getKey(name) {
    const keyData = this.keys.get(name);
    if (keyData && keyData.active) {
      keyData.lastUsed = new Date();
      return keyData.key;
    }
    return null;
  }
  
  rotateKey(name, newKey) {
    const keyData = this.keys.get(name);
    if (keyData) {
      keyData.key = newKey;
      keyData.rotatedAt = new Date();
      return true;
    }
    return false;
  }
  
  deactivateKey(name) {
    const keyData = this.keys.get(name);
    if (keyData) {
      keyData.active = false;
      return true;
    }
    return false;
  }
  
  getAllKeys() {
    return Array.from(this.keys.entries()).map(([name, data]) => ({
      name,
      ...data
    }));
  }
}

// Exercises and Tests
describe("API Key Authentication", () => {
  let authService;
  let apiKeyManager;
  const testApiKey = "test-api-key-12345";
  
  beforeEach(() => {
    authService = new ApiKeyAuthService(request);
    apiKeyManager = new ApiKeyManager();
    apiKeyManager.addKey("primary", testApiKey);
  });
  
  it("should authenticate with API key in header", async () => {
    const apiKey = apiKeyManager.getKey("primary");
    const response = await authService.requestWithApiKeyInHeader(apiKey);
    
    authService.validateApiKeyResponse(response, apiKey);
    console.log("API key authentication successful via header");
  });
  
  it("should authenticate with API key in query parameter", async () => {
    const apiKey = apiKeyManager.getKey("primary");
    const response = await authService.requestWithApiKeyInQuery(apiKey);
    
    expect(response.status).to.equal(200);
    expect(response.body).to.exist;
    
    // Verify API key in query params
    if (response.body.args) {
      expect(response.body.args.api_key).to.equal(apiKey);
    }
    
    console.log("API key authentication successful via query parameter");
  });
  
  it("should authenticate with custom header name", async () => {
    const apiKey = apiKeyManager.getKey("primary");
    const response = await authService.requestWithApiKeyCustomHeader(
      apiKey,
      "Authorization-Key"
    );
    
    expect(response.status).to.equal(200);
    expect(response.body).to.exist;
    
    console.log("API key authentication successful with custom header");
  });
  
  it("should handle invalid API key", async () => {
    const invalidKey = "invalid-api-key";
    const response = await authService.requestWithApiKeyInHeader(invalidKey);
    
    // httpbin.org doesn't validate API keys, but real APIs would return 401
    expect(response.status).to.equal(200);
    
    // In a real scenario:
    // expect(response.status).to.equal(401);
    // expect(response.body).to.have.property('error');
    
    console.log("Invalid API key handled");
  });
  
  it("should handle missing API key", async () => {
    const response = await request.get("/get");
    
    // Without API key, some APIs return 401
    expect(response.status).to.equal(200); // httpbin doesn't require auth
    
    // In a real scenario:
    // expect(response.status).to.equal(401);
    // expect(response.body).to.have.property('error', 'API key required');
  });
  
  it("should use multiple API keys", async () => {
    apiKeyManager.addKey("secondary", "secondary-key-67890");
    
    const keys = [
      apiKeyManager.getKey("primary"),
      apiKeyManager.getKey("secondary")
    ];
    
    const response = await authService.requestWithMultipleApiKeys(keys);
    
    expect(response.status).to.equal(200);
    console.log("Multiple API keys used successfully");
  });
  
  it("should rotate API keys", async () => {
    const oldKey = apiKeyManager.getKey("primary");
    const newKey = "new-rotated-key-54321";
    
    const rotated = apiKeyManager.rotateKey("primary", newKey);
    expect(rotated).to.be.true;
    
    const currentKey = apiKeyManager.getKey("primary");
    expect(currentKey).to.equal(newKey);
    expect(currentKey).to.not.equal(oldKey);
    
    console.log("API key rotated successfully");
  });
  
  it("should deactivate API key", async () => {
    const deactivated = apiKeyManager.deactivateKey("primary");
    expect(deactivated).to.be.true;
    
    const key = apiKeyManager.getKey("primary");
    expect(key).to.be.null;
    
    console.log("API key deactivated successfully");
  });
  
  it("should track API key usage", async () => {
    const keyData = apiKeyManager.getAllKeys().find(k => k.name === "primary");
    
    expect(keyData).to.exist;
    expect(keyData.createdAt).to.exist;
    
    // Use the key
    apiKeyManager.getKey("primary");
    
    const updatedKeyData = apiKeyManager.getAllKeys().find(k => k.name === "primary");
    expect(updatedKeyData.lastUsed).to.exist;
    
    console.log("API key usage tracked");
  });
});

// Advanced API Key Operations
describe("Advanced API Key Operations", () => {
  let authService;
  let apiKeyManager;
  
  beforeEach(() => {
    authService = new ApiKeyAuthService(request);
    apiKeyManager = new ApiKeyManager();
  });
  
  it("should handle API key expiration", async () => {
    const expiredKey = "expired-key-12345";
    apiKeyManager.addKey("expired", expiredKey, {
      expiresAt: new Date(Date.now() - 86400000) // Expired yesterday
    });
    
    const keyData = apiKeyManager.getAllKeys().find(k => k.name === "expired");
    const isExpired = keyData.metadata.expiresAt < new Date();
    
    expect(isExpired).to.be.true;
    
    // In a real scenario, you would check expiration before using
    if (isExpired) {
      console.log("API key has expired");
    }
  });
  
  it("should handle API key rate limiting", async () => {
    const apiKey = "rate-limited-key";
    apiKeyManager.addKey("limited", apiKey);
    
    // Simulate multiple requests
    const requests = Array.from({ length: 10 }, () =>
      authService.requestWithApiKeyInHeader(apiKey)
    );
    
    const responses = await Promise.all(requests);
    
    // Check for rate limiting (429 status)
    const rateLimited = responses.filter(r => r.status === 429);
    const successful = responses.filter(r => r.status === 200);
    
    console.log(`Successful: ${successful.length}, Rate Limited: ${rateLimited.length}`);
    
    // At least some should succeed
    expect(successful.length).to.be.greaterThan(0);
  });
  
  it("should validate API key format", () => {
    const validFormats = [
      /^[a-zA-Z0-9]{32}$/, // 32 alphanumeric characters
      /^sk-[a-zA-Z0-9]{40}$/, // Stripe-like format
      /^[a-f0-9]{64}$/ // 64 hex characters
    ];
    
    const testKeys = [
      "validkey123456789012345678901234", // 32 chars
      "sk-1234567890123456789012345678901234567890", // Stripe format
      "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" // 64 hex
    ];
    
    testKeys.forEach((key, index) => {
      const isValid = validFormats[index].test(key);
      expect(isValid).to.be.true;
    });
    
    console.log("API key format validation successful");
  });
  
  it("should handle API key scopes/permissions", () => {
    apiKeyManager.addKey("read-only", "read-key-123", {
      scopes: ["read"]
    });
    
    apiKeyManager.addKey("read-write", "write-key-456", {
      scopes: ["read", "write"]
    });
    
    const readOnlyKey = apiKeyManager.getAllKeys().find(k => k.name === "read-only");
    const readWriteKey = apiKeyManager.getAllKeys().find(k => k.name === "read-write");
    
    expect(readOnlyKey.metadata.scopes).to.include("read");
    expect(readOnlyKey.metadata.scopes).to.not.include("write");
    expect(readWriteKey.metadata.scopes).to.include.members(["read", "write"]);
    
    console.log("API key scopes validated");
  });
  
  it("should encrypt API keys in storage", () => {
    // In a real scenario, API keys should be encrypted
    const plainKey = "sensitive-api-key-12345";
    
    // Simple encoding (in production, use proper encryption)
    const encodedKey = Buffer.from(plainKey).toString('base64');
    const decodedKey = Buffer.from(encodedKey, 'base64').toString('utf-8');
    
    expect(decodedKey).to.equal(plainKey);
    expect(encodedKey).to.not.equal(plainKey);
    
    console.log("API key encoding/encryption demonstrated");
  });
  
  it("should handle API key rotation with zero downtime", async () => {
    const oldKey = "old-key-12345";
    const newKey = "new-key-67890";
    
    apiKeyManager.addKey("rotating", oldKey);
    
    // Add new key before removing old one
    apiKeyManager.addKey("rotating-new", newKey);
    
    // Verify both keys work
    const oldKeyData = apiKeyManager.getKey("rotating");
    const newKeyData = apiKeyManager.getKey("rotating-new");
    
    expect(oldKeyData).to.equal(oldKey);
    expect(newKeyData).to.equal(newKey);
    
    // After migration, deactivate old key
    apiKeyManager.deactivateKey("rotating");
    
    console.log("Zero-downtime API key rotation successful");
  });
});

// API Key Security Best Practices
describe("API Key Security Best Practices", () => {
  it("should never log API keys", () => {
    const apiKey = "sensitive-key-12345";
    
    // Bad practice: logging full key
    // console.log("API Key:", apiKey); // ❌ DON'T DO THIS
    
    // Good practice: log only partial key
    const maskedKey = apiKey.substring(0, 4) + "..." + apiKey.substring(apiKey.length - 4);
    console.log("API Key:", maskedKey); // ✅ Safe to log
    
    expect(maskedKey).to.not.equal(apiKey);
    expect(maskedKey).to.include("...");
  });
  
  it("should use environment variables for API keys", () => {
    // Good practice: Store API keys in environment variables
    const apiKey = process.env.API_KEY || "default-key-for-testing";
    
    expect(apiKey).to.exist;
    expect(typeof apiKey).to.equal('string');
    
    // In production, ensure API_KEY is set
    if (process.env.NODE_ENV === 'production') {
      expect(apiKey).to.not.equal("default-key-for-testing");
    }
    
    console.log("Environment variable usage validated");
  });
  
  it("should validate API key before use", () => {
    const validateApiKey = (key) => {
      if (!key || typeof key !== 'string') {
        return { valid: false, error: "API key must be a non-empty string" };
      }
      
      if (key.length < 16) {
        return { valid: false, error: "API key must be at least 16 characters" };
      }
      
      return { valid: true };
    };
    
    const validKey = "valid-key-123456789012345";
    const invalidKey1 = "";
    const invalidKey2 = "short";
    
    expect(validateApiKey(validKey).valid).to.be.true;
    expect(validateApiKey(invalidKey1).valid).to.be.false;
    expect(validateApiKey(invalidKey2).valid).to.be.false;
    
    console.log("API key validation successful");
  });
  
  it("should handle API key errors gracefully", async () => {
    const authService = new ApiKeyAuthService(request);
    
    try {
      const response = await authService.requestWithApiKeyInHeader("invalid-key");
      
      // In a real API, this might return 401
      // For now, we just verify it doesn't crash
      expect(response).to.exist;
      
    } catch (error) {
      // Handle error gracefully
      expect(error).to.be.an('error');
      console.log("API key error handled gracefully:", error.message);
    }
  });
});

export { 
  ApiKeyAuthService, 
  ApiKeyManager 
};


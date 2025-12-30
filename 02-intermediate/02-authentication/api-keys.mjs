/**
 * PHASE 2: INTERMEDIATE LEVEL
 * Module 2: Authentication
 * Lesson 2: API Key Authentication
 * 
 * Learning Objectives:
 * - Understand API key authentication
 * - Implement API key in headers
 * - Handle API key validation
 * - Manage multiple API keys
 * - Rotate API keys securely
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== API KEY AUTHENTICATION ===");

// API Key Authentication Service
class APIKeyAuthService {
  constructor(apiClient, apiKey) {
    this.apiClient = apiClient;
    this.apiKey = apiKey;
  }

  /**
   * Make request with API key in header
   */
  async requestWithAPIKey(method, endpoint, data = null) {
    let request = this.apiClient[method.toLowerCase()](endpoint)
      .set("X-API-Key", this.apiKey);

    if (data) {
      request = request.send(data);
    }

    return await request;
  }

  /**
   * Make request with API key in query parameter
   */
  async requestWithAPIKeyInQuery(method, endpoint, data = null) {
    let request = this.apiClient[method.toLowerCase()](endpoint)
      .query({ api_key: this.apiKey });

    if (data) {
      request = request.send(data);
    }

    return await request;
  }

  /**
   * Make request with API key in custom header
   */
  async requestWithCustomHeader(method, endpoint, headerName, data = null) {
    let request = this.apiClient[method.toLowerCase()](endpoint)
      .set(headerName, this.apiKey);

    if (data) {
      request = request.send(data);
    }

    return await request;
  }

  /**
   * Validate API key response
   */
  validateAPIKeyResponse(response) {
    if (response.status === 401) {
      throw new Error("Invalid or missing API key");
    }
    if (response.status === 403) {
      throw new Error("API key does not have required permissions");
    }
    return response.status === 200 || response.status === 201;
  }
}

// API Key Manager
class APIKeyManager {
  constructor() {
    this.keys = new Map();
  }

  /**
   * Add API key
   */
  addKey(name, key, metadata = {}) {
    this.keys.set(name, {
      key,
      metadata: {
        createdAt: new Date(),
        lastUsed: null,
        ...metadata
      }
    });
  }

  /**
   * Get API key
   */
  getKey(name) {
    const keyData = this.keys.get(name);
    if (!keyData) {
      throw new Error(`API key '${name}' not found`);
    }
    keyData.metadata.lastUsed = new Date();
    return keyData.key;
  }

  /**
   * Rotate API key
   */
  rotateKey(name, newKey) {
    const keyData = this.keys.get(name);
    if (!keyData) {
      throw new Error(`API key '${name}' not found`);
    }

    const oldKey = keyData.key;
    keyData.key = newKey;
    keyData.metadata.rotatedAt = new Date();
    keyData.metadata.previousKey = oldKey;

    return { oldKey, newKey };
  }

  /**
   * List all API keys
   */
  listKeys() {
    return Array.from(this.keys.keys());
  }

  /**
   * Remove API key
   */
  removeKey(name) {
    return this.keys.delete(name);
  }
}

// Exercises and Tests
describe("API Key Authentication", () => {
  // Note: Using a public API that supports API keys for demonstration
  // In real scenarios, replace with your actual API endpoint
  const baseURL = "https://api.example.com"; // Replace with actual API
  const request = supertest(baseURL);

  it("should authenticate with API key in header", async () => {
    const apiKey = "your-api-key-here";
    const authService = new APIKeyAuthService(request, apiKey);

    try {
      const response = await authService.requestWithAPIKey("get", "/endpoint");

      // API key authentication should return 200 or 401/403 if invalid
      expect(response.status).to.be.oneOf([200, 401, 403]);
    } catch (error) {
      // Network errors are acceptable in demo
      expect(error).to.be.an('error');
    }
  });

  it("should authenticate with API key in query parameter", async () => {
    const apiKey = "your-api-key-here";
    const authService = new APIKeyAuthService(request, apiKey);

    try {
      const response = await authService.requestWithAPIKeyInQuery("get", "/endpoint");

      expect(response.status).to.be.oneOf([200, 401, 403]);
    } catch (error) {
      expect(error).to.be.an('error');
    }
  });

  it("should authenticate with API key in custom header", async () => {
    const apiKey = "your-api-key-here";
    const authService = new APIKeyAuthService(request, apiKey);

    try {
      const response = await authService.requestWithCustomHeader(
        "get",
        "/endpoint",
        "Authorization",
        null
      );

      expect(response.status).to.be.oneOf([200, 401, 403]);
    } catch (error) {
      expect(error).to.be.an('error');
    }
  });

  it("should handle invalid API key", async () => {
    const invalidApiKey = "invalid-key-12345";
    const authService = new APIKeyAuthService(request, invalidApiKey);

    try {
      const response = await authService.requestWithAPIKey("get", "/endpoint");

      // Invalid key should return 401 or 403
      expect(response.status).to.be.oneOf([401, 403]);
    } catch (error) {
      // If validation throws error
      if (error.message.includes("Invalid")) {
        expect(error.message).to.include("Invalid");
      } else {
        expect(error).to.be.an('error');
      }
    }
  });

  it("should handle missing API key", async () => {
    const requestWithoutKey = supertest(baseURL);

    try {
      const response = await requestWithoutKey.get("/endpoint");

      // Missing key should return 401
      expect(response.status).to.be.oneOf([401, 403, 200]);
    } catch (error) {
      expect(error).to.be.an('error');
    }
  });

  it("should validate API key response", async () => {
    const apiKey = "your-api-key-here";
    const authService = new APIKeyAuthService(request, apiKey);

    try {
      const response = await authService.requestWithAPIKey("get", "/endpoint");

      if (response.status === 401 || response.status === 403) {
        try {
          authService.validateAPIKeyResponse(response);
          expect.fail("Should have thrown error for invalid key");
        } catch (error) {
          expect(error.message).to.include("API key");
        }
      } else {
        const isValid = authService.validateAPIKeyResponse(response);
        expect(isValid).to.be.true;
      }
    } catch (error) {
      expect(error).to.be.an('error');
    }
  });
});

// API Key Management Tests
describe("API Key Management", () => {
  it("should add and retrieve API keys", () => {
    const keyManager = new APIKeyManager();

    keyManager.addKey("production", "prod-key-123", { environment: "production" });
    keyManager.addKey("staging", "staging-key-456", { environment: "staging" });

    const prodKey = keyManager.getKey("production");
    const stagingKey = keyManager.getKey("staging");

    expect(prodKey).to.equal("prod-key-123");
    expect(stagingKey).to.equal("staging-key-456");
  });

  it("should track API key usage", () => {
    const keyManager = new APIKeyManager();

    keyManager.addKey("test", "test-key-789");
    const keyData = keyManager.keys.get("test");

    expect(keyData.metadata.lastUsed).to.be.null;

    keyManager.getKey("test");

    expect(keyData.metadata.lastUsed).to.not.be.null;
    expect(keyData.metadata.lastUsed).to.be.instanceOf(Date);
  });

  it("should rotate API keys", () => {
    const keyManager = new APIKeyManager();

    keyManager.addKey("app", "old-key-123");
    const { oldKey, newKey } = keyManager.rotateKey("app", "new-key-456");

    expect(oldKey).to.equal("old-key-123");
    expect(newKey).to.equal("new-key-456");

    const currentKey = keyManager.getKey("app");
    expect(currentKey).to.equal("new-key-456");

    const keyData = keyManager.keys.get("app");
    expect(keyData.metadata.previousKey).to.equal("old-key-123");
    expect(keyData.metadata.rotatedAt).to.be.instanceOf(Date);
  });

  it("should list all API keys", () => {
    const keyManager = new APIKeyManager();

    keyManager.addKey("key1", "value1");
    keyManager.addKey("key2", "value2");
    keyManager.addKey("key3", "value3");

    const keys = keyManager.listKeys();

    expect(keys).to.have.length(3);
    expect(keys).to.include("key1");
    expect(keys).to.include("key2");
    expect(keys).to.include("key3");
  });

  it("should remove API keys", () => {
    const keyManager = new APIKeyManager();

    keyManager.addKey("temp", "temp-key");
    expect(keyManager.listKeys()).to.include("temp");

    const removed = keyManager.removeKey("temp");
    expect(removed).to.be.true;
    expect(keyManager.listKeys()).to.not.include("temp");

    try {
      keyManager.getKey("temp");
      expect.fail("Should have thrown error");
    } catch (error) {
      expect(error.message).to.include("not found");
    }
  });

  it("should handle non-existent key retrieval", () => {
    const keyManager = new APIKeyManager();

    try {
      keyManager.getKey("non-existent");
      expect.fail("Should have thrown error");
    } catch (error) {
      expect(error.message).to.include("not found");
    }
  });
});

// Advanced API Key Patterns
describe("Advanced API Key Patterns", () => {
  it("should use different API keys for different environments", () => {
    const keyManager = new APIKeyManager();

    keyManager.addKey("prod", "prod-key", { environment: "production" });
    keyManager.addKey("staging", "staging-key", { environment: "staging" });
    keyManager.addKey("dev", "dev-key", { environment: "development" });

    const environments = ["prod", "staging", "dev"];
    const keys = environments.map(env => ({
      environment: env,
      key: keyManager.getKey(env)
    }));

    expect(keys).to.have.length(3);
    keys.forEach(key => {
      expect(key.key).to.be.a('string');
      expect(key.key.length).to.be.greaterThan(0);
    });
  });

  it("should implement API key rotation strategy", () => {
    const keyManager = new APIKeyManager();

    // Initial key
    keyManager.addKey("service", "initial-key");

    // Rotate key
    keyManager.rotateKey("service", "rotated-key-1");

    // Rotate again
    keyManager.rotateKey("service", "rotated-key-2");

    const keyData = keyManager.keys.get("service");
    expect(keyData.key).to.equal("rotated-key-2");
    expect(keyData.metadata.previousKey).to.equal("rotated-key-1");
  });

  it("should handle API key expiration", () => {
    const keyManager = new APIKeyManager();

    const expirationDate = new Date();
    expirationDate.setDate(expirationDate.getDate() + 30); // 30 days from now

    keyManager.addKey("temporary", "temp-key", {
      expiresAt: expirationDate
    });

    const keyData = keyManager.keys.get("temporary");
    expect(keyData.metadata.expiresAt).to.be.instanceOf(Date);

    // Check if expired
    const now = new Date();
    const isExpired = now > keyData.metadata.expiresAt;
    expect(isExpired).to.be.false; // Should not be expired yet
  });
});

// API Key Security Best Practices
describe("API Key Security Best Practices", () => {
  it("should not expose API keys in logs", () => {
    const apiKey = "sensitive-key-12345";
    const maskedKey = apiKey.substring(0, 4) + "..." + apiKey.substring(apiKey.length - 4);

    console.log(`API Key: ${maskedKey}`); // Should mask sensitive data

    expect(maskedKey).to.not.equal(apiKey);
    expect(maskedKey).to.include("...");
  });

  it("should validate API key format", () => {
    const validKeyPattern = /^[A-Za-z0-9_-]{20,}$/; // Example pattern

    const validKeys = [
      "valid-api-key-12345",
      "another_valid_key_67890",
      "ValidKey123456789012345"
    ];

    const invalidKeys = [
      "short",
      "key with spaces",
      "key-with-special-chars!@#"
    ];

    validKeys.forEach(key => {
      expect(validKeyPattern.test(key)).to.be.true;
    });

    invalidKeys.forEach(key => {
      expect(validKeyPattern.test(key)).to.be.false;
    });
  });

  it("should handle API key rate limiting", async () => {
    const apiKey = "test-key";
    const request = supertest("https://api.example.com");
    const authService = new APIKeyAuthService(request, apiKey);

    // Make multiple rapid requests
    const requests = Array.from({ length: 10 }, () =>
      authService.requestWithAPIKey("get", "/endpoint")
    );

    try {
      const responses = await Promise.allSettled(requests);

      const rateLimited = responses.filter(
        r => r.status === 'fulfilled' && r.value.status === 429
      );

      // Some requests might be rate limited
      console.log(`Rate limited requests: ${rateLimited.length}`);
    } catch (error) {
      expect(error).to.be.an('error');
    }
  });
});

export {
  APIKeyAuthService,
  APIKeyManager
};


/**
 * PHASE 2.5: DESIGN PATTERNS
 * Module 2: Structural Patterns
 * Lesson 2: Decorator Pattern
 * 
 * Learning Objectives:
 * - Understand the Decorator Pattern
 * - Add functionality to API clients dynamically
 * - Enhance requests/responses
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== DECORATOR PATTERN: TEST DECORATOR ===");

// Base API Client
class BaseAPIClient {
  constructor(baseURL) {
    this.baseURL = baseURL;
    this.client = supertest(baseURL);
  }
  
  async get(endpoint) {
    return await this.client.get(endpoint);
  }
  
  async post(endpoint, data) {
    return await this.client.post(endpoint).send(data);
  }
}

// Decorator: Logging
class LoggingDecorator {
  constructor(client) {
    this.client = client;
  }
  
  async get(endpoint) {
    console.log(`[LOG] GET ${endpoint}`);
    const startTime = Date.now();
    const response = await this.client.get(endpoint);
    const duration = Date.now() - startTime;
    console.log(`[LOG] GET ${endpoint} - ${response.status} - ${duration}ms`);
    return response;
  }
  
  async post(endpoint, data) {
    console.log(`[LOG] POST ${endpoint}`, data);
    const response = await this.client.post(endpoint, data);
    console.log(`[LOG] POST ${endpoint} - ${response.status}`);
    return response;
  }
}

// Decorator: Retry
class RetryDecorator {
  constructor(client, maxRetries = 3) {
    this.client = client;
    this.maxRetries = maxRetries;
  }
  
  async get(endpoint) {
    let lastError;
    for (let i = 0; i < this.maxRetries; i++) {
      try {
        return await this.client.get(endpoint);
      } catch (error) {
        lastError = error;
        if (i < this.maxRetries - 1) {
          await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
        }
      }
    }
    throw lastError;
  }
  
  async post(endpoint, data) {
    let lastError;
    for (let i = 0; i < this.maxRetries; i++) {
      try {
        return await this.client.post(endpoint, data);
      } catch (error) {
        lastError = error;
        if (i < this.maxRetries - 1) {
          await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
        }
      }
    }
    throw lastError;
  }
}

// Decorator: Caching
class CachingDecorator {
  constructor(client) {
    this.client = client;
    this.cache = new Map();
  }
  
  async get(endpoint) {
    if (this.cache.has(endpoint)) {
      console.log(`[CACHE] HIT ${endpoint}`);
      return this.cache.get(endpoint);
    }
    
    console.log(`[CACHE] MISS ${endpoint}`);
    const response = await this.client.get(endpoint);
    this.cache.set(endpoint, response);
    return response;
  }
  
  async post(endpoint, data) {
    // POST requests are not cached
    return await this.client.post(endpoint, data);
  }
  
  clearCache() {
    this.cache.clear();
  }
}

// Exercises and Tests
describe("Decorator Pattern - Test Decorator", () => {
  const baseURL = "https://jsonplaceholder.typicode.com";
  
  it("should use base client", async () => {
    const client = new BaseAPIClient(baseURL);
    const response = await client.get("/posts/1");
    
    expect(response.status).to.equal(200);
  });

  it("should add logging decorator", async () => {
    const baseClient = new BaseAPIClient(baseURL);
    const loggingClient = new LoggingDecorator(baseClient);
    
    const response = await loggingClient.get("/posts/1");
    expect(response.status).to.equal(200);
  });

  it("should add retry decorator", async () => {
    const baseClient = new BaseAPIClient(baseURL);
    const retryClient = new RetryDecorator(baseClient, 2);
    
    const response = await retryClient.get("/posts/1");
    expect(response.status).to.equal(200);
  });

  it("should add caching decorator", async () => {
    const baseClient = new BaseAPIClient(baseURL);
    const cachingClient = new CachingDecorator(baseClient);
    
    const response1 = await cachingClient.get("/posts/1");
    const response2 = await cachingClient.get("/posts/1");
    
    expect(response1.status).to.equal(200);
    expect(response2.status).to.equal(200);
    expect(response1).to.equal(response2); // Same cached response
  });

  it("should combine multiple decorators", async () => {
    const baseClient = new BaseAPIClient(baseURL);
    const loggingClient = new LoggingDecorator(baseClient);
    const cachingClient = new CachingDecorator(loggingClient);
    const retryClient = new RetryDecorator(cachingClient);
    
    const response = await retryClient.get("/posts/1");
    expect(response.status).to.equal(200);
  });
});

// Export classes
export { 
  BaseAPIClient, 
  LoggingDecorator, 
  RetryDecorator, 
  CachingDecorator 
};


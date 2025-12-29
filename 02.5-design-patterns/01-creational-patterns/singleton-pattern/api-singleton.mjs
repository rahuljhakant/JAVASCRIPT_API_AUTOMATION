/**
 * PHASE 2.5: DESIGN PATTERNS
 * Module 1: Creational Patterns
 * Lesson 3: Singleton Pattern
 * 
 * Learning Objectives:
 * - Understand the Singleton Pattern
 * - Create single instance API clients
 * - Manage shared resources
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== SINGLETON PATTERN: API CLIENT SINGLETON ===");

// Singleton API Client
class APIClientSingleton {
  constructor(baseURL) {
    if (APIClientSingleton.instance) {
      return APIClientSingleton.instance;
    }
    
    this.baseURL = baseURL;
    this.client = supertest(baseURL);
    this.requestCount = 0;
    
    APIClientSingleton.instance = this;
    return this;
  }
  
  async get(endpoint) {
    this.requestCount++;
    return await this.client.get(endpoint);
  }
  
  async post(endpoint, data) {
    this.requestCount++;
    return await this.client.post(endpoint).send(data);
  }
  
  getRequestCount() {
    return this.requestCount;
  }
  
  reset() {
    this.requestCount = 0;
  }
}

// Singleton Factory
class SingletonFactory {
  static getInstance(baseURL) {
    if (!SingletonFactory.instances) {
      SingletonFactory.instances = new Map();
    }
    
    if (!SingletonFactory.instances.has(baseURL)) {
      SingletonFactory.instances.set(baseURL, new APIClientSingleton(baseURL));
    }
    
    return SingletonFactory.instances.get(baseURL);
  }
}

// Exercises and Tests
describe("Singleton Pattern - API Client", () => {
  it("should return same instance", () => {
    const instance1 = new APIClientSingleton("https://jsonplaceholder.typicode.com");
    const instance2 = new APIClientSingleton("https://jsonplaceholder.typicode.com");
    
    expect(instance1).to.equal(instance2);
  });

  it("should share request count across instances", () => {
    const instance1 = new APIClientSingleton("https://jsonplaceholder.typicode.com");
    instance1.reset();
    
    const instance2 = new APIClientSingleton("https://jsonplaceholder.typicode.com");
    
    expect(instance1.getRequestCount()).to.equal(instance2.getRequestCount());
  });

  it("should use SingletonFactory", () => {
    const instance1 = SingletonFactory.getInstance("https://jsonplaceholder.typicode.com");
    const instance2 = SingletonFactory.getInstance("https://jsonplaceholder.typicode.com");
    
    expect(instance1).to.equal(instance2);
  });

  it("should make requests through singleton", async () => {
    const client = new APIClientSingleton("https://jsonplaceholder.typicode.com");
    client.reset();
    
    const response = await client.get("/posts/1");
    
    expect(response.status).to.equal(200);
    expect(client.getRequestCount()).to.equal(1);
  });
});

// Export classes
export { 
  APIClientSingleton, 
  SingletonFactory 
};


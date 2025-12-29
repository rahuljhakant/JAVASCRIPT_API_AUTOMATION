/**
 * PHASE 2.5: DESIGN PATTERNS
 * Module 2: Structural Patterns
 * Lesson 1: Adapter Pattern
 * 
 * Learning Objectives:
 * - Understand the Adapter Pattern
 * - Adapt different API clients to common interface
 * - Integrate incompatible interfaces
 */

import { expect } from "chai";
import supertest from "supertest";
import axios from "axios";

console.log("=== ADAPTER PATTERN: API CLIENT ADAPTER ===");

// Target interface
class APIClient {
  async get(endpoint) {
    throw new Error("Method must be implemented");
  }
  
  async post(endpoint, data) {
    throw new Error("Method must be implemented");
  }
}

// Adaptee 1: Supertest
class SupertestClient {
  constructor(baseURL) {
    this.client = supertest(baseURL);
  }
  
  async getRequest(endpoint) {
    return await this.client.get(endpoint);
  }
  
  async postRequest(endpoint, data) {
    return await this.client.post(endpoint).send(data);
  }
}

// Adaptee 2: Axios
class AxiosClient {
  constructor(baseURL) {
    this.client = axios.create({ baseURL });
  }
  
  async fetch(endpoint) {
    const response = await this.client.get(endpoint);
    return {
      status: response.status,
      body: response.data
    };
  }
  
  async create(endpoint, data) {
    const response = await this.client.post(endpoint, data);
    return {
      status: response.status,
      body: response.data
    };
  }
}

// Adapter for Supertest
class SupertestAdapter extends APIClient {
  constructor(baseURL) {
    super();
    this.adaptee = new SupertestClient(baseURL);
  }
  
  async get(endpoint) {
    const response = await this.adaptee.getRequest(endpoint);
    return {
      status: response.status,
      body: response.body
    };
  }
  
  async post(endpoint, data) {
    const response = await this.adaptee.postRequest(endpoint, data);
    return {
      status: response.status,
      body: response.body
    };
  }
}

// Adapter for Axios
class AxiosAdapter extends APIClient {
  constructor(baseURL) {
    super();
    this.adaptee = new AxiosClient(baseURL);
  }
  
  async get(endpoint) {
    return await this.adaptee.fetch(endpoint);
  }
  
  async post(endpoint, data) {
    return await this.adaptee.create(endpoint, data);
  }
}

// Exercises and Tests
describe("Adapter Pattern - API Client Adapter", () => {
  const baseURL = "https://jsonplaceholder.typicode.com";
  
  it("should adapt Supertest client", async () => {
    const adapter = new SupertestAdapter(baseURL);
    const response = await adapter.get("/posts/1");
    
    expect(response.status).to.equal(200);
    expect(response.body).to.have.property('id');
  });

  it("should adapt Axios client", async () => {
    const adapter = new AxiosAdapter(baseURL);
    const response = await adapter.get("/posts/1");
    
    expect(response.status).to.equal(200);
    expect(response.body).to.have.property('id');
  });

  it("should use adapters interchangeably", async () => {
    const adapters = [
      new SupertestAdapter(baseURL),
      new AxiosAdapter(baseURL)
    ];
    
    for (const adapter of adapters) {
      const response = await adapter.get("/posts/1");
      expect(response.status).to.equal(200);
      expect(response.body).to.have.property('id');
    }
  });

  it("should handle POST requests through adapter", async () => {
    const adapter = new SupertestAdapter(baseURL);
    const data = {
      title: "Test",
      body: "Test body",
      userId: 1
    };
    
    const response = await adapter.post("/posts", data);
    expect(response.status).to.equal(201);
  });
});

// Export classes
export { 
  APIClient, 
  SupertestAdapter, 
  AxiosAdapter 
};


/**
 * PHASE 2.5: DESIGN PATTERNS FOUNDATION
 * Module 1: Creational Patterns
 * Lesson 1: Factory Pattern - API Client Factory
 * 
 * Learning Objectives:
 * - Understand the Factory Pattern
 * - Create different types of API clients
 * - Implement flexible client creation
 */

import { expect } from "chai";
import supertest from "supertest";
import axios from "axios";

console.log("=== FACTORY PATTERN: API CLIENT FACTORY ===");

// Abstract base class for API clients
class APIClient {
  constructor(config) {
    this.baseURL = config.baseURL;
    this.timeout = config.timeout || 5000;
    this.headers = config.headers || {};
  }
  
  async request(method, endpoint, data = null) {
    throw new Error("Request method must be implemented by subclass");
  }
  
  async get(endpoint, params = {}) {
    return await this.request('GET', endpoint, null, params);
  }
  
  async post(endpoint, data) {
    return await this.request('POST', endpoint, data);
  }
  
  async put(endpoint, data) {
    return await this.request('PUT', endpoint, data);
  }
  
  async delete(endpoint) {
    return await this.request('DELETE', endpoint);
  }
}

// Concrete implementations
class SupertestAPIClient extends APIClient {
  constructor(config) {
    super(config);
    this.client = supertest(this.baseURL);
  }
  
  async request(method, endpoint, data = null, params = {}) {
    let request = this.client[method.toLowerCase()](endpoint);
    
    // Add headers
    Object.entries(this.headers).forEach(([key, value]) => {
      request = request.set(key, value);
    });
    
    // Add query parameters
    if (Object.keys(params).length > 0) {
      request = request.query(params);
    }
    
    // Add body for POST/PUT requests
    if (data && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
      request = request.send(data);
    }
    
    const response = await request;
    return {
      status: response.status,
      body: response.body,
      headers: response.headers,
      responseTime: response.responseTime
    };
  }
}

class AxiosAPIClient extends APIClient {
  constructor(config) {
    super(config);
    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: this.timeout,
      headers: this.headers
    });
  }
  
  async request(method, endpoint, data = null, params = {}) {
    try {
      const response = await this.client.request({
        method: method.toLowerCase(),
        url: endpoint,
        data: data,
        params: params
      });
      
      return {
        status: response.status,
        body: response.data,
        headers: response.headers,
        responseTime: response.config.metadata?.responseTime || 0
      };
    } catch (error) {
      return {
        status: error.response?.status || 500,
        body: error.response?.data || { error: error.message },
        headers: error.response?.headers || {},
        responseTime: 0,
        error: true
      };
    }
  }
}

class FetchAPIClient extends APIClient {
  async request(method, endpoint, data = null, params = {}) {
    const url = new URL(endpoint, this.baseURL);
    
    // Add query parameters
    Object.entries(params).forEach(([key, value]) => {
      url.searchParams.append(key, value);
    });
    
    const options = {
      method: method.toUpperCase(),
      headers: {
        'Content-Type': 'application/json',
        ...this.headers
      },
      signal: AbortSignal.timeout(this.timeout)
    };
    
    if (data && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
      options.body = JSON.stringify(data);
    }
    
    const startTime = Date.now();
    const response = await fetch(url.toString(), options);
    const endTime = Date.now();
    
    let responseBody;
    const contentType = response.headers.get('content-type');
    
    if (contentType && contentType.includes('application/json')) {
      responseBody = await response.json();
    } else {
      responseBody = await response.text();
    }
    
    return {
      status: response.status,
      body: responseBody,
      headers: Object.fromEntries(response.headers.entries()),
      responseTime: endTime - startTime
    };
  }
}

// Factory Pattern Implementation
class APIClientFactory {
  static create(type, config) {
    switch (type.toLowerCase()) {
      case 'supertest':
        return new SupertestAPIClient(config);
      case 'axios':
        return new AxiosAPIClient(config);
      case 'fetch':
        return new FetchAPIClient(config);
      default:
        throw new Error(`Unknown API client type: ${type}`);
    }
  }
  
  // Factory method with default configurations
  static createSupertestClient(baseURL, options = {}) {
    return this.create('supertest', {
      baseURL,
      timeout: 10000,
      headers: { 'Accept': 'application/json' },
      ...options
    });
  }
  
  static createAxiosClient(baseURL, options = {}) {
    return this.create('axios', {
      baseURL,
      timeout: 10000,
      headers: { 'Accept': 'application/json' },
      ...options
    });
  }
  
  static createFetchClient(baseURL, options = {}) {
    return this.create('fetch', {
      baseURL,
      timeout: 10000,
      headers: { 'Accept': 'application/json' },
      ...options
    });
  }
  
  // Batch creation for different environments
  static createForEnvironments(baseURL) {
    return {
      development: this.createSupertestClient(baseURL, { timeout: 15000 }),
      testing: this.createAxiosClient(baseURL, { timeout: 5000 }),
      production: this.createFetchClient(baseURL, { timeout: 8000 })
    };
  }
}

// Exercises and Tests
describe("Factory Pattern - API Client Factory", () => {
  const baseURL = "https://jsonplaceholder.typicode.com";
  
  it("should create Supertest client", () => {
    const client = APIClientFactory.create('supertest', { baseURL });
    expect(client).to.be.instanceOf(SupertestAPIClient);
    expect(client.baseURL).to.equal(baseURL);
  });

  it("should create Axios client", () => {
    const client = APIClientFactory.create('axios', { baseURL });
    expect(client).to.be.instanceOf(AxiosAPIClient);
    expect(client.baseURL).to.equal(baseURL);
  });

  it("should create Fetch client", () => {
    const client = APIClientFactory.create('fetch', { baseURL });
    expect(client).to.be.instanceOf(FetchAPIClient);
    expect(client.baseURL).to.equal(baseURL);
  });

  it("should throw error for unknown client type", () => {
    expect(() => {
      APIClientFactory.create('unknown', { baseURL });
    }).to.throw('Unknown API client type: unknown');
  });

  it("should create client with default configurations", () => {
    const client = APIClientFactory.createSupertestClient(baseURL);
    expect(client.timeout).to.equal(10000);
    expect(client.headers['Accept']).to.equal('application/json');
  });

  it("should create clients for different environments", () => {
    const clients = APIClientFactory.createForEnvironments(baseURL);
    
    expect(clients.development).to.be.instanceOf(SupertestAPIClient);
    expect(clients.testing).to.be.instanceOf(AxiosAPIClient);
    expect(clients.production).to.be.instanceOf(FetchAPIClient);
    
    expect(clients.development.timeout).to.equal(15000);
    expect(clients.testing.timeout).to.equal(5000);
    expect(clients.production.timeout).to.equal(8000);
  });
});

// Integration Tests
describe("API Client Integration Tests", () => {
  const baseURL = "https://jsonplaceholder.typicode.com";
  
  it("should make GET request with Supertest client", async () => {
    const client = APIClientFactory.createSupertestClient(baseURL);
    const response = await client.get("/posts/1");
    
    expect(response.status).to.equal(200);
    expect(response.body).to.be.an('object');
    expect(response.body.id).to.equal(1);
  });

  it("should make GET request with Axios client", async () => {
    const client = APIClientFactory.createAxiosClient(baseURL);
    const response = await client.get("/posts/1");
    
    expect(response.status).to.equal(200);
    expect(response.body).to.be.an('object');
    expect(response.body.id).to.equal(1);
  });

  it("should handle errors consistently across clients", async () => {
    const clients = [
      APIClientFactory.createSupertestClient(baseURL),
      APIClientFactory.createAxiosClient(baseURL)
    ];
    
    for (const client of clients) {
      const response = await client.get("/posts/999999");
      expect(response.status).to.equal(404);
    }
  });

  it("should make POST request with different clients", async () => {
    const clients = [
      APIClientFactory.createSupertestClient(baseURL),
      APIClientFactory.createAxiosClient(baseURL)
    ];
    
    const testData = {
      title: "Test Post",
      body: "Test Body",
      userId: 1
    };
    
    for (const client of clients) {
      const response = await client.post("/posts", testData);
      expect(response.status).to.equal(201);
      expect(response.body).to.have.property('id');
    }
  });
});

// Performance Comparison
describe("Client Performance Comparison", () => {
  const baseURL = "https://jsonplaceholder.typicode.com";
  
  it("should compare response times across clients", async () => {
    const clients = {
      supertest: APIClientFactory.createSupertestClient(baseURL),
      axios: APIClientFactory.createAxiosClient(baseURL)
    };
    
    const results = {};
    
    for (const [name, client] of Object.entries(clients)) {
      const startTime = Date.now();
      const response = await client.get("/posts/1");
      const endTime = Date.now();
      
      results[name] = {
        responseTime: endTime - startTime,
        status: response.status,
        success: response.status === 200
      };
    }
    
    expect(results.supertest.success).to.be.true;
    expect(results.axios.success).to.be.true;
    
    console.log("Performance Comparison:", results);
  });
});

// Advanced Factory Usage
describe("Advanced Factory Patterns", () => {
  it("should create client with custom configuration", () => {
    const customConfig = {
      baseURL: "https://api.example.com",
      timeout: 15000,
      headers: {
        'Authorization': 'Bearer token123',
        'X-API-Version': 'v2'
      }
    };
    
    const client = APIClientFactory.create('axios', customConfig);
    expect(client.timeout).to.equal(15000);
    expect(client.headers['Authorization']).to.equal('Bearer token123');
  });

  it("should create multiple clients with different configurations", () => {
    const configs = [
      { baseURL: "https://api1.example.com", timeout: 5000 },
      { baseURL: "https://api2.example.com", timeout: 10000 },
      { baseURL: "https://api3.example.com", timeout: 15000 }
    ];
    
    const clients = configs.map(config => 
      APIClientFactory.create('axios', config)
    );
    
    expect(clients).to.have.length(3);
    clients.forEach((client, index) => {
      expect(client.baseURL).to.equal(configs[index].baseURL);
      expect(client.timeout).to.equal(configs[index].timeout);
    });
  });
});

export { 
  APIClientFactory, 
  SupertestAPIClient, 
  AxiosAPIClient, 
  FetchAPIClient 
};

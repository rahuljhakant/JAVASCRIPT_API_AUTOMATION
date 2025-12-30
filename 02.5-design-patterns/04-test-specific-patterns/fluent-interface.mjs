/**
 * PHASE 2.5: DESIGN PATTERNS
 * Module 4: Test-Specific Patterns
 * Lesson 3: Fluent Interface Pattern
 * 
 * Learning Objectives:
 * - Implement Fluent Interface pattern for API testing
 * - Create chainable API request builders
 * - Improve test readability
 * - Enable method chaining for complex requests
 */

import { expect } from "chai";
import supertest from "supertest";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== FLUENT INTERFACE PATTERN ===");

const BASE_URL = "https://gorest.co.in/public-api/";
const TOKEN = getApiToken();

// Fluent API Request Builder
class FluentAPIRequest {
  constructor(apiClient, method, endpoint) {
    this.apiClient = apiClient;
    this.method = method;
    this.endpoint = endpoint;
    this.headers = {};
    this.queryParams = {};
    this.body = null;
    this.timeout = null;
  }

  withHeader(key, value) {
    this.headers[key] = value;
    return this;
  }

  withAuth(token) {
    this.headers.Authorization = `Bearer ${token}`;
    return this;
  }

  withQueryParam(key, value) {
    this.queryParams[key] = value;
    return this;
  }

  withQueryParams(params) {
    Object.assign(this.queryParams, params);
    return this;
  }

  withBody(data) {
    this.body = data;
    return this;
  }

  withTimeout(ms) {
    this.timeout = ms;
    return this;
  }

  async execute() {
    let request = this.apiClient[this.method.toLowerCase()](this.endpoint);
    
    // Set headers
    Object.entries(this.headers).forEach(([key, value]) => {
      request = request.set(key, value);
    });
    
    // Set query parameters
    if (Object.keys(this.queryParams).length > 0) {
      request = request.query(this.queryParams);
    }
    
    // Set body
    if (this.body) {
      request = request.send(this.body);
    }
    
    // Set timeout
    if (this.timeout) {
      request = request.timeout(this.timeout);
    }
    
    return await request;
  }

  async expectStatus(statusCode) {
    const response = await this.execute();
    expect(response.status).to.equal(statusCode);
    return response;
  }

  async expectSuccess() {
    const response = await this.execute();
    expect(response.status).to.be.at.least(200).and.below(300);
    return response;
  }
}

// Fluent API Client
class FluentAPIClient {
  constructor(baseUrl, defaultAuthToken = null) {
    this.apiClient = supertest(baseUrl);
    this.defaultAuthToken = defaultAuthToken;
  }

  get(endpoint) {
    const request = new FluentAPIRequest(this.apiClient, "GET", endpoint);
    if (this.defaultAuthToken) {
      request.withAuth(this.defaultAuthToken);
    }
    return request;
  }

  post(endpoint) {
    const request = new FluentAPIRequest(this.apiClient, "POST", endpoint);
    if (this.defaultAuthToken) {
      request.withAuth(this.defaultAuthToken);
    }
    return request;
  }

  put(endpoint) {
    const request = new FluentAPIRequest(this.apiClient, "PUT", endpoint);
    if (this.defaultAuthToken) {
      request.withAuth(this.defaultAuthToken);
    }
    return request;
  }

  patch(endpoint) {
    const request = new FluentAPIRequest(this.apiClient, "PATCH", endpoint);
    if (this.defaultAuthToken) {
      request.withAuth(this.defaultAuthToken);
    }
    return request;
  }

  delete(endpoint) {
    const request = new FluentAPIRequest(this.apiClient, "DELETE", endpoint);
    if (this.defaultAuthToken) {
      request.withAuth(this.defaultAuthToken);
    }
    return request;
  }
}

// Test Scenarios
async function testFluentGetRequest() {
  console.log("\n📝 Test 1: Fluent GET Request");
  
  const client = new FluentAPIClient(BASE_URL, TOKEN);
  
  const response = await client
    .get("/users")
    .withQueryParam("page", 1)
    .withQueryParam("per_page", 10)
    .expectStatus(200);
  
  expect(response.body).to.have.property("data");
  console.log("✅ Fluent GET request successful");
}

async function testFluentPostRequest() {
  console.log("\n📝 Test 2: Fluent POST Request");
  
  const client = new FluentAPIClient(BASE_URL, TOKEN);
  
  const newUser = {
    name: "Fluent Test User",
    email: `fluenttest${Date.now()}@example.com`,
    gender: "male",
    status: "active"
  };
  
  const response = await client
    .post("/users")
    .withBody(newUser)
    .expectStatus(201);
  
  expect(response.body.data).to.have.property("id");
  const userId = response.body.data.id;
  console.log(`✅ User created: ${userId}`);
  
  // Cleanup
  await client
    .delete(`/users/${userId}`)
    .expectStatus(204);
  
  console.log("✅ Fluent POST request successful");
}

async function testFluentUpdateRequest() {
  console.log("\n📝 Test 3: Fluent UPDATE Request");
  
  const client = new FluentAPIClient(BASE_URL, TOKEN);
  
  // Create user first
  const newUser = {
    name: "Fluent Update User",
    email: `fluentupdate${Date.now()}@example.com`,
    gender: "male",
    status: "active"
  };
  
  const createResponse = await client
    .post("/users")
    .withBody(newUser)
    .expectSuccess();
  
  const userId = createResponse.body.data.id;
  
  // Update user using fluent interface
  const updateResponse = await client
    .patch(`/users/${userId}`)
    .withBody({ name: "Updated Fluent User" })
    .expectStatus(200);
  
  expect(updateResponse.body.data.name).to.equal("Updated Fluent User");
  console.log("✅ User updated via fluent interface");
  
  // Cleanup
  await client
    .delete(`/users/${userId}`)
    .expectStatus(204);
}

async function testFluentChaining() {
  console.log("\n📝 Test 4: Fluent Method Chaining");
  
  const client = new FluentAPIClient(BASE_URL, TOKEN);
  
  // Complex chained request
  const response = await client
    .get("/users")
    .withQueryParams({
      page: 1,
      per_page: 5
    })
    .withHeader("Accept", "application/json")
    .withTimeout(5000)
    .expectSuccess();
  
  expect(response.body.data).to.be.an("array");
  expect(response.body.data.length).to.be.at.most(5);
  
  console.log("✅ Fluent method chaining successful");
}

async function testFluentWithoutDefaultAuth() {
  console.log("\n📝 Test 5: Fluent Interface without Default Auth");
  
  const client = new FluentAPIClient(BASE_URL); // No default token
  
  // Add auth manually
  const response = await client
    .get("/users")
    .withAuth(TOKEN)
    .withQueryParam("page", 1)
    .expectStatus(200);
  
  expect(response.body).to.have.property("data");
  console.log("✅ Fluent interface with manual auth successful");
}

// Run all tests
(async () => {
  try {
    await testFluentGetRequest();
    await testFluentPostRequest();
    await testFluentUpdateRequest();
    await testFluentChaining();
    await testFluentWithoutDefaultAuth();
    
    console.log("\n✅ All Fluent Interface Pattern tests completed!");
  } catch (error) {
    console.error("❌ Fluent Interface test failed:", error.message);
    process.exit(1);
  }
})();


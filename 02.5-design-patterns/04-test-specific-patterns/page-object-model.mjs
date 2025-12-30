/**
 * PHASE 2.5: DESIGN PATTERNS
 * Module 4: Test-Specific Patterns
 * Lesson 1: Page Object Model for API Testing
 * 
 * Learning Objectives:
 * - Implement Page Object Model for APIs
 * - Create reusable API interaction objects
 * - Encapsulate endpoint logic
 * - Improve test maintainability
 */

import { expect } from "chai";
import supertest from "supertest";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== PAGE OBJECT MODEL ===");

const BASE_URL = "https://gorest.co.in/public-api/";
const TOKEN = getApiToken();

// Base API Page Object
class BaseAPIPage {
  constructor(apiClient, authToken) {
    this.apiClient = apiClient;
    this.authToken = authToken;
  }

  getHeaders() {
    return {
      Authorization: `Bearer ${this.authToken}`,
      "Content-Type": "application/json"
    };
  }

  async get(endpoint, queryParams = {}) {
    let request = this.apiClient.get(endpoint)
      .set(this.getHeaders());
    
    if (Object.keys(queryParams).length > 0) {
      request = request.query(queryParams);
    }
    
    return await request;
  }

  async post(endpoint, data) {
    return await this.apiClient.post(endpoint)
      .set(this.getHeaders())
      .send(data);
  }

  async put(endpoint, data) {
    return await this.apiClient.put(endpoint)
      .set(this.getHeaders())
      .send(data);
  }

  async patch(endpoint, data) {
    return await this.apiClient.patch(endpoint)
      .set(this.getHeaders())
      .send(data);
  }

  async delete(endpoint) {
    return await this.apiClient.delete(endpoint)
      .set(this.getHeaders());
  }
}

// Users Page Object
class UsersPage extends BaseAPIPage {
  constructor(apiClient, authToken) {
    super(apiClient, authToken);
    this.endpoint = "/users";
  }

  async getAllUsers(page = 1, perPage = 20) {
    return await this.get(this.endpoint, { page, per_page: perPage });
  }

  async getUserById(userId) {
    return await this.get(`${this.endpoint}/${userId}`);
  }

  async createUser(userData) {
    return await this.post(this.endpoint, userData);
  }

  async updateUser(userId, userData) {
    return await this.put(`${this.endpoint}/${userId}`, userData);
  }

  async partialUpdateUser(userId, userData) {
    return await this.patch(`${this.endpoint}/${userId}`, userData);
  }

  async deleteUser(userId) {
    return await this.delete(`${this.endpoint}/${userId}`);
  }

  async searchUsers(query) {
    return await this.get(this.endpoint, { name: query });
  }

  async getUsersByStatus(status) {
    return await this.get(this.endpoint, { status });
  }
}

// Posts Page Object
class PostsPage extends BaseAPIPage {
  constructor(apiClient, authToken) {
    super(apiClient, authToken);
    this.endpoint = "/posts";
  }

  async getAllPosts(page = 1, perPage = 20) {
    return await this.get(this.endpoint, { page, per_page: perPage });
  }

  async getPostById(postId) {
    return await this.get(`${this.endpoint}/${postId}`);
  }

  async getPostsByUserId(userId) {
    return await this.get(this.endpoint, { user_id: userId });
  }

  async createPost(postData) {
    return await this.post(this.endpoint, postData);
  }

  async updatePost(postId, postData) {
    return await this.put(`${this.endpoint}/${postId}`, postData);
  }

  async deletePost(postId) {
    return await this.delete(`${this.endpoint}/${postId}`);
  }
}

// Page Object Factory
class PageObjectFactory {
  static create(baseUrl, authToken) {
    const apiClient = supertest(baseUrl);
    return {
      users: new UsersPage(apiClient, authToken),
      posts: new PostsPage(apiClient, authToken)
    };
  }
}

// Test Scenarios
async function testPageObjectModel() {
  console.log("\n📝 Test 1: Page Object Model Usage");
  
  const pages = PageObjectFactory.create(BASE_URL, TOKEN);
  
  // Create user using page object
  const newUser = {
    name: "POM Test User",
    email: `pomtest${Date.now()}@example.com`,
    gender: "male",
    status: "active"
  };
  
  const createResponse = await pages.users.createUser(newUser);
  expect(createResponse.status).to.equal(201);
  const userId = createResponse.body.data.id;
  console.log(`✅ User created via Page Object: ${userId}`);
  
  // Get user using page object
  const getUserResponse = await pages.users.getUserById(userId);
  expect(getUserResponse.status).to.equal(200);
  expect(getUserResponse.body.data.id).to.equal(userId);
  console.log("✅ User retrieved via Page Object");
  
  // Update user using page object
  const updateResponse = await pages.users.partialUpdateUser(userId, { name: "Updated POM User" });
  expect(updateResponse.status).to.equal(200);
  console.log("✅ User updated via Page Object");
  
  // Delete user using page object
  const deleteResponse = await pages.users.deleteUser(userId);
  expect(deleteResponse.status).to.equal(204);
  console.log("✅ User deleted via Page Object");
}

async function testPageObjectReusability() {
  console.log("\n📝 Test 2: Page Object Reusability");
  
  const pages = PageObjectFactory.create(BASE_URL, TOKEN);
  
  // Test multiple operations using same page object
  const users = [];
  
  // Create multiple users
  for (let i = 0; i < 3; i++) {
    const user = {
      name: `POM User ${i + 1}`,
      email: `pomuser${i + 1}${Date.now()}@example.com`,
      gender: i % 2 === 0 ? "male" : "female",
      status: "active"
    };
    
    const response = await pages.users.createUser(user);
    users.push(response.body.data.id);
  }
  
  // Get all users
  const allUsersResponse = await pages.users.getAllUsers();
  expect(allUsersResponse.status).to.equal(200);
  console.log(`✅ Retrieved ${allUsersResponse.body.data.length} users`);
  
  // Cleanup
  for (const userId of users) {
    await pages.users.deleteUser(userId);
  }
  console.log("✅ Cleanup completed");
}

// Run all tests
(async () => {
  try {
    await testPageObjectModel();
    await testPageObjectReusability();
    
    console.log("\n✅ All Page Object Model tests completed!");
  } catch (error) {
    console.error("❌ Page Object Model test failed:", error.message);
    process.exit(1);
  }
})();


/**
 * PHASE 3: ADVANCED LEVEL
 * Module 3: Test Patterns
 * Lesson 1: Page Object Pattern for API Testing
 * 
 * Learning Objectives:
 * - Implement Page Object Pattern for API testing
 * - Create reusable API interaction objects
 * - Encapsulate API endpoints and operations
 * - Improve test maintainability
 */

import { expect } from "chai";
import supertest from "supertest";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== PAGE OBJECT PATTERN ===");

const BASE_URL = "https://gorest.co.in/public-api/";
const TOKEN = getApiToken();

// Base Page Object
class BasePageObject {
  constructor(apiClient, authToken) {
    this.apiClient = apiClient;
    this.authToken = authToken;
    this.basePath = "";
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
class UsersPageObject extends BasePageObject {
  constructor(apiClient, authToken) {
    super(apiClient, authToken);
    this.basePath = "/users";
  }

  async getAllUsers(page = 1, perPage = 20) {
    return await this.get(this.basePath, { page, per_page: perPage });
  }

  async getUserById(userId) {
    return await this.get(`${this.basePath}/${userId}`);
  }

  async createUser(userData) {
    return await this.post(this.basePath, userData);
  }

  async updateUser(userId, userData) {
    return await this.put(`${this.basePath}/${userId}`, userData);
  }

  async partialUpdateUser(userId, userData) {
    return await this.patch(`${this.basePath}/${userId}`, userData);
  }

  async deleteUser(userId) {
    return await this.delete(`${this.basePath}/${userId}`);
  }

  async searchUsers(query) {
    return await this.get(this.basePath, { name: query });
  }

  async getUsersByStatus(status) {
    return await this.get(this.basePath, { status });
  }

  async getUsersByGender(gender) {
    return await this.get(this.basePath, { gender });
  }
}

// Posts Page Object
class PostsPageObject extends BasePageObject {
  constructor(apiClient, authToken) {
    super(apiClient, authToken);
    this.basePath = "/posts";
  }

  async getAllPosts(page = 1, perPage = 20) {
    return await this.get(this.basePath, { page, per_page: perPage });
  }

  async getPostById(postId) {
    return await this.get(`${this.basePath}/${postId}`);
  }

  async getPostsByUserId(userId) {
    return await this.get(this.basePath, { user_id: userId });
  }

  async createPost(postData) {
    return await this.post(this.basePath, postData);
  }

  async updatePost(postId, postData) {
    return await this.put(`${this.basePath}/${postId}`, postData);
  }

  async deletePost(postId) {
    return await this.delete(`${this.basePath}/${postId}`);
  }
}

// Comments Page Object
class CommentsPageObject extends BasePageObject {
  constructor(apiClient, authToken) {
    super(apiClient, authToken);
    this.basePath = "/comments";
  }

  async getAllComments(page = 1, perPage = 20) {
    return await this.get(this.basePath, { page, per_page: perPage });
  }

  async getCommentById(commentId) {
    return await this.get(`${this.basePath}/${commentId}`);
  }

  async getCommentsByPostId(postId) {
    return await this.get(this.basePath, { post_id: postId });
  }

  async createComment(commentData) {
    return await this.post(this.basePath, commentData);
  }

  async updateComment(commentId, commentData) {
    return await this.put(`${this.basePath}/${commentId}`, commentData);
  }

  async deleteComment(commentId) {
    return await this.delete(`${this.basePath}/${commentId}`);
  }
}

// API Client Factory
class APIClientFactory {
  static create(baseUrl, authToken) {
    const apiClient = supertest(baseUrl);
    return {
      users: new UsersPageObject(apiClient, authToken),
      posts: new PostsPageObject(apiClient, authToken),
      comments: new CommentsPageObject(apiClient, authToken)
    };
  }
}

// Test Scenarios using Page Objects
async function testUserOperations() {
  console.log("\n📝 Test 1: User Operations using Page Object");
  
  const api = APIClientFactory.create(BASE_URL, TOKEN);
  
  // Create user
  const newUser = {
    name: "Page Object User",
    email: `pageobject${Date.now()}@example.com`,
    gender: "male",
    status: "active"
  };
  
  const createResponse = await api.users.createUser(newUser);
  expect(createResponse.status).to.equal(201);
  expect(createResponse.body.data).to.have.property("id");
  
  const userId = createResponse.body.data.id;
  console.log(`✅ User created with ID: ${userId}`);
  
  // Get user
  const getUserResponse = await api.users.getUserById(userId);
  expect(getUserResponse.status).to.equal(200);
  expect(getUserResponse.body.data.id).to.equal(userId);
  console.log("✅ User retrieved successfully");
  
  // Update user
  const updateData = { name: "Updated Page Object User" };
  const updateResponse = await api.users.partialUpdateUser(userId, updateData);
  expect(updateResponse.status).to.equal(200);
  console.log("✅ User updated successfully");
  
  // Delete user
  const deleteResponse = await api.users.deleteUser(userId);
  expect(deleteResponse.status).to.equal(204);
  console.log("✅ User deleted successfully");
}

async function testPostOperations() {
  console.log("\n📝 Test 2: Post Operations using Page Object");
  
  const api = APIClientFactory.create(BASE_URL, TOKEN);
  
  // First create a user
  const newUser = {
    name: "Post Test User",
    email: `posttest${Date.now()}@example.com`,
    gender: "male",
    status: "active"
  };
  
  const userResponse = await api.users.createUser(newUser);
  const userId = userResponse.body.data.id;
  
  // Create post
  const newPost = {
    user_id: userId,
    title: "Test Post",
    body: "This is a test post created using Page Object Pattern"
  };
  
  const createPostResponse = await api.posts.createPost(newPost);
  expect(createPostResponse.status).to.equal(201);
  const postId = createPostResponse.body.data.id;
  console.log(`✅ Post created with ID: ${postId}`);
  
  // Get posts by user
  const userPostsResponse = await api.posts.getPostsByUserId(userId);
  expect(userPostsResponse.status).to.equal(200);
  expect(userPostsResponse.body.data.length).to.be.greaterThan(0);
  console.log("✅ User posts retrieved successfully");
  
  // Cleanup
  await api.posts.deletePost(postId);
  await api.users.deleteUser(userId);
  console.log("✅ Cleanup completed");
}

async function testCommentOperations() {
  console.log("\n📝 Test 3: Comment Operations using Page Object");
  
  const api = APIClientFactory.create(BASE_URL, TOKEN);
  
  // Create user and post first
  const newUser = {
    name: "Comment Test User",
    email: `commenttest${Date.now()}@example.com`,
    gender: "male",
    status: "active"
  };
  
  const userResponse = await api.users.createUser(newUser);
  const userId = userResponse.body.data.id;
  
  const newPost = {
    user_id: userId,
    title: "Comment Test Post",
    body: "Post for comment testing"
  };
  
  const postResponse = await api.posts.createPost(newPost);
  const postId = postResponse.body.data.id;
  
  // Create comment
  const newComment = {
    post_id: postId,
    name: "Comment Author",
    email: `comment${Date.now()}@example.com`,
    body: "This is a test comment"
  };
  
  const createCommentResponse = await api.comments.createComment(newComment);
  expect(createCommentResponse.status).to.equal(201);
  const commentId = createCommentResponse.body.data.id;
  console.log(`✅ Comment created with ID: ${commentId}`);
  
  // Get comments by post
  const postCommentsResponse = await api.comments.getCommentsByPostId(postId);
  expect(postCommentsResponse.status).to.equal(200);
  console.log("✅ Post comments retrieved successfully");
  
  // Cleanup
  await api.comments.deleteComment(commentId);
  await api.posts.deletePost(postId);
  await api.users.deleteUser(userId);
  console.log("✅ Cleanup completed");
}

// Run all tests
(async () => {
  try {
    await testUserOperations();
    await testPostOperations();
    await testCommentOperations();
    
    console.log("\n✅ All Page Object Pattern tests completed!");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
})();


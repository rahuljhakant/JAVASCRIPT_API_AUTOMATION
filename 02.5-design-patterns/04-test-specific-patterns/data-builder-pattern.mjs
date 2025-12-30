/**
 * PHASE 2.5: DESIGN PATTERNS
 * Module 4: Test-Specific Patterns
 * Lesson 2: Data Builder Pattern
 * 
 * Learning Objectives:
 * - Implement Data Builder pattern for test data
 * - Create flexible test data builders
 * - Generate complex nested data structures
 * - Reuse and customize test data easily
 */

import { expect } from "chai";
import supertest from "supertest";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== DATA BUILDER PATTERN ===");

const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = getApiToken();

// User Data Builder
class UserDataBuilder {
  constructor() {
    this.user = {
      name: "Default User",
      email: `default${Date.now()}@example.com`,
      gender: "male",
      status: "active"
    };
  }

  withName(name) {
    this.user.name = name;
    return this;
  }

  withEmail(email) {
    this.user.email = email;
    return this;
  }

  withGender(gender) {
    this.user.gender = gender;
    return this;
  }

  withStatus(status) {
    this.user.status = status;
    return this;
  }

  asInactive() {
    this.user.status = "inactive";
    return this;
  }

  asFemale() {
    this.user.gender = "female";
    return this;
  }

  withRandomEmail() {
    this.user.email = `user${Date.now()}${Math.random().toString(36).substr(2, 9)}@example.com`;
    return this;
  }

  build() {
    return { ...this.user };
  }

  static create() {
    return new UserDataBuilder();
  }
}

// Post Data Builder
class PostDataBuilder {
  constructor(userId) {
    this.post = {
      user_id: userId,
      title: "Default Post Title",
      body: "Default post body content"
    };
  }

  withTitle(title) {
    this.post.title = title;
    return this;
  }

  withBody(body) {
    this.post.body = body;
    return this;
  }

  withUserId(userId) {
    this.post.user_id = userId;
    return this;
  }

  build() {
    return { ...this.post };
  }

  static create(userId) {
    return new PostDataBuilder(userId);
  }
}

// Comment Data Builder
class CommentDataBuilder {
  constructor(postId) {
    this.comment = {
      post_id: postId,
      name: "Default Commenter",
      email: `commenter${Date.now()}@example.com`,
      body: "Default comment body"
    };
  }

  withName(name) {
    this.comment.name = name;
    return this;
  }

  withEmail(email) {
    this.comment.email = email;
    return this;
  }

  withBody(body) {
    this.comment.body = body;
    return this;
  }

  withPostId(postId) {
    this.comment.post_id = postId;
    return this;
  }

  build() {
    return { ...this.comment };
  }

  static create(postId) {
    return new CommentDataBuilder(postId);
  }
}

// Test Scenarios
async function testUserDataBuilder() {
  console.log("\n📝 Test 1: User Data Builder");
  
  // Build user with default values
  const defaultUser = UserDataBuilder.create().build();
  expect(defaultUser).to.have.property("name");
  expect(defaultUser).to.have.property("email");
  console.log("✅ Default user:", defaultUser);
  
  // Build user with custom values
  const customUser = UserDataBuilder.create()
    .withName("Custom User")
    .withEmail("custom@example.com")
    .asFemale()
    .asInactive()
    .build();
  
  expect(customUser.name).to.equal("Custom User");
  expect(customUser.gender).to.equal("female");
  expect(customUser.status).to.equal("inactive");
  console.log("✅ Custom user:", customUser);
  
  // Build user with random email
  const randomUser = UserDataBuilder.create()
    .withName("Random User")
    .withRandomEmail()
    .build();
  
  expect(randomUser.email).to.include("@example.com");
  console.log("✅ Random user:", randomUser);
}

async function testPostDataBuilder() {
  console.log("\n📝 Test 2: Post Data Builder");
  
  // First create a user
  const userBuilder = UserDataBuilder.create()
    .withName("Post Test User")
    .withRandomEmail();
  
  const userData = userBuilder.build();
  
  const createUserResponse = await request
    .post("/users")
    .set("Authorization", `Bearer ${TOKEN}`)
    .send(userData);
  
  const userId = createUserResponse.body.data.id;
  
  // Build post using builder
  const post = PostDataBuilder.create(userId)
    .withTitle("Test Post")
    .withBody("This is a test post created using Data Builder pattern")
    .build();
  
  expect(post.user_id).to.equal(userId);
  expect(post.title).to.equal("Test Post");
  
  // Create post via API
  const createPostResponse = await request
    .post("/posts")
    .set("Authorization", `Bearer ${TOKEN}`)
    .send(post);
  
  expect(createPostResponse.status).to.equal(201);
  const postId = createPostResponse.body.data.id;
  console.log(`✅ Post created: ${postId}`);
  
  // Cleanup
  await request
    .delete(`/posts/${postId}`)
    .set("Authorization", `Bearer ${TOKEN}`);
  
  await request
    .delete(`/users/${userId}`)
    .set("Authorization", `Bearer ${TOKEN}`);
}

async function testCommentDataBuilder() {
  console.log("\n📝 Test 3: Comment Data Builder");
  
  // Create user and post first
  const user = UserDataBuilder.create()
    .withName("Comment Test User")
    .withRandomEmail()
    .build();
  
  const createUserResponse = await request
    .post("/users")
    .set("Authorization", `Bearer ${TOKEN}`)
    .send(user);
  
  const userId = createUserResponse.body.data.id;
  
  const post = PostDataBuilder.create(userId)
    .withTitle("Comment Test Post")
    .withBody("Post for comment testing")
    .build();
  
  const createPostResponse = await request
    .post("/posts")
    .set("Authorization", `Bearer ${TOKEN}`)
    .send(post);
  
  const postId = createPostResponse.body.data.id;
  
  // Build comment using builder
  const comment = CommentDataBuilder.create(postId)
    .withName("Comment Author")
    .withEmail("commenter@example.com")
    .withBody("This is a test comment")
    .build();
  
  expect(comment.post_id).to.equal(postId);
  
  // Create comment via API
  const createCommentResponse = await request
    .post("/comments")
    .set("Authorization", `Bearer ${TOKEN}`)
    .send(comment);
  
  expect(createCommentResponse.status).to.equal(201);
  const commentId = createCommentResponse.body.data.id;
  console.log(`✅ Comment created: ${commentId}`);
  
  // Cleanup
  await request
    .delete(`/comments/${commentId}`)
    .set("Authorization", `Bearer ${TOKEN}`);
  
  await request
    .delete(`/posts/${postId}`)
    .set("Authorization", `Bearer ${TOKEN}`);
  
  await request
    .delete(`/users/${userId}`)
    .set("Authorization", `Bearer ${TOKEN}`);
}

async function testFluentInterface() {
  console.log("\n📝 Test 4: Fluent Interface Pattern");
  
  // Chain multiple builder methods
  const user = UserDataBuilder.create()
    .withName("Fluent User")
    .withRandomEmail()
    .asFemale()
    .asInactive()
    .build();
  
  expect(user.name).to.equal("Fluent User");
  expect(user.gender).to.equal("female");
  expect(user.status).to.equal("inactive");
  
  console.log("✅ Fluent interface test passed");
  console.log("✅ User built:", user);
}

// Run all tests
(async () => {
  try {
    await testUserDataBuilder();
    await testPostDataBuilder();
    await testCommentDataBuilder();
    await testFluentInterface();
    
    console.log("\n✅ All Data Builder Pattern tests completed!");
  } catch (error) {
    console.error("❌ Data Builder test failed:", error.message);
    process.exit(1);
  }
})();


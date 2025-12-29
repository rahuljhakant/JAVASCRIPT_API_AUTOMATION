/**
 * PHASE 2.5: DESIGN PATTERNS
 * Module 2: Structural Patterns
 * Lesson 3: Facade Pattern
 * 
 * Learning Objectives:
 * - Understand the Facade Pattern
 * - Simplify complex API interactions
 * - Provide unified interface
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== FACADE PATTERN: API FACADE ===");

// Complex subsystems
class UserService {
  constructor(client) {
    this.client = client;
  }
  
  async getUser(id) {
    return await this.client.get(`/users/${id}`);
  }
  
  async getUsers() {
    return await this.client.get("/users");
  }
}

class PostService {
  constructor(client) {
    this.client = client;
  }
  
  async getPost(id) {
    return await this.client.get(`/posts/${id}`);
  }
  
  async getPosts() {
    return await this.client.get("/posts");
  }
  
  async getPostsByUser(userId) {
    return await this.client.get("/posts").query({ userId });
  }
}

class CommentService {
  constructor(client) {
    this.client = client;
  }
  
  async getComments(postId) {
    return await this.client.get("/comments").query({ postId });
  }
}

// Facade: Simplified API
class APIFacade {
  constructor(baseURL) {
    this.client = supertest(baseURL);
    this.userService = new UserService(this.client);
    this.postService = new PostService(this.client);
    this.commentService = new CommentService(this.client);
  }
  
  // Simplified methods that hide complexity
  async getUserProfile(userId) {
    const [userResponse, postsResponse] = await Promise.all([
      this.userService.getUser(userId),
      this.postService.getPostsByUser(userId)
    ]);
    
    return {
      user: userResponse.body,
      posts: postsResponse.body
    };
  }
  
  async getPostWithComments(postId) {
    const [postResponse, commentsResponse] = await Promise.all([
      this.postService.getPost(postId),
      this.commentService.getComments(postId)
    ]);
    
    return {
      post: postResponse.body,
      comments: commentsResponse.body
    };
  }
  
  async getCompleteUserData(userId) {
    const userProfile = await this.getUserProfile(userId);
    const postsWithComments = await Promise.all(
      userProfile.posts.map(post => this.getPostWithComments(post.id))
    );
    
    return {
      ...userProfile,
      postsWithComments
    };
  }
}

// Exercises and Tests
describe("Facade Pattern - API Facade", () => {
  const baseURL = "https://jsonplaceholder.typicode.com";
  
  it("should use facade to get user profile", async () => {
    const facade = new APIFacade(baseURL);
    const profile = await facade.getUserProfile(1);
    
    expect(profile).to.have.property('user');
    expect(profile).to.have.property('posts');
    expect(profile.user.id).to.equal(1);
    expect(profile.posts).to.be.an('array');
  });

  it("should use facade to get post with comments", async () => {
    const facade = new APIFacade(baseURL);
    const data = await facade.getPostWithComments(1);
    
    expect(data).to.have.property('post');
    expect(data).to.have.property('comments');
    expect(data.post.id).to.equal(1);
    expect(data.comments).to.be.an('array');
  });

  it("should use facade for complex operations", async () => {
    const facade = new APIFacade(baseURL);
    const completeData = await facade.getCompleteUserData(1);
    
    expect(completeData).to.have.property('user');
    expect(completeData).to.have.property('posts');
    expect(completeData).to.have.property('postsWithComments');
  });

  it("should hide subsystem complexity", () => {
    const facade = new APIFacade(baseURL);
    
    // User doesn't need to know about UserService, PostService, etc.
    expect(facade.userService).to.exist;
    expect(facade.postService).to.exist;
    expect(facade.commentService).to.exist;
  });
});

// Export classes
export { 
  APIFacade, 
  UserService, 
  PostService, 
  CommentService 
};


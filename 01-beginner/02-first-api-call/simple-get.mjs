/**
 * PHASE 1: BEGINNER LEVEL
 * Module 2: First API Call
 * Lesson 1: Simple GET Request
 * 
 * Learning Objectives:
 * - Make your first API call
 * - Understand request/response structure
 * - Handle basic response data
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== YOUR FIRST API CALL ===");

// Set up the API client
const request = supertest("https://jsonplaceholder.typicode.com");

// Simple GET request example
async function makeSimpleGetRequest() {
  console.log("Making GET request to /posts/1...");
  
  try {
    const response = await request.get("/posts/1");
    
    console.log("Response Status:", response.status);
    console.log("Response Headers:", response.headers);
    console.log("Response Body:", response.body);
    
    return response;
  } catch (error) {
    console.error("Error making request:", error.message);
    throw error;
  }
}

// Understanding the response structure
function analyzeResponse(response) {
  return {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
    body: response.body,
    responseTime: response.responseTime,
    size: JSON.stringify(response.body).length
  };
}

// Exercises and Tests
describe("Simple GET Request", () => {
  it("should make a successful GET request", async () => {
    const response = await request.get("/posts/1");
    
    // Basic assertions
    expect(response.status).to.equal(200);
    expect(response.body).to.be.an('object');
    expect(response.body).to.have.property('id');
    expect(response.body).to.have.property('title');
    expect(response.body).to.have.property('body');
  });

  it("should return expected data structure", async () => {
    const response = await request.get("/posts/1");
    
    // Validate data structure
    expect(response.body.id).to.equal(1);
    expect(response.body.title).to.be.a('string');
    expect(response.body.body).to.be.a('string');
    expect(response.body.userId).to.be.a('number');
  });

  it("should handle response analysis", async () => {
    const response = await request.get("/posts/1");
    const analysis = analyzeResponse(response);
    
    expect(analysis.status).to.equal(200);
    expect(analysis.body).to.have.property('id');
    expect(analysis.size).to.be.greaterThan(0);
  });

  it("should handle multiple GET requests", async () => {
    const posts = [1, 2, 3];
    const responses = [];
    
    for (const postId of posts) {
      const response = await request.get(`/posts/${postId}`);
      responses.push(response);
    }
    
    expect(responses).to.have.length(3);
    responses.forEach((response, index) => {
      expect(response.status).to.equal(200);
      expect(response.body.id).to.equal(posts[index]);
    });
  });
});

// Practical Examples
describe("GET Request Variations", () => {
  it("should get all posts", async () => {
    const response = await request.get("/posts");
    
    expect(response.status).to.equal(200);
    expect(response.body).to.be.an('array');
    expect(response.body.length).to.be.greaterThan(0);
    
    // Check first post structure
    const firstPost = response.body[0];
    expect(firstPost).to.have.property('id');
    expect(firstPost).to.have.property('title');
  });

  it("should get posts with query parameters", async () => {
    const response = await request.get("/posts?userId=1");
    
    expect(response.status).to.equal(200);
    expect(response.body).to.be.an('array');
    
    // All posts should belong to user 1
    response.body.forEach(post => {
      expect(post.userId).to.equal(1);
    });
  });

  it("should handle non-existent resource", async () => {
    const response = await request.get("/posts/999999");
    
    expect(response.status).to.equal(404);
    expect(response.body).to.be.empty;
  });
});

// Error Handling Examples
describe("Error Handling", () => {
  it("should handle network errors gracefully", async () => {
    const invalidRequest = supertest("https://invalid-domain-12345.com");
    
    try {
      await invalidRequest.get("/posts/1");
      expect.fail("Should have thrown an error");
    } catch (error) {
      expect(error).to.be.an('error');
      expect(error.message).to.include('ENOTFOUND');
    }
  });

  it("should handle timeout scenarios", async () => {
    const slowRequest = supertest("https://httpbin.org");
    
    try {
      const response = await slowRequest.get("/delay/10").timeout(5000);
      expect.fail("Should have timed out");
    } catch (error) {
      expect(error).to.be.an('error');
      expect(error.message).to.include('timeout');
    }
  });
});

// Response Time Analysis
describe("Performance Analysis", () => {
  it("should measure response time", async () => {
    const startTime = Date.now();
    const response = await request.get("/posts/1");
    const endTime = Date.now();
    
    const responseTime = endTime - startTime;
    
    expect(response.status).to.equal(200);
    expect(responseTime).to.be.lessThan(5000); // Should respond within 5 seconds
    console.log(`Response time: ${responseTime}ms`);
  });

  it("should compare response times", async () => {
    const endpoints = ["/posts/1", "/posts/2", "/posts/3"];
    const results = [];
    
    for (const endpoint of endpoints) {
      const startTime = Date.now();
      const response = await request.get(endpoint);
      const endTime = Date.now();
      
      results.push({
        endpoint,
        responseTime: endTime - startTime,
        status: response.status
      });
    }
    
    expect(results).to.have.length(3);
    results.forEach(result => {
      expect(result.status).to.equal(200);
      expect(result.responseTime).to.be.lessThan(5000);
    });
    
    console.log("Response times comparison:", results);
  });
});

// Export functions for reuse
export { 
  makeSimpleGetRequest, 
  analyzeResponse
};

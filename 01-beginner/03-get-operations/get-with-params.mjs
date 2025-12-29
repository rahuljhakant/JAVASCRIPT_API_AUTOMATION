/**
 * PHASE 1: BEGINNER LEVEL
 * Module 3: GET Operations
 * Lesson 1: GET Requests with Query Parameters
 * 
 * Learning Objectives:
 * - Master GET requests with query parameters
 * - Understand filtering and searching
 * - Handle pagination parameters
 * - Work with multiple query parameters
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== GET REQUESTS WITH QUERY PARAMETERS ===");

// Set up the API client
const request = supertest("https://jsonplaceholder.typicode.com");

// GET request with single query parameter
async function getWithSingleParam() {
  console.log("Making GET request with userId parameter...");
  
  const response = await request.get("/posts").query({ userId: 1 });
  
  console.log("Response Status:", response.status);
  console.log("Number of posts:", response.body.length);
  
  return response;
}

// GET request with multiple query parameters
async function getWithMultipleParams() {
  console.log("Making GET request with multiple parameters...");
  
  const response = await request
    .get("/posts")
    .query({
      userId: 1,
      _limit: 5
    });
  
  console.log("Response Status:", response.status);
  console.log("Filtered posts:", response.body.length);
  
  return response;
}

// GET request with filtering
async function getWithFiltering() {
  console.log("Making GET request with filtering...");
  
  const response = await request
    .get("/posts")
    .query({
      userId: 1,
      _limit: 10,
      _sort: "id",
      _order: "desc"
    });
  
  return response;
}

// Exercises and Tests
describe("GET Requests with Query Parameters", () => {
  it("should make GET request with single query parameter", async () => {
    const response = await request.get("/posts").query({ userId: 1 });
    
    expect(response.status).to.equal(200);
    expect(response.body).to.be.an('array');
    
    // Verify all posts belong to user 1
    response.body.forEach(post => {
      expect(post.userId).to.equal(1);
    });
  });

  it("should make GET request with multiple query parameters", async () => {
    const response = await request
      .get("/posts")
      .query({
        userId: 1,
        _limit: 5
      });
    
    expect(response.status).to.equal(200);
    expect(response.body).to.be.an('array');
    expect(response.body.length).to.be.at.most(5);
    
    response.body.forEach(post => {
      expect(post.userId).to.equal(1);
    });
  });

  it("should filter posts by userId", async () => {
    const userId = 2;
    const response = await request.get("/posts").query({ userId });
    
    expect(response.status).to.equal(200);
    expect(response.body.length).to.be.greaterThan(0);
    
    response.body.forEach(post => {
      expect(post.userId).to.equal(userId);
    });
  });

  it("should limit results with _limit parameter", async () => {
    const limit = 3;
    const response = await request.get("/posts").query({ _limit: limit });
    
    expect(response.status).to.equal(200);
    expect(response.body.length).to.be.at.most(limit);
  });

  it("should handle invalid query parameters gracefully", async () => {
    const response = await request
      .get("/posts")
      .query({
        invalidParam: "value",
        anotherInvalid: 123
      });
    
    // API should still return results (ignoring invalid params)
    expect(response.status).to.equal(200);
    expect(response.body).to.be.an('array');
  });
});

// Advanced Query Parameter Examples
describe("Advanced Query Parameter Usage", () => {
  it("should combine multiple filters", async () => {
    const response = await request
      .get("/posts")
      .query({
        userId: 1,
        _limit: 10,
        _start: 0
      });
    
    expect(response.status).to.equal(200);
    expect(response.body.length).to.be.at.most(10);
  });

  it("should handle special characters in query parameters", async () => {
    const response = await request
      .get("/posts")
      .query({
        userId: 1,
        title: "qui"
      });
    
    expect(response.status).to.equal(200);
    expect(response.body).to.be.an('array');
  });

  it("should work with URL-encoded parameters", async () => {
    const response = await request
      .get("/posts")
      .query({
        userId: "1,2,3"
      });
    
    expect(response.status).to.equal(200);
  });
});

// Export functions for reuse
export { 
  getWithSingleParam, 
  getWithMultipleParams, 
  getWithFiltering 
};


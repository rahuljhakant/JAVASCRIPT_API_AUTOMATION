/**
 * PHASE 1: BEGINNER LEVEL
 * Module 2: First API Call
 * Lesson 3: Basic Assertions
 * 
 * Learning Objectives:
 * - Learn assertion fundamentals
 * - Understand different assertion types
 * - Validate response data
 * - Handle assertion failures
 */

import { expect, assert } from "chai";
import supertest from "supertest";

console.log("=== BASIC ASSERTIONS ===");

// Set up the API client
const request = supertest("https://jsonplaceholder.typicode.com");

// Assertion types demonstration
describe("Basic Assertions", () => {
  it("should use expect assertions for status codes", async () => {
    const response = await request.get("/posts/1");
    
    // Status code assertions
    expect(response.status).to.equal(200);
    expect(response.status).to.be.a('number');
    expect(response.status).to.be.above(199);
    expect(response.status).to.be.below(300);
  });

  it("should use expect assertions for response body", async () => {
    const response = await request.get("/posts/1");
    
    // Object existence
    expect(response.body).to.exist;
    expect(response.body).to.be.an('object');
    
    // Property existence
    expect(response.body).to.have.property('id');
    expect(response.body).to.have.property('title');
    expect(response.body).to.have.property('body');
    expect(response.body).to.have.property('userId');
    
    // Property values
    expect(response.body.id).to.equal(1);
    expect(response.body.userId).to.be.a('number');
    expect(response.body.title).to.be.a('string');
    expect(response.body.body).to.be.a('string');
  });

  it("should use expect assertions for arrays", async () => {
    const response = await request.get("/posts");
    
    // Array assertions
    expect(response.body).to.be.an('array');
    expect(response.body).to.have.length.above(0);
    expect(response.body.length).to.be.greaterThan(0);
    
    // Array element assertions
    if (response.body.length > 0) {
      expect(response.body[0]).to.be.an('object');
      expect(response.body[0]).to.have.property('id');
    }
  });

  it("should use assert for explicit checks", async () => {
    const response = await request.get("/posts/1");
    
    // Using assert
    assert.isObject(response.body, "Response body should be an object");
    assert.property(response.body, 'id', "Response should have id property");
    assert.isNumber(response.body.id, "ID should be a number");
    assert.isString(response.body.title, "Title should be a string");
  });

  it("should validate response headers", async () => {
    const response = await request.get("/posts/1");
    
    // Header assertions
    expect(response.headers).to.exist;
    expect(response.headers).to.be.an('object');
    expect(response.headers).to.have.property('content-type');
    expect(response.headers['content-type']).to.include('application/json');
  });

  it("should use deep equality checks", async () => {
    const response = await request.get("/posts/1");
    
    // Deep equality
    expect(response.body).to.deep.include({
      id: 1,
      userId: 1
    });
    
    // Partial object matching
    expect(response.body).to.include.keys(['id', 'title', 'body', 'userId']);
  });

  it("should validate string properties", async () => {
    const response = await request.get("/posts/1");
    
    // String assertions
    expect(response.body.title).to.be.a('string');
    expect(response.body.title).to.have.length.above(0);
    expect(response.body.title).to.not.be.empty;
    expect(response.body.body).to.be.a('string');
    expect(response.body.body.length).to.be.greaterThan(0);
  });

  it("should validate number properties", async () => {
    const response = await request.get("/posts/1");
    
    // Number assertions
    expect(response.body.id).to.be.a('number');
    expect(response.body.id).to.equal(1);
    expect(response.body.id).to.be.above(0);
    expect(response.body.userId).to.be.a('number');
    expect(response.body.userId).to.be.at.least(1);
  });

  it("should use negation in assertions", async () => {
    const response = await request.get("/posts/1");
    
    // Negation assertions
    expect(response.status).to.not.equal(404);
    expect(response.status).to.not.equal(500);
    expect(response.body).to.not.be.null;
    expect(response.body).to.not.be.undefined;
    expect(response.body.title).to.not.be.empty;
  });

  it("should validate response time", async () => {
    const startTime = Date.now();
    const response = await request.get("/posts/1");
    const endTime = Date.now();
    
    const responseTime = endTime - startTime;
    
    expect(response.status).to.equal(200);
    expect(responseTime).to.be.a('number');
    expect(responseTime).to.be.above(0);
    expect(responseTime).to.be.below(5000); // Should complete within 5 seconds
  });

  it("should handle multiple assertions in sequence", async () => {
    const response = await request.get("/posts/1");
    
    // Multiple assertions
    expect(response.status).to.equal(200);
    expect(response.body).to.be.an('object');
    expect(response.body.id).to.equal(1);
    expect(response.body.title).to.be.a('string');
    expect(response.body.body).to.be.a('string');
    expect(response.body.userId).to.be.a('number');
    expect(response.headers['content-type']).to.include('application/json');
  });
});

// Advanced Assertion Patterns
describe("Advanced Assertion Patterns", () => {
  it("should use chaining for complex assertions", async () => {
    const response = await request.get("/posts/1");
    
    // Chained assertions
    expect(response)
      .to.have.property('status', 200)
      .and.to.have.property('body')
      .and.to.have.property('headers');
    
    expect(response.body)
      .to.have.property('id')
      .and.to.be.a('number')
      .and.to.equal(1);
  });

  it("should validate nested object properties", async () => {
    const response = await request.get("/posts/1");
    
    // Nested property validation
    expect(response.body).to.have.nested.property('id');
    expect(response.body).to.have.nested.include({
      'id': 1
    });
  });

  it("should use custom assertion messages", async () => {
    const response = await request.get("/posts/1");
    
    // Custom messages
    expect(response.status, "API should return 200 OK").to.equal(200);
    expect(response.body.id, "Post ID should be 1").to.equal(1);
    expect(response.body.title, "Post should have a title").to.exist;
  });

  it("should validate response structure with schema-like checks", async () => {
    const response = await request.get("/posts/1");
    
    // Schema-like validation
    const requiredFields = ['id', 'title', 'body', 'userId'];
    requiredFields.forEach(field => {
      expect(response.body, `Response should have ${field} field`)
        .to.have.property(field);
    });
    
    // Type validation
    expect(response.body.id).to.be.a('number');
    expect(response.body.title).to.be.a('string');
    expect(response.body.body).to.be.a('string');
    expect(response.body.userId).to.be.a('number');
  });

  it("should compare multiple responses", async () => {
    const response1 = await request.get("/posts/1");
    const response2 = await request.get("/posts/2");
    
    // Compare responses
    expect(response1.status).to.equal(response2.status);
    expect(response1.body).to.have.property('id', 1);
    expect(response2.body).to.have.property('id', 2);
    expect(response1.body.userId).to.be.a('number');
    expect(response2.body.userId).to.be.a('number');
  });

  it("should validate array elements", async () => {
    const response = await request.get("/posts");
    
    // Array element validation
    expect(response.body).to.be.an('array');
    expect(response.body.length).to.be.greaterThan(0);
    
    // Validate first element
    if (response.body.length > 0) {
      const firstPost = response.body[0];
      expect(firstPost).to.have.property('id');
      expect(firstPost).to.have.property('title');
      expect(firstPost).to.have.property('body');
      expect(firstPost).to.have.property('userId');
    }
    
    // Validate all elements have required properties
    response.body.forEach((post, index) => {
      expect(post, `Post at index ${index} should have id`)
        .to.have.property('id');
      expect(post, `Post at index ${index} should have title`)
        .to.have.property('title');
    });
  });

  it("should handle conditional assertions", async () => {
    const response = await request.get("/posts/1");
    
    // Conditional assertions
    if (response.status === 200) {
      expect(response.body).to.exist;
      expect(response.body).to.have.property('id');
    } else {
      expect.fail("Expected status 200 but got " + response.status);
    }
    
    // Conditional based on data
    if (response.body.userId) {
      expect(response.body.userId).to.be.a('number');
      expect(response.body.userId).to.be.above(0);
    }
  });
});

// Error Assertion Patterns
describe("Error Assertion Patterns", () => {
  it("should assert error responses", async () => {
    const response = await request.get("/posts/999999");
    
    // Error response assertions
    expect(response.status).to.equal(404);
    expect(response.body).to.be.an('object');
  });

  it("should validate error message structure", async () => {
    try {
      const invalidRequest = supertest("https://invalid-domain-12345.com");
      await invalidRequest.get("/posts/1");
      expect.fail("Should have thrown an error");
    } catch (error) {
      // Error assertions
      expect(error).to.exist;
      expect(error).to.be.an('error');
      expect(error.message).to.be.a('string');
    }
  });

  it("should use expect.fail for explicit failures", async () => {
    const response = await request.get("/posts/1");
    
    if (response.status !== 200) {
      expect.fail(`Expected status 200 but got ${response.status}`);
    }
    
    if (!response.body || !response.body.id) {
      expect.fail("Response body should have id property");
    }
  });
});

// Assertion Utilities
class AssertionHelper {
  static validatePost(post, expectedId = null) {
    expect(post).to.be.an('object');
    expect(post).to.have.property('id');
    expect(post).to.have.property('title');
    expect(post).to.have.property('body');
    expect(post).to.have.property('userId');
    
    if (expectedId !== null) {
      expect(post.id).to.equal(expectedId);
    }
    
    expect(post.id).to.be.a('number');
    expect(post.title).to.be.a('string');
    expect(post.body).to.be.a('string');
    expect(post.userId).to.be.a('number');
  }
  
  static validateResponse(response, expectedStatus = 200) {
    expect(response).to.exist;
    expect(response.status).to.equal(expectedStatus);
    expect(response.body).to.exist;
    expect(response.headers).to.exist;
  }
  
  static validateArrayResponse(response, minLength = 0) {
    expect(response.body).to.be.an('array');
    expect(response.body.length).to.be.at.least(minLength);
  }
}

// Using assertion helpers
describe("Assertion Helpers", () => {
  it("should use helper for post validation", async () => {
    const response = await request.get("/posts/1");
    
    AssertionHelper.validateResponse(response);
    AssertionHelper.validatePost(response.body, 1);
  });

  it("should use helper for array validation", async () => {
    const response = await request.get("/posts");
    
    AssertionHelper.validateResponse(response);
    AssertionHelper.validateArrayResponse(response, 1);
    
    if (response.body.length > 0) {
      AssertionHelper.validatePost(response.body[0]);
    }
  });
});

export { 
  AssertionHelper 
};


/**
 * PHASE 1: BEGINNER LEVEL
 * Module 2: First API Call
 * Lesson 2: Handle Response
 * 
 * Learning Objectives:
 * - Understand response structure
 * - Extract and validate response data
 * - Handle different response formats
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== HANDLING API RESPONSES ===");

const request = supertest("https://jsonplaceholder.typicode.com");

// Understanding Response Structure
class ResponseHandler {
  constructor(response) {
    this.response = response;
    this.status = response.status;
    this.headers = response.headers;
    this.body = response.body;
    this.responseTime = response.responseTime;
  }
  
  // Extract specific data from response
  extractData(path = null) {
    if (!path) {
      return this.body;
    }
    
    // Handle dot notation like "data.users[0].name"
    return this.getNestedValue(this.body, path);
  }
  
  getNestedValue(obj, path) {
    return path.split(/[.\[\]]/).filter(Boolean).reduce((current, key) => {
      return current && current[key] !== undefined ? current[key] : null;
    }, obj);
  }
  
  // Validate response structure
  validateStructure(expectedStructure) {
    const validation = {
      isValid: true,
      errors: []
    };
    
    for (const [key, type] of Object.entries(expectedStructure)) {
      const value = this.getNestedValue(this.body, key);
      
      if (value === null || value === undefined) {
        validation.errors.push(`Missing field: ${key}`);
        validation.isValid = false;
      } else if (typeof value !== type) {
        validation.errors.push(`Field ${key} should be ${type}, got ${typeof value}`);
        validation.isValid = false;
      }
    }
    
    return validation;
  }
  
  // Check if response is successful
  isSuccessful() {
    return this.status >= 200 && this.status < 300;
  }
  
  // Get response metadata
  getMetadata() {
    return {
      status: this.status,
      contentType: this.headers['content-type'],
      contentLength: this.headers['content-length'],
      responseTime: this.responseTime,
      size: JSON.stringify(this.body).length
    };
  }
}

// Response Data Extraction Examples
async function demonstrateResponseHandling() {
  console.log("=== RESPONSE HANDLING DEMONSTRATION ===");
  
  // Get a single post
  const postResponse = await request.get("/posts/1");
  const postHandler = new ResponseHandler(postResponse);
  
  console.log("Post Response Metadata:", postHandler.getMetadata());
  console.log("Is Successful:", postHandler.isSuccessful());
  
  // Extract specific data
  const postId = postHandler.extractData("id");
  const postTitle = postHandler.extractData("title");
  const postBody = postHandler.extractData("body");
  
  console.log("Extracted Data:", { postId, postTitle, postBody });
  
  // Validate structure
  const expectedStructure = {
    "id": "number",
    "title": "string",
    "body": "string",
    "userId": "number"
  };
  
  const validation = postHandler.validateStructure(expectedStructure);
  console.log("Structure Validation:", validation);
  
  return postHandler;
}

// Handle Different Response Formats
async function handleDifferentFormats() {
  console.log("=== HANDLING DIFFERENT FORMATS ===");
  
  const formats = [
    { endpoint: "/posts/1", description: "Single Object" },
    { endpoint: "/posts", description: "Array of Objects" },
    { endpoint: "/posts?userId=1", description: "Filtered Array" }
  ];
  
  const results = [];
  
  for (const format of formats) {
    const response = await request.get(format.endpoint);
    const handler = new ResponseHandler(response);
    
    const result = {
      endpoint: format.endpoint,
      description: format.description,
      dataType: Array.isArray(handler.body) ? 'array' : 'object',
      itemCount: Array.isArray(handler.body) ? handler.body.length : 1,
      metadata: handler.getMetadata()
    };
    
    results.push(result);
  }
  
  return results;
}

// Error Response Handling
async function handleErrorResponses() {
  console.log("=== ERROR RESPONSE HANDLING ===");
  
  const errorScenarios = [
    { endpoint: "/posts/999999", expectedStatus: 404, description: "Not Found" },
    { endpoint: "/invalid-endpoint", expectedStatus: 404, description: "Invalid Endpoint" }
  ];
  
  const errorResults = [];
  
  for (const scenario of errorScenarios) {
    try {
      const response = await request.get(scenario.endpoint);
      const handler = new ResponseHandler(response);
      
      errorResults.push({
        scenario: scenario.description,
        actualStatus: handler.status,
        expectedStatus: scenario.expectedStatus,
        isExpected: handler.status === scenario.expectedStatus,
        body: handler.body
      });
    } catch (error) {
      errorResults.push({
        scenario: scenario.description,
        error: error.message,
        type: 'exception'
      });
    }
  }
  
  return errorResults;
}

// Exercises and Tests
describe("Response Handling", () => {
  it("should handle successful response", async () => {
    const response = await request.get("/posts/1");
    const handler = new ResponseHandler(response);
    
    expect(handler.isSuccessful()).to.be.true;
    expect(handler.status).to.equal(200);
    expect(handler.body).to.be.an('object');
  });

  it("should extract specific data from response", async () => {
    const response = await request.get("/posts/1");
    const handler = new ResponseHandler(response);
    
    const id = handler.extractData("id");
    const title = handler.extractData("title");
    
    expect(id).to.equal(1);
    expect(title).to.be.a('string');
    expect(title.length).to.be.greaterThan(0);
  });

  it("should validate response structure", async () => {
    const response = await request.get("/posts/1");
    const handler = new ResponseHandler(response);
    
    const expectedStructure = {
      "id": "number",
      "title": "string",
      "body": "string",
      "userId": "number"
    };
    
    const validation = handler.validateStructure(expectedStructure);
    expect(validation.isValid).to.be.true;
    expect(validation.errors).to.have.length(0);
  });

  it("should handle array responses", async () => {
    const response = await request.get("/posts");
    const handler = new ResponseHandler(response);
    
    expect(handler.isSuccessful()).to.be.true;
    expect(Array.isArray(handler.body)).to.be.true;
    expect(handler.body.length).to.be.greaterThan(0);
    
    // Validate first item structure
    const firstPost = handler.body[0];
    expect(firstPost).to.have.property('id');
    expect(firstPost).to.have.property('title');
  });

  it("should handle nested data extraction", async () => {
    const response = await request.get("/posts/1");
    const handler = new ResponseHandler(response);
    
    // Test nested extraction (though this API doesn't have deep nesting)
    const userId = handler.extractData("userId");
    expect(userId).to.be.a('number');
  });

  it("should provide response metadata", async () => {
    const response = await request.get("/posts/1");
    const handler = new ResponseHandler(response);
    
    const metadata = handler.getMetadata();
    
    expect(metadata.status).to.equal(200);
    expect(metadata.contentType).to.include('application/json');
    expect(metadata.responseTime).to.be.a('number');
    expect(metadata.size).to.be.greaterThan(0);
  });
});

// Error Handling Tests
describe("Error Response Handling", () => {
  it("should handle 404 responses", async () => {
    const response = await request.get("/posts/999999");
    const handler = new ResponseHandler(response);
    
    expect(handler.isSuccessful()).to.be.false;
    expect(handler.status).to.equal(404);
  });

  it("should validate error response structure", async () => {
    const response = await request.get("/posts/999999");
    const handler = new ResponseHandler(response);
    
    // Empty response for 404
    expect(handler.body).to.be.empty;
  });
});

// Performance and Response Time Tests
describe("Response Performance", () => {
  it("should measure response time", async () => {
    const startTime = Date.now();
    const response = await request.get("/posts/1");
    const endTime = Date.now();
    
    const handler = new ResponseHandler(response);
    const metadata = handler.getMetadata();
    
    expect(metadata.responseTime).to.be.a('number');
    expect(endTime - startTime).to.be.lessThan(5000);
  });

  it("should handle multiple concurrent requests", async () => {
    const requests = [
      request.get("/posts/1"),
      request.get("/posts/2"),
      request.get("/posts/3")
    ];
    
    const responses = await Promise.all(requests);
    const handlers = responses.map(response => new ResponseHandler(response));
    
    expect(handlers).to.have.length(3);
    handlers.forEach(handler => {
      expect(handler.isSuccessful()).to.be.true;
    });
  });
});

// Run demonstrations
async function runDemonstrations() {
  try {
    await demonstrateResponseHandling();
    const formats = await handleDifferentFormats();
    console.log("Different Formats:", formats);
    
    const errors = await handleErrorResponses();
    console.log("Error Scenarios:", errors);
  } catch (error) {
    console.error("Demonstration error:", error);
  }
}

export { 
  ResponseHandler, 
  demonstrateResponseHandling, 
  handleDifferentFormats, 
  handleErrorResponses,
  runDemonstrations 
};

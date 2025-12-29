/**
 * PHASE 1: BEGINNER LEVEL
 * Module 4: Basic Error Handling
 * Lesson 2: HTTP Status Code Handling
 * 
 * Learning Objectives:
 * - Understand HTTP status codes
 * - Handle different status code categories
 * - Validate expected status codes
 * - Create status code validators
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== HTTP STATUS CODE HANDLING ===");

// Set up the API client
const request = supertest("https://jsonplaceholder.typicode.com");

// Status code categories
const STATUS_CODES = {
  SUCCESS: [200, 201, 202, 204],
  CLIENT_ERROR: [400, 401, 403, 404, 422, 429],
  SERVER_ERROR: [500, 502, 503, 504],
  REDIRECT: [301, 302, 307, 308]
};

// Validate status code
function validateStatusCode(statusCode, expectedCategory) {
  const categories = {
    success: STATUS_CODES.SUCCESS,
    clientError: STATUS_CODES.CLIENT_ERROR,
    serverError: STATUS_CODES.SERVER_ERROR,
    redirect: STATUS_CODES.REDIRECT
  };
  
  const expectedCodes = categories[expectedCategory];
  return expectedCodes ? expectedCodes.includes(statusCode) : false;
}

// Handle different status codes
async function handleStatusCode(statusCode) {
  const handlers = {
    200: () => ({ message: "OK - Request successful" }),
    201: () => ({ message: "Created - Resource created successfully" }),
    204: () => ({ message: "No Content - Request successful, no content to return" }),
    400: () => ({ error: "Bad Request - Invalid request parameters" }),
    401: () => ({ error: "Unauthorized - Authentication required" }),
    403: () => ({ error: "Forbidden - Access denied" }),
    404: () => ({ error: "Not Found - Resource not found" }),
    422: () => ({ error: "Unprocessable Entity - Validation failed" }),
    429: () => ({ error: "Too Many Requests - Rate limit exceeded" }),
    500: () => ({ error: "Internal Server Error - Server error occurred" }),
    502: () => ({ error: "Bad Gateway - Gateway error" }),
    503: () => ({ error: "Service Unavailable - Service temporarily unavailable" })
  };
  
  const handler = handlers[statusCode];
  return handler ? handler() : { message: `Status code: ${statusCode}` };
}

// Test different status codes
async function testStatusCodes() {
  const testCases = [
    { endpoint: "/posts/1", expectedStatus: 200 },
    { endpoint: "/posts/999999", expectedStatus: 404 },
    { endpoint: "/posts", method: "POST", expectedStatus: 201 }
  ];
  
  const results = [];
  
  for (const testCase of testCases) {
    try {
      let response;
      
      if (testCase.method === "POST") {
        response = await request
          .post(testCase.endpoint)
          .send({ title: "Test", body: "Test body", userId: 1 });
      } else {
        response = await request.get(testCase.endpoint);
      }
      
      const handler = await handleStatusCode(response.status);
      results.push({
        endpoint: testCase.endpoint,
        status: response.status,
        expected: testCase.expectedStatus,
        match: response.status === testCase.expectedStatus,
        handler
      });
    } catch (error) {
      results.push({
        endpoint: testCase.endpoint,
        error: error.message
      });
    }
  }
  
  return results;
}

// Exercises and Tests
describe("HTTP Status Code Handling", () => {
  it("should validate success status codes", () => {
    expect(validateStatusCode(200, 'success')).to.be.true;
    expect(validateStatusCode(201, 'success')).to.be.true;
    expect(validateStatusCode(204, 'success')).to.be.true;
    expect(validateStatusCode(404, 'success')).to.be.false;
  });

  it("should validate client error status codes", () => {
    expect(validateStatusCode(404, 'clientError')).to.be.true;
    expect(validateStatusCode(400, 'clientError')).to.be.true;
    expect(validateStatusCode(200, 'clientError')).to.be.false;
  });

  it("should validate server error status codes", () => {
    expect(validateStatusCode(500, 'serverError')).to.be.true;
    expect(validateStatusCode(503, 'serverError')).to.be.true;
    expect(validateStatusCode(404, 'serverError')).to.be.false;
  });

  it("should handle status code 200", async () => {
    const response = await request.get("/posts/1");
    const handler = await handleStatusCode(response.status);
    
    expect(response.status).to.equal(200);
    expect(handler.message).to.include("OK");
  });

  it("should handle status code 404", async () => {
    const response = await request.get("/posts/999999");
    const handler = await handleStatusCode(response.status);
    
    expect(response.status).to.equal(404);
    expect(handler.error).to.include("Not Found");
  });

  it("should test multiple status codes", async () => {
    const results = await testStatusCodes();
    
    expect(results).to.be.an('array');
    expect(results.length).to.be.greaterThan(0);
    
    results.forEach(result => {
      expect(result).to.have.property('status');
      expect(result).to.have.property('handler');
    });
  });
});

// Status Code Validator Class
class StatusCodeValidator {
  static validate(response, expectedStatus) {
    if (Array.isArray(expectedStatus)) {
      return expectedStatus.includes(response.status);
    }
    return response.status === expectedStatus;
  }
  
  static assertSuccess(response) {
    expect(response.status).to.be.oneOf(STATUS_CODES.SUCCESS);
  }
  
  static assertClientError(response) {
    expect(response.status).to.be.oneOf(STATUS_CODES.CLIENT_ERROR);
  }
  
  static assertServerError(response) {
    expect(response.status).to.be.oneOf(STATUS_CODES.SERVER_ERROR);
  }
  
  static getCategory(statusCode) {
    if (STATUS_CODES.SUCCESS.includes(statusCode)) return 'success';
    if (STATUS_CODES.CLIENT_ERROR.includes(statusCode)) return 'clientError';
    if (STATUS_CODES.SERVER_ERROR.includes(statusCode)) return 'serverError';
    if (STATUS_CODES.REDIRECT.includes(statusCode)) return 'redirect';
    return 'unknown';
  }
}

// Advanced Status Code Examples
describe("Advanced Status Code Handling", () => {
  it("should use StatusCodeValidator", async () => {
    const response = await request.get("/posts/1");
    
    StatusCodeValidator.assertSuccess(response);
    expect(StatusCodeValidator.getCategory(response.status)).to.equal('success');
  });

  it("should validate against multiple expected statuses", async () => {
    const response = await request.get("/posts/1");
    
    const isValid = StatusCodeValidator.validate(response, [200, 201]);
    expect(isValid).to.be.true;
  });

  it("should identify status code category", () => {
    expect(StatusCodeValidator.getCategory(200)).to.equal('success');
    expect(StatusCodeValidator.getCategory(404)).to.equal('clientError');
    expect(StatusCodeValidator.getCategory(500)).to.equal('serverError');
  });
});

// Export functions and classes
export { 
  validateStatusCode, 
  handleStatusCode, 
  testStatusCodes,
  StatusCodeValidator,
  STATUS_CODES 
};


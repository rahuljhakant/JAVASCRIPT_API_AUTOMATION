/**
 * PHASE 1: BEGINNER LEVEL
 * Module 1: HTTP Basics
 * Lesson 3: HTTP Status Codes
 * 
 * Learning Objectives:
 * - Understand HTTP status code categories
 * - Learn common status codes and their meanings
 * - Practice status code validation in tests
 */

import { expect } from "chai";

console.log("=== HTTP STATUS CODES ===");

// HTTP Status Code Categories
const statusCodeCategories = {
  informational: {
    range: "100-199",
    description: "Provisional response, request continuing",
    examples: [100, 101, 102]
  },
  success: {
    range: "200-299",
    description: "Request was successful",
    examples: [200, 201, 202, 204]
  },
  redirection: {
    range: "300-399",
    description: "Further action needed to complete request",
    examples: [301, 302, 304, 307]
  },
  client_error: {
    range: "400-499",
    description: "Client made an error in the request",
    examples: [400, 401, 403, 404, 422, 429]
  },
  server_error: {
    range: "500-599",
    description: "Server encountered an error",
    examples: [500, 502, 503, 504]
  }
};

console.log("Status Code Categories:", statusCodeCategories);

// Detailed Status Codes
const detailedStatusCodes = {
  // Success Codes
  200: {
    name: "OK",
    description: "Request successful",
    common_use: "GET requests, successful updates",
    test_expectation: "expect(response.status).to.equal(200)"
  },
  
  201: {
    name: "Created",
    description: "Resource created successfully",
    common_use: "POST requests creating new resources",
    test_expectation: "expect(response.status).to.equal(201)"
  },
  
  202: {
    name: "Accepted",
    description: "Request accepted for processing",
    common_use: "Async operations, batch processing",
    test_expectation: "expect(response.status).to.equal(202)"
  },
  
  204: {
    name: "No Content",
    description: "Successful request with no response body",
    common_use: "DELETE requests, successful updates",
    test_expectation: "expect(response.status).to.equal(204)"
  },
  
  // Client Error Codes
  400: {
    name: "Bad Request",
    description: "Invalid request syntax or parameters",
    common_use: "Missing required fields, invalid data format",
    test_expectation: "expect(response.status).to.equal(400)"
  },
  
  401: {
    name: "Unauthorized",
    description: "Authentication required or failed",
    common_use: "Missing or invalid authentication token",
    test_expectation: "expect(response.status).to.equal(401)"
  },
  
  403: {
    name: "Forbidden",
    description: "Server understood but refuses to authorize",
    common_use: "Insufficient permissions, access denied",
    test_expectation: "expect(response.status).to.equal(403)"
  },
  
  404: {
    name: "Not Found",
    description: "Requested resource not found",
    common_use: "Invalid URL, deleted resource",
    test_expectation: "expect(response.status).to.equal(404)"
  },
  
  422: {
    name: "Unprocessable Entity",
    description: "Request well-formed but contains semantic errors",
    common_use: "Validation errors, business logic violations",
    test_expectation: "expect(response.status).to.equal(422)"
  },
  
  429: {
    name: "Too Many Requests",
    description: "Rate limit exceeded",
    common_use: "API rate limiting, too many requests",
    test_expectation: "expect(response.status).to.equal(429)"
  },
  
  // Server Error Codes
  500: {
    name: "Internal Server Error",
    description: "Unexpected server error",
    common_use: "Application crashes, database errors",
    test_expectation: "expect(response.status).to.equal(500)"
  },
  
  502: {
    name: "Bad Gateway",
    description: "Invalid response from upstream server",
    common_use: "Proxy server issues, service unavailable",
    test_expectation: "expect(response.status).to.equal(502)"
  },
  
  503: {
    name: "Service Unavailable",
    description: "Server temporarily unavailable",
    common_use: "Maintenance, overloaded server",
    test_expectation: "expect(response.status).to.equal(503)"
  },
  
  504: {
    name: "Gateway Timeout",
    description: "Upstream server timeout",
    common_use: "Slow database queries, external service timeout",
    test_expectation: "expect(response.status).to.equal(504)"
  }
};

console.log("Detailed Status Codes:", detailedStatusCodes);

// Status Code Helper Functions
class StatusCodeHelper {
  static isSuccess(statusCode) {
    return statusCode >= 200 && statusCode < 300;
  }
  
  static isClientError(statusCode) {
    return statusCode >= 400 && statusCode < 500;
  }
  
  static isServerError(statusCode) {
    return statusCode >= 500 && statusCode < 600;
  }
  
  static isError(statusCode) {
    return this.isClientError(statusCode) || this.isServerError(statusCode);
  }
  
  static getCategory(statusCode) {
    if (statusCode >= 100 && statusCode < 200) return 'informational';
    if (statusCode >= 200 && statusCode < 300) return 'success';
    if (statusCode >= 300 && statusCode < 400) return 'redirection';
    if (statusCode >= 400 && statusCode < 500) return 'client_error';
    if (statusCode >= 500 && statusCode < 600) return 'server_error';
    return 'unknown';
  }
  
  static getExpectedStatusCodes(method, operation) {
    const expectations = {
      'GET': [200, 404],
      'POST': [201, 400, 422],
      'PUT': [200, 201, 400, 404, 422],
      'PATCH': [200, 400, 404, 422],
      'DELETE': [200, 204, 404]
    };
    
    return expectations[method] || [];
  }
}

console.log("StatusCodeHelper created");

// Exercises and Tests
describe("HTTP Status Codes", () => {
  it("should categorize status codes correctly", () => {
    expect(StatusCodeHelper.getCategory(200)).to.equal('success');
    expect(StatusCodeHelper.getCategory(404)).to.equal('client_error');
    expect(StatusCodeHelper.getCategory(500)).to.equal('server_error');
  });

  it("should identify success codes", () => {
    expect(StatusCodeHelper.isSuccess(200)).to.be.true;
    expect(StatusCodeHelper.isSuccess(201)).to.be.true;
    expect(StatusCodeHelper.isSuccess(404)).to.be.false;
  });

  it("should identify client error codes", () => {
    expect(StatusCodeHelper.isClientError(400)).to.be.true;
    expect(StatusCodeHelper.isClientError(404)).to.be.true;
    expect(StatusCodeHelper.isClientError(200)).to.be.false;
  });

  it("should identify server error codes", () => {
    expect(StatusCodeHelper.isServerError(500)).to.be.true;
    expect(StatusCodeHelper.isServerError(503)).to.be.true;
    expect(StatusCodeHelper.isServerError(404)).to.be.false;
  });

  it("should get expected status codes for HTTP methods", () => {
    expect(StatusCodeHelper.getExpectedStatusCodes('GET')).to.include(200);
    expect(StatusCodeHelper.getExpectedStatusCodes('POST')).to.include(201);
    expect(StatusCodeHelper.getExpectedStatusCodes('PUT')).to.include(200);
    expect(StatusCodeHelper.getExpectedStatusCodes('DELETE')).to.include(204);
  });

  it("should understand common success codes", () => {
    expect(detailedStatusCodes[200].name).to.equal("OK");
    expect(detailedStatusCodes[201].name).to.equal("Created");
    expect(detailedStatusCodes[204].name).to.equal("No Content");
  });

  it("should understand common client error codes", () => {
    expect(detailedStatusCodes[400].name).to.equal("Bad Request");
    expect(detailedStatusCodes[401].name).to.equal("Unauthorized");
    expect(detailedStatusCodes[404].name).to.equal("Not Found");
  });

  it("should understand common server error codes", () => {
    expect(detailedStatusCodes[500].name).to.equal("Internal Server Error");
    expect(detailedStatusCodes[503].name).to.equal("Service Unavailable");
  });
});

// Practical Example: Status Code Validation
function validateResponseStatus(response, expectedStatus) {
  const actualStatus = response.status;
  const isSuccess = StatusCodeHelper.isSuccess(actualStatus);
  
  return {
    actualStatus,
    expectedStatus,
    isSuccess,
    category: StatusCodeHelper.getCategory(actualStatus),
    isValid: actualStatus === expectedStatus
  };
}

describe("Status Code Validation", () => {
  it("should validate successful response", () => {
    const mockResponse = { status: 200 };
    const result = validateResponseStatus(mockResponse, 200);
    
    expect(result.actualStatus).to.equal(200);
    expect(result.isSuccess).to.be.true;
    expect(result.isValid).to.be.true;
    expect(result.category).to.equal('success');
  });

  it("should validate error response", () => {
    const mockResponse = { status: 404 };
    const result = validateResponseStatus(mockResponse, 404);
    
    expect(result.actualStatus).to.equal(404);
    expect(result.isSuccess).to.be.false;
    expect(result.isValid).to.be.true;
    expect(result.category).to.equal('client_error');
  });
});

export { 
  statusCodeCategories, 
  detailedStatusCodes, 
  StatusCodeHelper, 
  validateResponseStatus 
};

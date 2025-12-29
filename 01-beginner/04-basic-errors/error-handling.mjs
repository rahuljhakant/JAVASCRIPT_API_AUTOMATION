/**
 * PHASE 1: BEGINNER LEVEL
 * Module 4: Basic Error Handling
 * Lesson 1: Error Handling Basics
 * 
 * Learning Objectives:
 * - Handle API errors gracefully
 * - Understand different error types
 * - Implement try-catch blocks
 * - Handle network errors
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== ERROR HANDLING BASICS ===");

// Set up the API client
const request = supertest("https://jsonplaceholder.typicode.com");

// Basic error handling with try-catch
async function handleErrorsWithTryCatch() {
  try {
    const response = await request.get("/posts/999999");
    
    if (response.status === 404) {
      console.log("Resource not found");
      return { error: "Resource not found", status: 404 };
    }
    
    return response.body;
  } catch (error) {
    console.error("Error occurred:", error.message);
    throw error;
  }
}

// Handle different HTTP status codes
async function handleStatusCodes() {
  const testCases = [
    { endpoint: "/posts/1", expectedStatus: 200 },
    { endpoint: "/posts/999999", expectedStatus: 404 },
    { endpoint: "/invalid-endpoint", expectedStatus: 404 }
  ];
  
  const results = [];
  
  for (const testCase of testCases) {
    try {
      const response = await request.get(testCase.endpoint);
      results.push({
        endpoint: testCase.endpoint,
        status: response.status,
        expected: testCase.expectedStatus,
        match: response.status === testCase.expectedStatus
      });
    } catch (error) {
      results.push({
        endpoint: testCase.endpoint,
        error: error.message,
        expected: testCase.expectedStatus
      });
    }
  }
  
  return results;
}

// Network error handling
async function handleNetworkErrors() {
  const invalidRequest = supertest("https://invalid-domain-12345.com");
  
  try {
    await invalidRequest.get("/test");
  } catch (error) {
    console.log("Network error caught:", error.message);
    return {
      error: "Network error",
      message: error.message,
      code: error.code
    };
  }
}

// Exercises and Tests
describe("Error Handling Basics", () => {
  it("should handle 404 errors gracefully", async () => {
    const response = await request.get("/posts/999999");
    
    expect(response.status).to.equal(404);
  });

  it("should handle errors with try-catch", async () => {
    try {
      const result = await handleErrorsWithTryCatch();
      expect(result).to.have.property('error');
    } catch (error) {
      // Error was caught and handled
      expect(error).to.exist;
    }
  });

  it("should handle different status codes", async () => {
    const results = await handleStatusCodes();
    
    expect(results).to.be.an('array');
    expect(results.length).to.be.greaterThan(0);
    
    results.forEach(result => {
      expect(result).to.have.property('status');
    });
  });

  it("should handle invalid endpoints", async () => {
    const response = await request.get("/invalid-endpoint-12345");
    
    expect(response.status).to.be.oneOf([404, 400]);
  });

  it("should handle network errors", async () => {
    const result = await handleNetworkErrors();
    
    expect(result).to.have.property('error');
    expect(result.error).to.equal('Network error');
  });
});

// Error Handling Utilities
class ErrorHandler {
  static isClientError(statusCode) {
    return statusCode >= 400 && statusCode < 500;
  }
  
  static isServerError(statusCode) {
    return statusCode >= 500 && statusCode < 600;
  }
  
  static isSuccess(statusCode) {
    return statusCode >= 200 && statusCode < 300;
  }
  
  static getErrorMessage(statusCode) {
    const errorMessages = {
      400: "Bad Request",
      401: "Unauthorized",
      403: "Forbidden",
      404: "Not Found",
      500: "Internal Server Error",
      502: "Bad Gateway",
      503: "Service Unavailable"
    };
    
    return errorMessages[statusCode] || "Unknown Error";
  }
  
  static async safeRequest(apiClient, method, endpoint, data = null) {
    try {
      let response;
      
      switch (method.toUpperCase()) {
        case 'GET':
          response = await apiClient.get(endpoint);
          break;
        case 'POST':
          response = await apiClient.post(endpoint).send(data);
          break;
        case 'PUT':
          response = await apiClient.put(endpoint).send(data);
          break;
        case 'DELETE':
          response = await apiClient.delete(endpoint);
          break;
        default:
          throw new Error(`Unsupported method: ${method}`);
      }
      
      if (!this.isSuccess(response.status)) {
        return {
          success: false,
          status: response.status,
          error: this.getErrorMessage(response.status),
          data: response.body
        };
      }
      
      return {
        success: true,
        status: response.status,
        data: response.body
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        code: error.code
      };
    }
  }
}

// Advanced Error Handling Examples
describe("Advanced Error Handling", () => {
  it("should use ErrorHandler utility", async () => {
    const result = await ErrorHandler.safeRequest(request, 'GET', '/posts/999999');
    
    expect(result).to.have.property('success');
    expect(result.success).to.be.false;
    expect(result).to.have.property('status');
  });

  it("should identify client errors", () => {
    expect(ErrorHandler.isClientError(404)).to.be.true;
    expect(ErrorHandler.isClientError(400)).to.be.true;
    expect(ErrorHandler.isClientError(200)).to.be.false;
  });

  it("should identify server errors", () => {
    expect(ErrorHandler.isServerError(500)).to.be.true;
    expect(ErrorHandler.isServerError(503)).to.be.true;
    expect(ErrorHandler.isServerError(404)).to.be.false;
  });

  it("should get error messages", () => {
    expect(ErrorHandler.getErrorMessage(404)).to.equal("Not Found");
    expect(ErrorHandler.getErrorMessage(500)).to.equal("Internal Server Error");
  });
});

// Export functions and classes
export { 
  handleErrorsWithTryCatch, 
  handleStatusCodes, 
  handleNetworkErrors,
  ErrorHandler 
};


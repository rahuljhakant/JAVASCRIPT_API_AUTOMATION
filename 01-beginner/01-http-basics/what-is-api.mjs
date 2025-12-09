/**
 * PHASE 1: BEGINNER LEVEL
 * Module 1: HTTP Basics
 * Lesson 1: What is an API?
 * 
 * Learning Objectives:
 * - Understand what an API is
 * - Learn the basics of REST APIs
 * - Understand HTTP protocol fundamentals
 */

import { expect } from "chai";

// What is an API?
// API = Application Programming Interface
// It's a way for different software applications to communicate with each other

console.log("=== API FUNDAMENTALS ===");

// Example: Understanding API concepts
const apiConcept = {
  definition: "Application Programming Interface",
  purpose: "Enable communication between different software systems",
  analogy: "Like a waiter in a restaurant - takes your order and brings food from kitchen",
  benefits: [
    "Modularity - separate concerns",
    "Reusability - use same API for different apps",
    "Scalability - scale components independently"
  ]
};

console.log("API Concept:", apiConcept);

// REST API Basics
const restApiBasics = {
  what_is_rest: "Representational State Transfer - architectural style for web services",
  principles: [
    "Stateless - each request contains all information needed",
    "Client-Server - separation of concerns",
    "Cacheable - responses can be cached",
    "Uniform Interface - consistent way to interact"
  ],
  http_methods: {
    GET: "Retrieve data",
    POST: "Create new data",
    PUT: "Update existing data",
    DELETE: "Remove data"
  }
};

console.log("REST API Basics:", restApiBasics);

// HTTP Status Codes
const httpStatusCodes = {
  informational: "1xx - Request received, continuing process",
  success: "2xx - Request successful",
  redirection: "3xx - Further action needed",
  client_error: "4xx - Client made an error",
  server_error: "5xx - Server encountered an error"
};

console.log("HTTP Status Codes:", httpStatusCodes);

// Exercise: Understanding API concepts
describe("API Fundamentals", () => {
  it("should understand what an API is", () => {
    expect(apiConcept.definition).to.equal("Application Programming Interface");
  });

  it("should know REST principles", () => {
    expect(restApiBasics.principles).to.include("Stateless");
    expect(restApiBasics.principles).to.include("Client-Server");
  });

  it("should understand HTTP methods", () => {
    expect(restApiBasics.http_methods.GET).to.equal("Retrieve data");
    expect(restApiBasics.http_methods.POST).to.equal("Create new data");
  });

  it("should know status code categories", () => {
    expect(httpStatusCodes.success).to.include("2xx");
    expect(httpStatusCodes.client_error).to.include("4xx");
  });
});

export { apiConcept, restApiBasics, httpStatusCodes };

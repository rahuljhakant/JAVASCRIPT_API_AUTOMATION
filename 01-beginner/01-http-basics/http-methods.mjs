/**
 * PHASE 1: BEGINNER LEVEL
 * Module 1: HTTP Basics
 * Lesson 2: HTTP Methods
 * 
 * Learning Objectives:
 * - Understand different HTTP methods
 * - Learn when to use each method
 * - Practice with HTTP method examples
 */

import { expect } from "chai";

console.log("=== HTTP METHODS DEEP DIVE ===");

// HTTP Methods with detailed explanations
const httpMethods = {
  GET: {
    purpose: "Retrieve data from server",
    characteristics: ["Safe", "Idempotent", "Cacheable"],
    use_cases: ["Fetch user data", "Get list of items", "Retrieve configuration"],
    example_url: "/api/users/123",
    body_allowed: false,
    status_codes: [200, 404, 500]
  },
  
  POST: {
    purpose: "Create new resource on server",
    characteristics: ["Not Safe", "Not Idempotent", "Not Cacheable"],
    use_cases: ["Create new user", "Submit form data", "Upload file"],
    example_url: "/api/users",
    body_allowed: true,
    status_codes: [201, 400, 409, 500]
  },
  
  PUT: {
    purpose: "Update entire resource or create if not exists",
    characteristics: ["Not Safe", "Idempotent", "Not Cacheable"],
    use_cases: ["Update user profile", "Replace entire document"],
    example_url: "/api/users/123",
    body_allowed: true,
    status_codes: [200, 201, 400, 404, 500]
  },
  
  PATCH: {
    purpose: "Partially update a resource",
    characteristics: ["Not Safe", "Not Idempotent", "Not Cacheable"],
    use_cases: ["Update specific fields", "Modify user status"],
    example_url: "/api/users/123",
    body_allowed: true,
    status_codes: [200, 400, 404, 500]
  },
  
  DELETE: {
    purpose: "Remove resource from server",
    characteristics: ["Not Safe", "Idempotent", "Not Cacheable"],
    use_cases: ["Delete user account", "Remove item from cart"],
    example_url: "/api/users/123",
    body_allowed: true,
    status_codes: [200, 204, 404, 500]
  },
  
  HEAD: {
    purpose: "Get response headers without body",
    characteristics: ["Safe", "Idempotent", "Cacheable"],
    use_cases: ["Check if resource exists", "Get metadata"],
    example_url: "/api/users/123",
    body_allowed: false,
    status_codes: [200, 404, 500]
  },
  
  OPTIONS: {
    purpose: "Get allowed methods for a resource",
    characteristics: ["Safe", "Idempotent", "Cacheable"],
    use_cases: ["CORS preflight", "API discovery"],
    example_url: "/api/users",
    body_allowed: false,
    status_codes: [200, 204, 500]
  }
};

console.log("HTTP Methods:", httpMethods);

// Method Safety and Idempotency
const methodCharacteristics = {
  safe_methods: ["GET", "HEAD", "OPTIONS"],
  idempotent_methods: ["GET", "HEAD", "PUT", "DELETE", "OPTIONS"],
  cacheable_methods: ["GET", "HEAD"],
  
  safe_explanation: "Safe methods don't cause side effects on server",
  idempotent_explanation: "Idempotent methods produce same result when called multiple times",
  cacheable_explanation: "Cacheable methods can be stored and reused"
};

console.log("Method Characteristics:", methodCharacteristics);

// Common HTTP Headers
const commonHeaders = {
  request_headers: {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Authorization": "Bearer token123",
    "User-Agent": "MyApp/1.0",
    "Accept-Language": "en-US,en;q=0.9"
  },
  response_headers: {
    "Content-Type": "application/json",
    "Content-Length": "1024",
    "Cache-Control": "max-age=3600",
    "ETag": "\"abc123\"",
    "Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT"
  }
};

console.log("Common Headers:", commonHeaders);

// Exercises and Tests
describe("HTTP Methods", () => {
  it("should understand GET method characteristics", () => {
    expect(httpMethods.GET.characteristics).to.include("Safe");
    expect(httpMethods.GET.characteristics).to.include("Idempotent");
    expect(httpMethods.GET.body_allowed).to.be.false;
  });

  it("should understand POST method characteristics", () => {
    expect(httpMethods.POST.characteristics).to.include("Not Safe");
    expect(httpMethods.POST.characteristics).to.include("Not Idempotent");
    expect(httpMethods.POST.body_allowed).to.be.true;
  });

  it("should know safe methods", () => {
    expect(methodCharacteristics.safe_methods).to.include("GET");
    expect(methodCharacteristics.safe_methods).to.include("HEAD");
    expect(methodCharacteristics.safe_methods).to.include("OPTIONS");
  });

  it("should know idempotent methods", () => {
    expect(methodCharacteristics.idempotent_methods).to.include("GET");
    expect(methodCharacteristics.idempotent_methods).to.include("PUT");
    expect(methodCharacteristics.idempotent_methods).to.include("DELETE");
  });

  it("should understand common request headers", () => {
    expect(commonHeaders.request_headers["Content-Type"]).to.equal("application/json");
    expect(commonHeaders.request_headers["Accept"]).to.equal("application/json");
  });
});

// Practical Example: Method Selection
function selectHttpMethod(operation, data) {
  switch (operation) {
    case "create":
      return "POST";
    case "read":
      return "GET";
    case "update_full":
      return "PUT";
    case "update_partial":
      return "PATCH";
    case "delete":
      return "DELETE";
    default:
      throw new Error(`Unknown operation: ${operation}`);
  }
}

// Test method selection
describe("HTTP Method Selection", () => {
  it("should select POST for create operation", () => {
    expect(selectHttpMethod("create")).to.equal("POST");
  });

  it("should select GET for read operation", () => {
    expect(selectHttpMethod("read")).to.equal("GET");
  });

  it("should select PUT for full update", () => {
    expect(selectHttpMethod("update_full")).to.equal("PUT");
  });

  it("should select PATCH for partial update", () => {
    expect(selectHttpMethod("update_partial")).to.equal("PATCH");
  });

  it("should select DELETE for delete operation", () => {
    expect(selectHttpMethod("delete")).to.equal("DELETE");
  });
});

export { httpMethods, methodCharacteristics, commonHeaders, selectHttpMethod };

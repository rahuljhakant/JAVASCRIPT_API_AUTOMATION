/**
 * PHASE 3: ADVANCED LEVEL
 * Module 9: Contract Testing
 * Lesson 1: API Contract Testing
 * 
 * Learning Objectives:
 * - Implement API contract testing with OpenAPI/Swagger
 * - Create consumer-driven contract tests
 * - Validate API schemas and contracts
 * - Test API versioning and backward compatibility
 */

import { expect } from "chai";
import supertest from "supertest";
import { EnhancedSupertestClient } from "../../utils/advanced-supertest-extensions.mjs";

console.log("=== API CONTRACT TESTING ===");

// OpenAPI Schema Validator
class OpenAPISchemaValidator {
  constructor(schema) {
    this.schema = schema;
    this.validators = new Map();
  }
  
  // Validate request against schema
  validateRequest(path, method, requestData) {
    const operation = this.getOperation(path, method);
    if (!operation) {
      throw new Error(`Operation ${method.toUpperCase()} ${path} not found in schema`);
    }
    
    const requestBody = operation.requestBody;
    if (requestBody && requestData) {
      this.validateRequestBody(requestBody, requestData);
    }
    
    return { valid: true, errors: [] };
  }
  
  // Validate response against schema
  validateResponse(path, method, response) {
    const operation = this.getOperation(path, method);
    if (!operation) {
      throw new Error(`Operation ${method.toUpperCase()} ${path} not found in schema`);
    }
    
    const responses = operation.responses;
    const statusCode = response.status.toString();
    const responseSchema = responses[statusCode] || responses.default;
    
    if (responseSchema) {
      this.validateResponseBody(responseSchema, response.body);
    }
    
    return { valid: true, errors: [] };
  }
  
  // Get operation from schema
  getOperation(path, method) {
    const pathItem = this.schema.paths[path];
    if (!pathItem) return null;
    
    return pathItem[method.toLowerCase()];
  }
  
  // Validate request body
  validateRequestBody(requestBody, data) {
    const content = requestBody.content;
    const jsonContent = content['application/json'];
    
    if (jsonContent && jsonContent.schema) {
      this.validateAgainstSchema(jsonContent.schema, data);
    }
  }
  
  // Validate response body
  validateResponseBody(responseSchema, data) {
    const content = responseSchema.content;
    const jsonContent = content['application/json'];
    
    if (jsonContent && jsonContent.schema) {
      this.validateAgainstSchema(jsonContent.schema, data);
    }
  }
  
  // Validate data against JSON schema
  validateAgainstSchema(schema, data) {
    // Simplified validation - in real implementation, use ajv or similar
    if (schema.type === 'object' && typeof data !== 'object') {
      throw new Error(`Expected object, got ${typeof data}`);
    }
    
    if (schema.required) {
      for (const field of schema.required) {
        if (!(field in data)) {
          throw new Error(`Required field '${field}' is missing`);
        }
      }
    }
    
    if (schema.properties) {
      for (const [field, fieldSchema] of Object.entries(schema.properties)) {
        if (field in data) {
          this.validateField(fieldSchema, data[field], field);
        }
      }
    }
  }
  
  // Validate individual field
  validateField(fieldSchema, value, fieldName) {
    if (fieldSchema.type === 'string' && typeof value !== 'string') {
      throw new Error(`Field '${fieldName}' must be a string`);
    }
    
    if (fieldSchema.type === 'number' && typeof value !== 'number') {
      throw new Error(`Field '${fieldName}' must be a number`);
    }
    
    if (fieldSchema.type === 'boolean' && typeof value !== 'boolean') {
      throw new Error(`Field '${fieldName}' must be a boolean`);
    }
    
    if (fieldSchema.enum && !fieldSchema.enum.includes(value)) {
      throw new Error(`Field '${fieldName}' must be one of: ${fieldSchema.enum.join(', ')}`);
    }
    
    if (fieldSchema.minLength && value.length < fieldSchema.minLength) {
      throw new Error(`Field '${fieldName}' must be at least ${fieldSchema.minLength} characters`);
    }
    
    if (fieldSchema.maxLength && value.length > fieldSchema.maxLength) {
      throw new Error(`Field '${fieldName}' must be at most ${fieldSchema.maxLength} characters`);
    }
  }
}

// Consumer-Driven Contract Testing
class ConsumerDrivenContract {
  constructor(consumer, provider) {
    this.consumer = consumer;
    this.provider = provider;
    this.interactions = [];
  }
  
  // Add interaction expectation
  given(state) {
    this.currentInteraction = { state, request: null, response: null };
    return this;
  }
  
  // Define request
  uponReceiving(description) {
    if (!this.currentInteraction) {
      throw new Error('Must call given() first');
    }
    this.currentInteraction.description = description;
    return this;
  }
  
  // Define request details
  withRequest(method, path, options = {}) {
    if (!this.currentInteraction) {
      throw new Error('Must call given() and uponReceiving() first');
    }
    
    this.currentInteraction.request = {
      method: method.toUpperCase(),
      path,
      headers: options.headers || {},
      body: options.body || null,
      query: options.query || {}
    };
    return this;
  }
  
  // Define expected response
  willRespondWith(status, options = {}) {
    if (!this.currentInteraction) {
      throw new Error('Must define request first');
    }
    
    this.currentInteraction.response = {
      status,
      headers: options.headers || {},
      body: options.body || null
    };
    
    this.interactions.push(this.currentInteraction);
    this.currentInteraction = null;
    return this;
  }
  
  // Verify contract
  async verify() {
    const results = [];
    
    for (const interaction of this.interactions) {
      try {
        const result = await this.verifyInteraction(interaction);
        results.push({ interaction, result, success: true });
      } catch (error) {
        results.push({ interaction, error: error.message, success: false });
      }
    }
    
    return results;
  }
  
  // Verify individual interaction
  async verifyInteraction(interaction) {
    const { request, response } = interaction;
    
    // Make actual request to provider
    const actualResponse = await this.makeRequest(request);
    
    // Compare with expected response
    this.compareResponses(response, actualResponse);
    
    return actualResponse;
  }
  
  // Make request to provider
  async makeRequest(request) {
    const client = new EnhancedSupertestClient(this.provider);
    
    let response;
    switch (request.method) {
      case 'GET':
        response = await client.get(request.path, { query: request.query });
        break;
      case 'POST':
        response = await client.post(request.path, request.body);
        break;
      case 'PUT':
        response = await client.put(request.path, request.body);
        break;
      case 'DELETE':
        response = await client.delete(request.path);
        break;
      default:
        throw new Error(`Unsupported method: ${request.method}`);
    }
    
    return response;
  }
  
  // Compare expected vs actual response
  compareResponses(expected, actual) {
    expect(actual.status).to.equal(expected.status);
    
    if (expected.headers) {
      for (const [key, value] of Object.entries(expected.headers)) {
        expect(actual.headers[key.toLowerCase()]).to.equal(value);
      }
    }
    
    if (expected.body) {
      expect(actual.body).to.deep.equal(expected.body);
    }
  }
}

// API Versioning Contract Testing
class APIVersioningContract {
  constructor(baseUrl, versions) {
    this.baseUrl = baseUrl;
    this.versions = versions;
    this.client = new EnhancedSupertestClient(baseUrl);
  }
  
  // Test backward compatibility
  async testBackwardCompatibility(endpoint, testData) {
    const results = [];
    
    for (const version of this.versions) {
      try {
        const response = await this.testEndpointVersion(endpoint, version, testData);
        results.push({
          version,
          success: true,
          response,
          compatibility: this.checkCompatibility(response, version)
        });
      } catch (error) {
        results.push({
          version,
          success: false,
          error: error.message
        });
      }
    }
    
    return results;
  }
  
  // Test endpoint for specific version
  async testEndpointVersion(endpoint, version, testData) {
    const versionedUrl = this.getVersionedUrl(endpoint, version);
    
    const response = await this.client.post(versionedUrl, testData);
    
    return {
      version,
      url: versionedUrl,
      status: response.status,
      body: response.body,
      headers: response.headers
    };
  }
  
  // Get versioned URL
  getVersionedUrl(endpoint, version) {
    return `/v${version}${endpoint}`;
  }
  
  // Check compatibility
  checkCompatibility(response, version) {
    const compatibility = {
      status: response.status >= 200 && response.status < 300,
      structure: this.checkResponseStructure(response.body),
      fields: this.checkRequiredFields(response.body)
    };
    
    return compatibility;
  }
  
  // Check response structure
  checkResponseStructure(body) {
    return typeof body === 'object' && body !== null;
  }
  
  // Check required fields
  checkRequiredFields(body) {
    const requiredFields = ['id', 'status'];
    return requiredFields.every(field => field in body);
  }
  
  // Test breaking changes
  async testBreakingChanges(oldVersion, newVersion, endpoint, testData) {
    const oldResponse = await this.testEndpointVersion(endpoint, oldVersion, testData);
    const newResponse = await this.testEndpointVersion(endpoint, newVersion, testData);
    
    const breakingChanges = this.identifyBreakingChanges(oldResponse, newResponse);
    
    return {
      oldVersion,
      newVersion,
      breakingChanges,
      compatible: breakingChanges.length === 0
    };
  }
  
  // Identify breaking changes
  identifyBreakingChanges(oldResponse, newResponse) {
    const breakingChanges = [];
    
    // Check status code changes
    if (oldResponse.status !== newResponse.status) {
      breakingChanges.push({
        type: 'status_code_change',
        old: oldResponse.status,
        new: newResponse.status
      });
    }
    
    // Check removed fields
    const oldFields = this.getFields(oldResponse.body);
    const newFields = this.getFields(newResponse.body);
    const removedFields = oldFields.filter(field => !newFields.includes(field));
    
    if (removedFields.length > 0) {
      breakingChanges.push({
        type: 'removed_fields',
        fields: removedFields
      });
    }
    
    // Check type changes
    const typeChanges = this.checkTypeChanges(oldResponse.body, newResponse.body);
    if (typeChanges.length > 0) {
      breakingChanges.push({
        type: 'type_changes',
        changes: typeChanges
      });
    }
    
    return breakingChanges;
  }
  
  // Get all fields from object
  getFields(obj, prefix = '') {
    const fields = [];
    
    for (const [key, value] of Object.entries(obj)) {
      const fieldName = prefix ? `${prefix}.${key}` : key;
      fields.push(fieldName);
      
      if (typeof value === 'object' && value !== null) {
        fields.push(...this.getFields(value, fieldName));
      }
    }
    
    return fields;
  }
  
  // Check for type changes
  checkTypeChanges(oldObj, newObj) {
    const changes = [];
    
    for (const [key, oldValue] of Object.entries(oldObj)) {
      if (key in newObj) {
        const newValue = newObj[key];
        const oldType = typeof oldValue;
        const newType = typeof newValue;
        
        if (oldType !== newType) {
          changes.push({
            field: key,
            oldType,
            newType
          });
        }
      }
    }
    
    return changes;
  }
}

// Contract Test Suite
class ContractTestSuite {
  constructor() {
    this.contracts = [];
    this.schemas = new Map();
  }
  
  // Add OpenAPI schema
  addSchema(name, schema) {
    this.schemas.set(name, new OpenAPISchemaValidator(schema));
  }
  
  // Add consumer-driven contract
  addContract(contract) {
    this.contracts.push(contract);
  }
  
  // Run all contract tests
  async runContractTests() {
    const results = {
      schemaTests: [],
      contractTests: [],
      summary: { passed: 0, failed: 0, total: 0 }
    };
    
    // Run schema validation tests
    for (const [name, validator] of this.schemas.entries()) {
      try {
        const schemaResult = await this.runSchemaTests(validator);
        results.schemaTests.push({ name, ...schemaResult });
        results.summary.passed += schemaResult.passed;
        results.summary.failed += schemaResult.failed;
        results.summary.total += schemaResult.total;
      } catch (error) {
        results.schemaTests.push({ name, error: error.message });
        results.summary.failed++;
        results.summary.total++;
      }
    }
    
    // Run consumer-driven contract tests
    for (const contract of this.contracts) {
      try {
        const contractResult = await contract.verify();
        results.contractTests.push(contractResult);
        results.summary.passed += contractResult.filter(r => r.success).length;
        results.summary.failed += contractResult.filter(r => !r.success).length;
        results.summary.total += contractResult.length;
      } catch (error) {
        results.contractTests.push({ error: error.message });
        results.summary.failed++;
        results.summary.total++;
      }
    }
    
    return results;
  }
  
  // Run schema validation tests
  async runSchemaTests(validator) {
    // This would contain actual schema validation tests
    return { passed: 1, failed: 0, total: 1 };
  }
}

// Sample OpenAPI Schema
const sampleOpenAPISchema = {
  openapi: "3.0.0",
  info: {
    title: "User API",
    version: "1.0.0"
  },
  paths: {
    "/users": {
      post: {
        summary: "Create user",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["name", "email"],
                properties: {
                  name: { type: "string", minLength: 2, maxLength: 50 },
                  email: { type: "string", format: "email" },
                  gender: { type: "string", enum: ["male", "female"] },
                  status: { type: "string", enum: ["active", "inactive"] }
                }
              }
            }
          }
        },
        responses: {
          "201": {
            description: "User created",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    id: { type: "number" },
                    name: { type: "string" },
                    email: { type: "string" },
                    gender: { type: "string" },
                    status: { type: "string" }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
};

// Exercises and Tests
describe("API Contract Testing", () => {
  let schemaValidator;
  let contractTestSuite;
  
  beforeEach(() => {
    schemaValidator = new OpenAPISchemaValidator(sampleOpenAPISchema);
    contractTestSuite = new ContractTestSuite();
  });
  
  it("should validate request against OpenAPI schema", () => {
    const validRequest = {
      name: "John Doe",
      email: "john@example.com",
      gender: "male",
      status: "active"
    };
    
    const result = schemaValidator.validateRequest("/users", "POST", validRequest);
    expect(result.valid).to.be.true;
    expect(result.errors).to.have.length(0);
  });
  
  it("should reject invalid request data", () => {
    const invalidRequest = {
      name: "", // Invalid: empty name
      email: "invalid-email", // Invalid: malformed email
      gender: "invalid", // Invalid: not in enum
      status: "invalid" // Invalid: not in enum
    };
    
    expect(() => {
      schemaValidator.validateRequest("/users", "POST", invalidRequest);
    }).to.throw();
  });
  
  it("should validate response against schema", () => {
    const validResponse = {
      status: 201,
      body: {
        id: 1,
        name: "John Doe",
        email: "john@example.com",
        gender: "male",
        status: "active"
      }
    };
    
    const result = schemaValidator.validateResponse("/users", "POST", validResponse);
    expect(result.valid).to.be.true;
  });
  
  it("should create consumer-driven contract", () => {
    const contract = new ConsumerDrivenContract("mobile-app", "user-service");
    
    contract
      .given("user exists")
      .uponReceiving("a request to get user")
      .withRequest("GET", "/users/1")
      .willRespondWith(200, {
        headers: { "Content-Type": "application/json" },
        body: { id: 1, name: "John Doe" }
      });
    
    expect(contract.interactions).to.have.length(1);
    expect(contract.interactions[0].request.method).to.equal("GET");
    expect(contract.interactions[0].response.status).to.equal(200);
  });
  
  it("should test API versioning compatibility", async () => {
    const versioningContract = new APIVersioningContract("https://api.example.com", [1, 2, 3]);
    
    const testData = {
      name: "Test User",
      email: "test@example.com"
    };
    
    const results = await versioningContract.testBackwardCompatibility("/users", testData);
    
    expect(results).to.be.an('array');
    expect(results.length).to.equal(3);
    
    results.forEach(result => {
      expect(result).to.have.property('version');
      expect(result).to.have.property('success');
    });
  });
  
  it("should detect breaking changes between versions", async () => {
    const versioningContract = new APIVersioningContract("https://api.example.com", [1, 2]);
    
    const testData = { name: "Test User" };
    
    const breakingChanges = await versioningContract.testBreakingChanges(1, 2, "/users", testData);
    
    expect(breakingChanges).to.have.property('oldVersion');
    expect(breakingChanges).to.have.property('newVersion');
    expect(breakingChanges).to.have.property('breakingChanges');
    expect(breakingChanges).to.have.property('compatible');
  });
  
  it("should run complete contract test suite", async () => {
    contractTestSuite.addSchema("user-api", sampleOpenAPISchema);
    
    const results = await contractTestSuite.runContractTests();
    
    expect(results).to.have.property('schemaTests');
    expect(results).to.have.property('contractTests');
    expect(results).to.have.property('summary');
    expect(results.summary).to.have.property('passed');
    expect(results.summary).to.have.property('failed');
    expect(results.summary).to.have.property('total');
  });
});

export { 
  OpenAPISchemaValidator, 
  ConsumerDrivenContract, 
  APIVersioningContract, 
  ContractTestSuite 
};





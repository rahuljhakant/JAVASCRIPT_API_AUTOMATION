/**
 * PHASE 3: ADVANCED LEVEL
 * Module 4: API Contracts
 * Lesson 1: Contract Validation
 * 
 * Learning Objectives:
 * - Implement API contract validation
 * - Validate request/response schemas
 * - Ensure API contract compliance
 * - Handle contract versioning
 */

import { expect } from "chai";
import supertest from "supertest";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== API CONTRACT VALIDATION ===");

const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = getApiToken();

// Initialize AJV validator
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);

// Contract Schemas
const UserSchema = {
  type: "object",
  required: ["id", "name", "email", "gender", "status"],
  properties: {
    id: { type: "integer", minimum: 1 },
    name: { type: "string", minLength: 1 },
    email: { type: "string", format: "email" },
    gender: { type: "string", enum: ["male", "female"] },
    status: { type: "string", enum: ["active", "inactive"] },
    created_at: { type: "string", format: "date-time" },
    updated_at: { type: "string", format: "date-time" }
  }
};

const UserListSchema = {
  type: "object",
  required: ["code", "meta", "data"],
  properties: {
    code: { type: "integer" },
    meta: {
      type: "object",
      required: ["pagination"],
      properties: {
        pagination: {
          type: "object",
          required: ["total", "pages", "page", "limit"],
          properties: {
            total: { type: "integer", minimum: 0 },
            pages: { type: "integer", minimum: 0 },
            page: { type: "integer", minimum: 1 },
            limit: { type: "integer", minimum: 1 }
          }
        }
      }
    },
    data: {
      type: "array",
      items: UserSchema
    }
  }
};

const CreateUserRequestSchema = {
  type: "object",
  required: ["name", "email", "gender", "status"],
  properties: {
    name: { type: "string", minLength: 1 },
    email: { type: "string", format: "email" },
    gender: { type: "string", enum: ["male", "female"] },
    status: { type: "string", enum: ["active", "inactive"] }
  }
};

// Contract Validator
class ContractValidator {
  constructor() {
    this.validators = {
      user: ajv.compile(UserSchema),
      userList: ajv.compile(UserListSchema),
      createUserRequest: ajv.compile(CreateUserRequestSchema)
    };
  }

  validate(schemaName, data) {
    const validator = this.validators[schemaName];
    if (!validator) {
      throw new Error(`Schema '${schemaName}' not found`);
    }

    const valid = validator(data);
    
    if (!valid) {
      const errors = validator.errors.map(err => ({
        path: err.instancePath || err.schemaPath,
        message: err.message,
        params: err.params
      }));
      
      return {
        valid: false,
        errors
      };
    }

    return { valid: true };
  }

  validateResponse(schemaName, response) {
    if (response.body && response.body.data) {
      return this.validate(schemaName, response.body.data);
    }
    return this.validate(schemaName, response.body);
  }
}

// Contract Test Suite
class ContractTestSuite {
  constructor(apiClient, authToken) {
    this.apiClient = apiClient;
    this.authToken = authToken;
    this.validator = new ContractValidator();
  }

  async testGetUserContract() {
    console.log("\n📋 Test 1: GET User Contract Validation");
    
    // First create a user
    const newUser = {
      name: "Contract Test User",
      email: `contracttest${Date.now()}@example.com`,
      gender: "male",
      status: "active"
    };
    
    const createResponse = await this.apiClient
      .post("/users")
      .set("Authorization", `Bearer ${this.authToken}`)
      .send(newUser);
    
    const userId = createResponse.body.data.id;
    
    // Get user and validate contract
    const response = await this.apiClient
      .get(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`);
    
    const validation = this.validator.validateResponse("user", response);
    
    expect(validation.valid).to.be.true;
    if (!validation.valid) {
      console.error("Contract validation errors:", validation.errors);
    }
    
    expect(response.body.data).to.have.property("id");
    expect(response.body.data).to.have.property("name");
    expect(response.body.data).to.have.property("email");
    expect(response.body.data).to.have.property("gender");
    expect(response.body.data).to.have.property("status");
    
    // Cleanup
    await this.apiClient
      .delete(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`);
    
    console.log("✅ GET User contract validated");
    return validation;
  }

  async testGetUsersListContract() {
    console.log("\n📋 Test 2: GET Users List Contract Validation");
    
    const response = await this.apiClient
      .get("/users")
      .set("Authorization", `Bearer ${this.authToken}`);
    
    const validation = this.validator.validate("userList", response.body);
    
    expect(validation.valid).to.be.true;
    if (!validation.valid) {
      console.error("Contract validation errors:", validation.errors);
    }
    
    expect(response.body).to.have.property("code");
    expect(response.body).to.have.property("meta");
    expect(response.body).to.have.property("data");
    expect(response.body.meta).to.have.property("pagination");
    expect(response.body.data).to.be.an("array");
    
    console.log("✅ GET Users List contract validated");
    return validation;
  }

  async testCreateUserContract() {
    console.log("\n📋 Test 3: CREATE User Contract Validation");
    
    const newUser = {
      name: "Contract Create Test",
      email: `contractcreate${Date.now()}@example.com`,
      gender: "male",
      status: "active"
    };
    
    // Validate request schema
    const requestValidation = this.validator.validate("createUserRequest", newUser);
    expect(requestValidation.valid).to.be.true;
    
    const response = await this.apiClient
      .post("/users")
      .set("Authorization", `Bearer ${this.authToken}`)
      .send(newUser);
    
    // Validate response schema
    const responseValidation = this.validator.validateResponse("user", response);
    expect(responseValidation.valid).to.be.true;
    
    expect(response.status).to.equal(201);
    expect(response.body.data).to.have.property("id");
    expect(response.body.data.email).to.equal(newUser.email);
    
    // Cleanup
    const userId = response.body.data.id;
    await this.apiClient
      .delete(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`);
    
    console.log("✅ CREATE User contract validated");
    return { requestValidation, responseValidation };
  }

  async testUpdateUserContract() {
    console.log("\n📋 Test 4: UPDATE User Contract Validation");
    
    // Create user first
    const newUser = {
      name: "Contract Update Test",
      email: `contractupdate${Date.now()}@example.com`,
      gender: "male",
      status: "active"
    };
    
    const createResponse = await this.apiClient
      .post("/users")
      .set("Authorization", `Bearer ${this.authToken}`)
      .send(newUser);
    
    const userId = createResponse.body.data.id;
    
    // Update user
    const updateData = { name: "Updated Contract User" };
    const response = await this.apiClient
      .patch(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`)
      .send(updateData);
    
    // Validate response
    const validation = this.validator.validateResponse("user", response);
    expect(validation.valid).to.be.true;
    
    expect(response.status).to.equal(200);
    expect(response.body.data.name).to.equal(updateData.name);
    
    // Cleanup
    await this.apiClient
      .delete(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`);
    
    console.log("✅ UPDATE User contract validated");
    return validation;
  }

  async testContractVersioning() {
    console.log("\n📋 Test 5: Contract Versioning");
    
    // Simulate version checking
    const response = await this.apiClient
      .get("/users")
      .set("Authorization", `Bearer ${this.authToken}`)
      .set("Accept", "application/json");
    
    // Check API version indicators
    const hasVersion = response.headers["x-api-version"] || response.body.meta?.version;
    
    if (hasVersion) {
      console.log(`✅ API Version detected: ${hasVersion}`);
    } else {
      console.log("ℹ️  No explicit version header found");
    }
    
    // Validate contract still matches
    const validation = this.validator.validate("userList", response.body);
    expect(validation.valid).to.be.true;
    
    console.log("✅ Contract versioning validated");
    return { version: hasVersion, validation };
  }
}

// Run all contract tests
(async () => {
  try {
    const testSuite = new ContractTestSuite(request, TOKEN);
    
    await testSuite.testGetUserContract();
    await testSuite.testGetUsersListContract();
    await testSuite.testCreateUserContract();
    await testSuite.testUpdateUserContract();
    await testSuite.testContractVersioning();
    
    console.log("\n✅ All contract validation tests completed!");
  } catch (error) {
    console.error("❌ Contract test failed:", error.message);
    if (error.validation) {
      console.error("Validation errors:", error.validation.errors);
    }
    process.exit(1);
  }
})();


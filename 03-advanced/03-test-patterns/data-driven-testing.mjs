/**
 * PHASE 3: ADVANCED LEVEL
 * Module 3: Test Patterns
 * Lesson 2: Data-Driven Testing
 * 
 * Learning Objectives:
 * - Implement data-driven testing patterns
 * - Separate test data from test logic
 * - Create reusable test data sets
 * - Handle multiple test scenarios efficiently
 */

import { expect } from "chai";
import supertest from "supertest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== DATA-DRIVEN TESTING ===");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = getApiToken();

// Test Data Provider
class TestDataProvider {
  static getUserTestData() {
    return [
      {
        name: "John Doe",
        email: `john${Date.now()}@example.com`,
        gender: "male",
        status: "active",
        expectedStatus: 201
      },
      {
        name: "Jane Smith",
        email: `jane${Date.now()}@example.com`,
        gender: "female",
        status: "active",
        expectedStatus: 201
      },
      {
        name: "Bob Johnson",
        email: `bob${Date.now()}@example.com`,
        gender: "male",
        status: "inactive",
        expectedStatus: 201
      }
    ];
  }

  static getInvalidUserTestData() {
    return [
      {
        name: "",
        email: "invalid-email",
        gender: "unknown",
        status: "invalid",
        expectedStatus: 422,
        errorField: "email"
      },
      {
        name: "Test User",
        email: "",
        gender: "male",
        status: "active",
        expectedStatus: 422,
        errorField: "email"
      },
      {
        name: "Test User",
        email: "not-an-email",
        gender: "male",
        status: "active",
        expectedStatus: 422,
        errorField: "email"
      }
    ];
  }

  static getUpdateTestData() {
    return [
      {
        updateField: "name",
        updateValue: "Updated Name",
        expectedStatus: 200
      },
      {
        updateField: "status",
        updateValue: "inactive",
        expectedStatus: 200
      }
    ];
  }

  static loadFromJSON(filePath) {
    try {
      const fullPath = path.join(__dirname, "../../../test-data", filePath);
      const data = fs.readFileSync(fullPath, "utf8");
      return JSON.parse(data);
    } catch (error) {
      console.warn(`Could not load ${filePath}, using default data`);
      return [];
    }
  }
}

// Data-Driven Test Runner
class DataDrivenTestRunner {
  constructor(apiClient, authToken) {
    this.apiClient = apiClient;
    this.authToken = authToken;
  }

  async runDataDrivenTest(testData, testFunction) {
    const results = [];
    
    for (const data of testData) {
      try {
        const result = await testFunction(data);
        results.push({
          data,
          success: true,
          result
        });
      } catch (error) {
        results.push({
          data,
          success: false,
          error: error.message
        });
      }
    }
    
    return results;
  }

  async createUser(userData) {
    const response = await this.apiClient
      .post("/users")
      .set("Authorization", `Bearer ${this.authToken}`)
      .send({
        name: userData.name,
        email: userData.email,
        gender: userData.gender,
        status: userData.status
      });
    
    return response;
  }

  async updateUser(userId, updateData) {
    const response = await this.apiClient
      .patch(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`)
      .send(updateData);
    
    return response;
  }
}

// Test Scenarios
async function testValidUserCreation() {
  console.log("\n📊 Test 1: Valid User Creation (Data-Driven)");
  
  const testData = TestDataProvider.getUserTestData();
  const runner = new DataDrivenTestRunner(request, TOKEN);
  const createdUsers = [];
  
  const results = await runner.runDataDrivenTest(testData, async (data) => {
    const response = await runner.createUser(data);
    
    expect(response.status).to.equal(data.expectedStatus);
    expect(response.body.data).to.have.property("id");
    expect(response.body.data.email).to.equal(data.email);
    
    createdUsers.push(response.body.data.id);
    
    return {
      userId: response.body.data.id,
      status: response.status
    };
  });
  
  console.log(`✅ Created ${results.filter(r => r.success).length} users`);
  
  // Cleanup
  for (const userId of createdUsers) {
    try {
      await request
        .delete(`/users/${userId}`)
        .set("Authorization", `Bearer ${TOKEN}`);
    } catch (error) {
      // Ignore cleanup errors
    }
  }
  
  return results;
}

async function testInvalidUserCreation() {
  console.log("\n📊 Test 2: Invalid User Creation (Data-Driven)");
  
  const testData = TestDataProvider.getInvalidUserTestData();
  const runner = new DataDrivenTestRunner(request, TOKEN);
  
  const results = await runner.runDataDrivenTest(testData, async (data) => {
    const response = await runner.createUser(data);
    
    expect(response.status).to.equal(data.expectedStatus);
    
    if (data.errorField) {
      expect(response.body.data).to.be.an("array");
      const errors = response.body.data;
      const hasFieldError = errors.some(err => 
        err.field === data.errorField || err.message.includes(data.errorField)
      );
      expect(hasFieldError).to.be.true;
    }
    
    return {
      status: response.status,
      errors: response.body.data
    };
  });
  
  console.log(`✅ Tested ${results.length} invalid scenarios`);
  return results;
}

async function testUserUpdates() {
  console.log("\n📊 Test 3: User Updates (Data-Driven)");
  
  // First create a user
  const newUser = {
    name: "Update Test User",
    email: `updatetest${Date.now()}@example.com`,
    gender: "male",
    status: "active"
  };
  
  const createResponse = await request
    .post("/users")
    .set("Authorization", `Bearer ${TOKEN}`)
    .send(newUser);
  
  const userId = createResponse.body.data.id;
  const updateTestData = TestDataProvider.getUpdateTestData();
  const runner = new DataDrivenTestRunner(request, TOKEN);
  
  const results = await runner.runDataDrivenTest(updateTestData, async (data) => {
    const updatePayload = { [data.updateField]: data.updateValue };
    const response = await runner.updateUser(userId, updatePayload);
    
    expect(response.status).to.equal(data.expectedStatus);
    expect(response.body.data[data.updateField]).to.equal(data.updateValue);
    
    return {
      field: data.updateField,
      value: data.updateValue,
      status: response.status
    };
  });
  
  // Cleanup
  await request
    .delete(`/users/${userId}`)
    .set("Authorization", `Bearer ${TOKEN}`);
  
  console.log(`✅ Tested ${results.length} update scenarios`);
  return results;
}

async function testFromExternalData() {
  console.log("\n📊 Test 4: External Data Source (Data-Driven)");
  
  // Try to load from external JSON file
  const externalData = TestDataProvider.loadFromJSON("orders.json");
  
  if (externalData.length > 0) {
    console.log(`✅ Loaded ${externalData.length} test cases from external file`);
    // Process external data if available
  } else {
    console.log("ℹ️  Using default test data (external file not available)");
    const defaultData = TestDataProvider.getUserTestData();
    const runner = new DataDrivenTestRunner(request, TOKEN);
    
    const results = await runner.runDataDrivenTest(defaultData.slice(0, 1), async (data) => {
      const response = await runner.createUser(data);
      const userId = response.body.data.id;
      
      // Cleanup
      await request
        .delete(`/users/${userId}`)
        .set("Authorization", `Bearer ${TOKEN}`);
      
      return { success: true };
    });
    
    return results;
  }
}

// Run all tests
(async () => {
  try {
    await testValidUserCreation();
    await testInvalidUserCreation();
    await testUserUpdates();
    await testFromExternalData();
    
    console.log("\n✅ All data-driven tests completed!");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
})();


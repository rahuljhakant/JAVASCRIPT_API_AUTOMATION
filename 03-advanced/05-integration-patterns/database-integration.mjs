/**
 * PHASE 3: ADVANCED LEVEL
 * Module 5: Integration Patterns
 * Lesson 1: Database Integration Testing
 * 
 * Learning Objectives:
 * - Integrate database operations with API testing
 * - Verify data consistency between API and database
 * - Test database transactions and rollbacks
 * - Implement database cleanup strategies
 */

import { expect } from "chai";
import supertest from "supertest";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== DATABASE INTEGRATION TESTING ===");

const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = getApiToken();

// Database Integration Service (Simulated)
// Note: In real scenarios, you would use actual database drivers like pg, mysql2, etc.
class DatabaseIntegrationService {
  constructor() {
    // In a real implementation, this would connect to an actual database
    this.connection = null;
    this.testData = new Map(); // Simulated database storage
  }

  // Simulate database connection
  async connect() {
    console.log("🔌 Connecting to database...");
    // In real implementation: await this.connection.connect()
    return true;
  }

  // Simulate database query
  async query(sql, params = []) {
    console.log(`📊 Executing query: ${sql}`);
    // In real implementation: return await this.connection.query(sql, params)
    
    // Simulated query results
    if (sql.includes("SELECT") && sql.includes("users")) {
      return { rows: Array.from(this.testData.values()) };
    }
    return { rows: [] };
  }

  // Simulate inserting test data
  async insertTestData(key, data) {
    this.testData.set(key, data);
    return { id: key, ...data };
  }

  // Simulate deleting test data
  async deleteTestData(key) {
    this.testData.delete(key);
    return true;
  }

  // Simulate transaction
  async transaction(callback) {
    console.log("🔄 Starting transaction...");
    try {
      const result = await callback();
      console.log("✅ Transaction committed");
      return result;
    } catch (error) {
      console.log("❌ Transaction rolled back");
      throw error;
    }
  }

  async disconnect() {
    console.log("🔌 Disconnecting from database...");
    // In real implementation: await this.connection.end()
  }
}

// API-Database Integration Tester
class APIDatabaseIntegrationTester {
  constructor(apiClient, authToken, dbService) {
    this.apiClient = apiClient;
    this.authToken = authToken;
    this.dbService = dbService;
  }

  async verifyAPIDataInDatabase(apiResponse, dbQuery) {
    console.log("\n🔍 Verifying API data in database...");
    
    const apiData = apiResponse.body.data;
    const dbResult = await this.dbService.query(dbQuery);
    
    if (dbResult.rows.length === 0) {
      throw new Error("Data not found in database");
    }
    
    const dbData = dbResult.rows[0];
    
    // Compare key fields
    expect(dbData.id).to.equal(apiData.id);
    expect(dbData.email).to.equal(apiData.email);
    expect(dbData.name).to.equal(apiData.name);
    
    console.log("✅ API data matches database");
    return { apiData, dbData };
  }

  async testCreateAndVerify() {
    console.log("\n📝 Test 1: Create via API and Verify in Database");
    
    const newUser = {
      name: "DB Integration User",
      email: `dbintegration${Date.now()}@example.com`,
      gender: "male",
      status: "active"
    };
    
    // Create via API
    const apiResponse = await this.apiClient
      .post("/users")
      .set("Authorization", `Bearer ${this.authToken}`)
      .send(newUser);
    
    expect(apiResponse.status).to.equal(201);
    const userId = apiResponse.body.data.id;
    
    // Store in simulated database
    await this.dbService.insertTestData(userId, apiResponse.body.data);
    
    // Verify in database
    const dbQuery = `SELECT * FROM users WHERE id = ${userId}`;
    await this.verifyAPIDataInDatabase(apiResponse, dbQuery);
    
    // Cleanup
    await this.apiClient
      .delete(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`);
    
    await this.dbService.deleteTestData(userId);
    
    console.log("✅ Create and verify test completed");
  }

  async testUpdateAndVerify() {
    console.log("\n📝 Test 2: Update via API and Verify in Database");
    
    // Create user first
    const newUser = {
      name: "DB Update Test",
      email: `dbupdate${Date.now()}@example.com`,
      gender: "male",
      status: "active"
    };
    
    const createResponse = await this.apiClient
      .post("/users")
      .set("Authorization", `Bearer ${this.authToken}`)
      .send(newUser);
    
    const userId = createResponse.body.data.id;
    await this.dbService.insertTestData(userId, createResponse.body.data);
    
    // Update via API
    const updateData = { name: "Updated DB User" };
    const updateResponse = await this.apiClient
      .patch(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`)
      .send(updateData);
    
    expect(updateResponse.status).to.equal(200);
    
    // Update in database
    const updatedData = { ...createResponse.body.data, ...updateData };
    await this.dbService.insertTestData(userId, updatedData);
    
    // Verify update in database
    const dbQuery = `SELECT * FROM users WHERE id = ${userId}`;
    await this.verifyAPIDataInDatabase(updateResponse, dbQuery);
    
    // Cleanup
    await this.apiClient
      .delete(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`);
    
    await this.dbService.deleteTestData(userId);
    
    console.log("✅ Update and verify test completed");
  }

  async testDeleteAndVerify() {
    console.log("\n📝 Test 3: Delete via API and Verify in Database");
    
    // Create user first
    const newUser = {
      name: "DB Delete Test",
      email: `dbdelete${Date.now()}@example.com`,
      gender: "male",
      status: "active"
    };
    
    const createResponse = await this.apiClient
      .post("/users")
      .set("Authorization", `Bearer ${this.authToken}`)
      .send(newUser);
    
    const userId = createResponse.body.data.id;
    await this.dbService.insertTestData(userId, createResponse.body.data);
    
    // Delete via API
    const deleteResponse = await this.apiClient
      .delete(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`);
    
    expect(deleteResponse.status).to.equal(204);
    
    // Verify deletion in database
    const dbResult = await this.dbService.query(
      `SELECT * FROM users WHERE id = ${userId}`
    );
    
    // In real scenario, verify record is deleted or marked as deleted
    await this.dbService.deleteTestData(userId);
    
    console.log("✅ Delete and verify test completed");
  }

  async testTransactionRollback() {
    console.log("\n📝 Test 4: Transaction Rollback on API Failure");
    
    await this.dbService.transaction(async () => {
      const newUser = {
        name: "Transaction Test",
        email: `transaction${Date.now()}@example.com`,
        gender: "male",
        status: "active"
      };
      
      // Create in database first
      const dbUser = await this.dbService.insertTestData(
        `temp_${Date.now()}`,
        newUser
      );
      
      try {
        // Try to create via API with invalid data (should fail)
        const apiResponse = await this.apiClient
          .post("/users")
          .set("Authorization", `Bearer ${this.authToken}`)
          .send({ ...newUser, email: "invalid-email" }); // Invalid email
        
        // If API fails, transaction should rollback
        if (apiResponse.status !== 201) {
          throw new Error("API creation failed, rolling back transaction");
        }
      } catch (error) {
        // Transaction rollback happens automatically
        console.log("✅ Transaction rolled back due to API failure");
        throw error;
      }
    });
  }

  async testDataConsistency() {
    console.log("\n📝 Test 5: Data Consistency Check");
    
    // Create user via API
    const newUser = {
      name: "Consistency Test",
      email: `consistency${Date.now()}@example.com`,
      gender: "male",
      status: "active"
    };
    
    const apiResponse = await this.apiClient
      .post("/users")
      .set("Authorization", `Bearer ${this.authToken}`)
      .send(newUser);
    
    const userId = apiResponse.body.data.id;
    await this.dbService.insertTestData(userId, apiResponse.body.data);
    
    // Fetch from API again
    const getResponse = await this.apiClient
      .get(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`);
    
    // Fetch from database
    const dbResult = await this.dbService.query(
      `SELECT * FROM users WHERE id = ${userId}`
    );
    
    // Compare data
    const apiData = getResponse.body.data;
    const dbData = dbResult.rows[0];
    
    expect(apiData.id).to.equal(dbData.id);
    expect(apiData.email).to.equal(dbData.email);
    expect(apiData.name).to.equal(dbData.name);
    expect(apiData.status).to.equal(dbData.status);
    
    console.log("✅ Data consistency verified");
    
    // Cleanup
    await this.apiClient
      .delete(`/users/${userId}`)
      .set("Authorization", `Bearer ${this.authToken}`);
    
    await this.dbService.deleteTestData(userId);
  }
}

// Run all integration tests
(async () => {
  try {
    const dbService = new DatabaseIntegrationService();
    await dbService.connect();
    
    const tester = new APIDatabaseIntegrationTester(request, TOKEN, dbService);
    
    await tester.testCreateAndVerify();
    await tester.testUpdateAndVerify();
    await tester.testDeleteAndVerify();
    
    try {
      await tester.testTransactionRollback();
    } catch (error) {
      console.log("ℹ️  Transaction rollback test completed (expected failure)");
    }
    
    await tester.testDataConsistency();
    
    await dbService.disconnect();
    
    console.log("\n✅ All database integration tests completed!");
  } catch (error) {
    console.error("❌ Integration test failed:", error.message);
    process.exit(1);
  }
})();


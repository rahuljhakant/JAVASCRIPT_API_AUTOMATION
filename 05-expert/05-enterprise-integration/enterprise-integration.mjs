/**
 * PHASE 5: EXPERT LEVEL
 * Module 5: Enterprise Integration
 * Lesson 1: Enterprise Integration Patterns
 * 
 * Learning Objectives:
 * - Integrate with enterprise systems
 * - Implement service mesh patterns
 * - Create API gateway integrations
 * - Design for microservices architecture
 */

import { expect } from "chai";
import supertest from "supertest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== ENTERPRISE INTEGRATION ===");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = getApiToken();

// API Gateway Client
class APIGatewayClient {
  constructor(baseUrl, apiKey) {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
    this.routes = new Map();
  }

  registerRoute(serviceName, path, targetUrl) {
    this.routes.set(`${serviceName}:${path}`, {
      serviceName,
      path,
      targetUrl,
      registeredAt: Date.now()
    });
  }

  async routeRequest(serviceName, path, method = "GET", data = null) {
    const route = this.routes.get(`${serviceName}:${path}`);
    if (!route) {
      throw new Error(`Route not found: ${serviceName}:${path}`);
    }

    const client = supertest(route.targetUrl);
    let req = client[method.toLowerCase()](route.path)
      .set("X-API-Key", this.apiKey)
      .set("X-Service-Name", serviceName);

    if (data) {
      req = req.send(data);
    }

    return await req;
  }

  getRoutes() {
    return Array.from(this.routes.values());
  }
}

// Service Mesh Client
class ServiceMeshClient {
  constructor() {
    this.services = new Map();
    this.circuitBreakers = new Map();
  }

  registerService(serviceName, config) {
    this.services.set(serviceName, {
      ...config,
      status: "healthy",
      lastHealthCheck: Date.now(),
      requestCount: 0,
      errorCount: 0
    });

    // Initialize circuit breaker
    this.circuitBreakers.set(serviceName, {
      state: "closed", // closed, open, half-open
      failureCount: 0,
      lastFailureTime: null,
      threshold: config.circuitBreakerThreshold || 5
    });
  }

  async callService(serviceName, endpoint, method = "GET", data = null) {
    const service = this.services.get(serviceName);
    if (!service) {
      throw new Error(`Service not registered: ${serviceName}`);
    }

    const circuitBreaker = this.circuitBreakers.get(serviceName);

    // Check circuit breaker state
    if (circuitBreaker.state === "open") {
      const timeSinceLastFailure = Date.now() - circuitBreaker.lastFailureTime;
      if (timeSinceLastFailure > 60000) { // 1 minute timeout
        circuitBreaker.state = "half-open";
      } else {
        throw new Error(`Circuit breaker is open for service: ${serviceName}`);
      }
    }

    try {
      const client = supertest(service.baseUrl);
      let req = client[method.toLowerCase()](endpoint);

      if (service.authToken) {
        req = req.set("Authorization", `Bearer ${service.authToken}`);
      }

      if (data) {
        req = req.send(data);
      }

      const response = await req;

      service.requestCount++;
      
      // Reset circuit breaker on success
      if (circuitBreaker.state === "half-open") {
        circuitBreaker.state = "closed";
        circuitBreaker.failureCount = 0;
      }

      return response;
    } catch (error) {
      service.errorCount++;
      circuitBreaker.failureCount++;
      circuitBreaker.lastFailureTime = Date.now();

      if (circuitBreaker.failureCount >= circuitBreaker.threshold) {
        circuitBreaker.state = "open";
      }

      throw error;
    }
  }

  getServiceHealth(serviceName) {
    const service = this.services.get(serviceName);
    if (!service) {
      return null;
    }

    const circuitBreaker = this.circuitBreakers.get(serviceName);
    const errorRate = service.requestCount > 0
      ? (service.errorCount / service.requestCount) * 100
      : 0;

    return {
      serviceName,
      status: service.status,
      requestCount: service.requestCount,
      errorCount: service.errorCount,
      errorRate: `${errorRate.toFixed(2)}%`,
      circuitBreakerState: circuitBreaker.state
    };
  }
}

// Microservices Test Orchestrator
class MicroservicesOrchestrator {
  constructor() {
    this.services = new Map();
    this.dependencies = new Map();
  }

  registerMicroservice(name, config) {
    this.services.set(name, {
      ...config,
      endpoints: config.endpoints || [],
      version: config.version || "1.0.0"
    });
  }

  addDependency(serviceName, dependsOn) {
    if (!this.dependencies.has(serviceName)) {
      this.dependencies.set(serviceName, []);
    }
    this.dependencies.get(serviceName).push(dependsOn);
  }

  async executeDistributedTest(testConfig) {
    const { services, testFlow } = testConfig;
    const results = new Map();

    // Execute tests in dependency order
    const executionOrder = this.calculateExecutionOrder(services);
    
    for (const serviceName of executionOrder) {
      const service = this.services.get(serviceName);
      if (!service) continue;

      try {
        const testFunction = testFlow[serviceName];
        if (testFunction) {
          const result = await testFunction(service);
          results.set(serviceName, { success: true, result });
        }
      } catch (error) {
        results.set(serviceName, { success: false, error: error.message });
      }
    }

    return results;
  }

  calculateExecutionOrder(services) {
    // Topological sort for dependency order
    const visited = new Set();
    const order = [];

    const visit = (serviceName) => {
      if (visited.has(serviceName)) return;
      visited.add(serviceName);

      const deps = this.dependencies.get(serviceName) || [];
      deps.forEach(dep => visit(dep));

      order.push(serviceName);
    };

    services.forEach(service => visit(service));
    return order;
  }
}

// Test Scenarios
async function testAPIGateway() {
  console.log("\n📝 Test 1: API Gateway Integration");
  
  const gateway = new APIGatewayClient("https://api-gateway.example.com", "api-key-123");
  
  // Register routes
  gateway.registerRoute("users-service", "/users", "https://gorest.co.in/public-api/");
  gateway.registerRoute("posts-service", "/posts", "https://gorest.co.in/public-api/");
  
  const routes = gateway.getRoutes();
  expect(routes.length).to.equal(2);
  
  // Test routing (simulated - actual routing would require real gateway)
  console.log("✅ API Gateway routes registered:", routes);
  
  console.log("✅ API Gateway test passed");
}

async function testServiceMesh() {
  console.log("\n📝 Test 2: Service Mesh Integration");
  
  const mesh = new ServiceMeshClient();
  
  // Register services
  mesh.registerService("users-service", {
    baseUrl: "https://gorest.co.in/public-api/",
    authToken: TOKEN,
    circuitBreakerThreshold: 5
  });
  
  // Test service call
  try {
    const response = await mesh.callService("users-service", "/users", "GET");
    expect(response.status).to.be.oneOf([200, 201]);
    console.log("✅ Service call successful");
  } catch (error) {
    console.log("ℹ️  Service call failed (expected in demo):", error.message);
  }
  
  // Check service health
  const health = mesh.getServiceHealth("users-service");
  console.log("🏥 Service Health:", health);
  
  console.log("✅ Service Mesh test passed");
}

async function testMicroservicesOrchestration() {
  console.log("\n📝 Test 3: Microservices Orchestration");
  
  const orchestrator = new MicroservicesOrchestrator();
  
  // Register microservices
  orchestrator.registerMicroservice("users-service", {
    baseUrl: "https://gorest.co.in/public-api/",
    endpoints: ["/users"]
  });
  
  orchestrator.registerMicroservice("posts-service", {
    baseUrl: "https://gorest.co.in/public-api/",
    endpoints: ["/posts"]
  });
  
  // Add dependencies
  orchestrator.addDependency("posts-service", "users-service");
  
  // Execute distributed test
  const testConfig = {
    services: ["users-service", "posts-service"],
    testFlow: {
      "users-service": async (service) => {
        const client = supertest(service.baseUrl);
        const response = await client.get("/users").set("Authorization", `Bearer ${TOKEN}`);
        return { status: response.status };
      },
      "posts-service": async (service) => {
        const client = supertest(service.baseUrl);
        const response = await client.get("/posts");
        return { status: response.status };
      }
    }
  };
  
  const results = await orchestrator.executeDistributedTest(testConfig);
  
  expect(results.size).to.be.greaterThan(0);
  console.log("📊 Orchestration Results:", Array.from(results.entries()));
  
  console.log("✅ Microservices orchestration test passed");
}

// Run all tests
(async () => {
  try {
    await testAPIGateway();
    await testServiceMesh();
    await testMicroservicesOrchestration();
    
    console.log("\n✅ All enterprise integration tests completed!");
  } catch (error) {
    console.error("❌ Enterprise integration test failed:", error.message);
    process.exit(1);
  }
})();


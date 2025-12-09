/**
 * PHASE 3: ADVANCED LEVEL
 * Module 8: Allure Reporting
 * Lesson 1: Allure Setup and Configuration
 * 
 * Learning Objectives:
 * - Set up Allure reporting framework
 * - Configure Allure with Mocha
 * - Create detailed test reports
 */

import { expect } from "chai";
import supertest from "supertest";
import allure from '@wdio/allure-reporter';

console.log("=== ALLURE REPORTING SETUP ===");

// Allure Configuration
const allureConfig = {
  resultsDir: 'allure-results',
  reportDir: 'allure-report',
  categories: [
    {
      name: 'API Tests',
      matchedStatuses: ['passed', 'failed', 'broken', 'skipped']
    },
    {
      name: 'Performance Tests',
      matchedStatuses: ['passed', 'failed']
    },
    {
      name: 'Security Tests',
      matchedStatuses: ['passed', 'failed', 'broken']
    }
  ],
  environment: {
    browser: 'Node.js',
    version: process.version,
    platform: process.platform,
    arch: process.arch
  }
};

// Allure Helper Class
class AllureHelper {
  static addFeature(feature) {
    allure.addFeature(feature);
  }
  
  static addStory(story) {
    allure.addStory(story);
  }
  
  static addSeverity(severity) {
    allure.addSeverity(severity);
  }
  
  static addStep(step, body) {
    allure.addStep(step);
    if (body) {
      allure.addAttachment('Step Details', body, 'text/plain');
    }
  }
  
  static addAttachment(name, content, type = 'text/plain') {
    allure.addAttachment(name, content, type);
  }
  
  static addDescription(description, type = 'text') {
    allure.addDescription(description, type);
  }
  
  static addLabel(name, value) {
    allure.addLabel(name, value);
  }
  
  static addLink(url, name, type = 'link') {
    allure.addLink(url, name, type);
  }
  
  static addParameter(name, value) {
    allure.addParameter(name, value);
  }
  
  static addTestId(testId) {
    allure.addTestId(testId);
  }
  
  static addIssue(issue) {
    allure.addIssue(issue);
  }
  
  static addEpic(epic) {
    allure.addEpic(epic);
  }
  
  static startStep(step) {
    allure.startStep(step);
  }
  
  static endStep(status = 'passed') {
    allure.endStep(status);
  }
}

// Enhanced Test Base Class
class AllureTestBase {
  constructor(testName) {
    this.testName = testName;
    this.startTime = Date.now();
    this.steps = [];
  }
  
  setup() {
    AllureHelper.addFeature('API Automation');
    AllureHelper.addEpic('JavaScript API Testing');
    AllureHelper.addTestId(this.testName);
  }
  
  addStep(stepName, stepFunction) {
    AllureHelper.startStep(stepName);
    try {
      const result = stepFunction();
      this.steps.push({ name: stepName, status: 'passed', result });
      AllureHelper.endStep('passed');
      return result;
    } catch (error) {
      this.steps.push({ name: stepName, status: 'failed', error: error.message });
      AllureHelper.endStep('failed');
      throw error;
    }
  }
  
  addAttachment(name, content, type) {
    AllureHelper.addAttachment(name, content, type);
  }
  
  addRequestAttachment(request) {
    this.addAttachment('Request Details', JSON.stringify({
      method: request.method,
      url: request.url,
      headers: request.headers,
      body: request.body
    }, null, 2), 'application/json');
  }
  
  addResponseAttachment(response) {
    this.addAttachment('Response Details', JSON.stringify({
      status: response.status,
      headers: response.headers,
      body: response.body,
      responseTime: response.responseTime
    }, null, 2), 'application/json');
  }
  
  teardown() {
    const endTime = Date.now();
    const duration = endTime - this.startTime;
    AllureHelper.addParameter('Duration (ms)', duration.toString());
    AllureHelper.addParameter('Total Steps', this.steps.length.toString());
  }
}

// API Test with Allure Integration
const request = supertest("https://jsonplaceholder.typicode.com");

describe("Allure Reporting - User Management", () => {
  let testBase;
  
  beforeEach(() => {
    testBase = new AllureTestBase('User Management Tests');
    testBase.setup();
  });
  
  afterEach(() => {
    testBase.teardown();
  });
  
  it("should create user with detailed Allure reporting", async () => {
    // Add test metadata
    AllureHelper.addFeature('User Management');
    AllureHelper.addStory('Create User');
    AllureHelper.addSeverity('critical');
    AllureHelper.addDescription('Test user creation with validation', 'html');
    
    // Add labels
    AllureHelper.addLabel('component', 'user-api');
    AllureHelper.addLabel('owner', 'api-team');
    AllureHelper.addLabel('priority', 'high');
    
    // Test steps with Allure integration
    const userData = testBase.addStep('Prepare test data', () => {
      const data = {
        name: 'John Doe',
        email: 'john.doe@example.com',
        username: 'johndoe',
        phone: '+1234567890',
        website: 'johndoe.com'
      };
      testBase.addAttachment('User Data', JSON.stringify(data, null, 2), 'application/json');
      return data;
    });
    
    const requestDetails = testBase.addStep('Prepare request', () => {
      const requestConfig = {
        method: 'POST',
        url: '/users',
        headers: { 'Content-Type': 'application/json' },
        body: userData
      };
      testBase.addRequestAttachment(requestConfig);
      return requestConfig;
    });
    
    const response = await testBase.addStep('Send POST request', async () => {
      const res = await request
        .post('/users')
        .send(userData);
      
      testBase.addResponseAttachment(res);
      return res;
    });
    
    testBase.addStep('Validate response', () => {
      expect(response.status).to.equal(201);
      expect(response.body).to.have.property('id');
      expect(response.body.name).to.equal(userData.name);
      expect(response.body.email).to.equal(userData.email);
      
      AllureHelper.addAttachment('Validation Results', JSON.stringify({
        statusValidation: response.status === 201,
        idExists: response.body.hasOwnProperty('id'),
        nameMatch: response.body.name === userData.name,
        emailMatch: response.body.email === userData.email
      }, null, 2), 'application/json');
    });
    
    // Add performance metrics
    testBase.addStep('Performance Analysis', () => {
      const metrics = {
        responseTime: response.responseTime,
        status: response.status,
        bodySize: JSON.stringify(response.body).length
      };
      
      AllureHelper.addParameter('Response Time (ms)', metrics.responseTime.toString());
      AllureHelper.addParameter('Response Size (bytes)', metrics.bodySize.toString());
      
      expect(metrics.responseTime).to.be.lessThan(5000);
    });
  });
  
  it("should retrieve user with error handling", async () => {
    AllureHelper.addFeature('User Management');
    AllureHelper.addStory('Retrieve User');
    AllureHelper.addSeverity('high');
    
    const userId = testBase.addStep('Generate test user ID', () => {
      const id = Math.floor(Math.random() * 1000) + 1;
      AllureHelper.addParameter('User ID', id.toString());
      return id;
    });
    
    const response = await testBase.addStep('Send GET request', async () => {
      const res = await request.get(`/users/${userId}`);
      testBase.addResponseAttachment(res);
      return res;
    });
    
    testBase.addStep('Validate user data', () => {
      expect(response.status).to.equal(200);
      expect(response.body).to.have.property('id');
      expect(response.body.id).to.equal(userId);
      
      // Add user data to report
      AllureHelper.addAttachment('User Profile', JSON.stringify({
        id: response.body.id,
        name: response.body.name,
        email: response.body.email,
        username: response.body.username
      }, null, 2), 'application/json');
    });
  });
  
  it("should handle API errors gracefully", async () => {
    AllureHelper.addFeature('Error Handling');
    AllureHelper.addStory('API Error Scenarios');
    AllureHelper.addSeverity('medium');
    
    const response = await testBase.addStep('Request non-existent user', async () => {
      const res = await request.get('/users/999999');
      testBase.addResponseAttachment(res);
      return res;
    });
    
    testBase.addStep('Validate error response', () => {
      expect(response.status).to.equal(404);
      
      AllureHelper.addAttachment('Error Analysis', JSON.stringify({
        expectedStatus: 404,
        actualStatus: response.status,
        errorHandled: response.status === 404,
        responseBody: response.body
      }, null, 2), 'application/json');
    });
  });
});

// Performance Testing with Allure
describe("Performance Testing with Allure", () => {
  it("should measure API response times", async () => {
    AllureHelper.addFeature('Performance Testing');
    AllureHelper.addStory('Response Time Measurement');
    AllureHelper.addSeverity('medium');
    
    const iterations = 5;
    const responseTimes = [];
    
    for (let i = 0; i < iterations; i++) {
      const startTime = Date.now();
      const response = await request.get('/posts/1');
      const endTime = Date.now();
      
      const responseTime = endTime - startTime;
      responseTimes.push(responseTime);
      
      AllureHelper.addParameter(`Response Time ${i + 1} (ms)`, responseTime.toString());
    }
    
    const averageResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
    const minResponseTime = Math.min(...responseTimes);
    const maxResponseTime = Math.max(...responseTimes);
    
    AllureHelper.addAttachment('Performance Metrics', JSON.stringify({
      iterations,
      averageResponseTime: Math.round(averageResponseTime),
      minResponseTime,
      maxResponseTime,
      allResponseTimes: responseTimes
    }, null, 2), 'application/json');
    
    expect(averageResponseTime).to.be.lessThan(2000);
  });
});

// Security Testing with Allure
describe("Security Testing with Allure", () => {
  it("should validate API security headers", async () => {
    AllureHelper.addFeature('Security Testing');
    AllureHelper.addStory('Security Headers Validation');
    AllureHelper.addSeverity('high');
    
    const response = await request.get('/posts/1');
    
    const securityHeaders = {
      'X-Content-Type-Options': response.headers['x-content-type-options'],
      'X-Frame-Options': response.headers['x-frame-options'],
      'X-XSS-Protection': response.headers['x-xss-protection'],
      'Strict-Transport-Security': response.headers['strict-transport-security'],
      'Content-Security-Policy': response.headers['content-security-policy']
    };
    
    AllureHelper.addAttachment('Security Headers Analysis', JSON.stringify({
      headersPresent: Object.values(securityHeaders).filter(h => h).length,
      totalHeaders: Object.keys(securityHeaders).length,
      securityScore: Math.round((Object.values(securityHeaders).filter(h => h).length / Object.keys(securityHeaders).length) * 100),
      headers: securityHeaders
    }, null, 2), 'application/json');
    
    // Note: This API might not have all security headers, so we'll just log the analysis
    console.log('Security Headers Analysis:', securityHeaders);
  });
});

// Export utilities
export { 
  AllureHelper, 
  AllureTestBase, 
  allureConfig 
};

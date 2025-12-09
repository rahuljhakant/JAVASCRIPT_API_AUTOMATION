/**
 * PHASE 5: EXPERT LEVEL
 * Module 2: Mutation Testing
 * Lesson 1: Mutation Testing for API Automation
 * 
 * Learning Objectives:
 * - Implement mutation testing for API test suites
 * - Create mutation operators for API testing
 * - Analyze mutation test results
 * - Improve test quality based on mutation analysis
 */

import { expect } from "chai";
import supertest from "supertest";
import { EnhancedSupertestClient } from "../../utils/advanced-supertest-extensions.mjs";

console.log("=== MUTATION TESTING FOR API AUTOMATION ===");

// Mutation Operators for API Testing
class APIMutationOperators {
  constructor() {
    this.operators = new Map();
    this.setupOperators();
  }
  
  // Setup mutation operators
  setupOperators() {
    // Status Code Mutations
    this.operators.set('status_code_change', {
      name: 'Status Code Change',
      description: 'Change expected status code',
      apply: (test, mutation) => {
        const originalStatus = test.expectedStatus;
        test.expectedStatus = mutation.newStatus;
        return { original: originalStatus, mutated: mutation.newStatus };
      }
    });
    
    // Response Body Mutations
    this.operators.set('response_body_change', {
      name: 'Response Body Change',
      description: 'Modify expected response body',
      apply: (test, mutation) => {
        const originalBody = test.expectedBody;
        test.expectedBody = mutation.newBody;
        return { original: originalBody, mutated: mutation.newBody };
      }
    });
    
    // Header Mutations
    this.operators.set('header_change', {
      name: 'Header Change',
      description: 'Modify expected headers',
      apply: (test, mutation) => {
        const originalHeaders = test.expectedHeaders;
        test.expectedHeaders = { ...originalHeaders, ...mutation.newHeaders };
        return { original: originalHeaders, mutated: test.expectedHeaders };
      }
    });
    
    // Request Method Mutations
    this.operators.set('method_change', {
      name: 'HTTP Method Change',
      description: 'Change HTTP method',
      apply: (test, mutation) => {
        const originalMethod = test.method;
        test.method = mutation.newMethod;
        return { original: originalMethod, mutated: mutation.newMethod };
      }
    });
    
    // URL Mutations
    this.operators.set('url_change', {
      name: 'URL Change',
      description: 'Modify request URL',
      apply: (test, mutation) => {
        const originalUrl = test.url;
        test.url = mutation.newUrl;
        return { original: originalUrl, mutated: mutation.newUrl };
      }
    });
    
    // Request Body Mutations
    this.operators.set('request_body_change', {
      name: 'Request Body Change',
      description: 'Modify request body',
      apply: (test, mutation) => {
        const originalBody = test.requestBody;
        test.requestBody = mutation.newBody;
        return { original: originalBody, mutated: mutation.newBody };
      }
    });
    
    // Query Parameter Mutations
    this.operators.set('query_param_change', {
      name: 'Query Parameter Change',
      description: 'Modify query parameters',
      apply: (test, mutation) => {
        const originalParams = test.queryParams;
        test.queryParams = { ...originalParams, ...mutation.newParams };
        return { original: originalParams, mutated: test.queryParams };
      }
    });
    
    // Assertion Mutations
    this.operators.set('assertion_change', {
      name: 'Assertion Change',
      description: 'Modify test assertions',
      apply: (test, mutation) => {
        const originalAssertions = test.assertions;
        test.assertions = mutation.newAssertions;
        return { original: originalAssertions, mutated: mutation.newAssertions };
      }
    });
    
    // Timeout Mutations
    this.operators.set('timeout_change', {
      name: 'Timeout Change',
      description: 'Modify request timeout',
      apply: (test, mutation) => {
        const originalTimeout = test.timeout;
        test.timeout = mutation.newTimeout;
        return { original: originalTimeout, mutated: mutation.newTimeout };
      }
    });
    
    // Authentication Mutations
    this.operators.set('auth_change', {
      name: 'Authentication Change',
      description: 'Modify authentication',
      apply: (test, mutation) => {
        const originalAuth = test.authentication;
        test.authentication = mutation.newAuth;
        return { original: originalAuth, mutated: mutation.newAuth };
      }
    });
  }
  
  // Get operator by name
  getOperator(name) {
    return this.operators.get(name);
  }
  
  // Get all operators
  getAllOperators() {
    return Array.from(this.operators.values());
  }
  
  // Apply mutation
  applyMutation(test, operatorName, mutation) {
    const operator = this.getOperator(operatorName);
    if (!operator) {
      throw new Error(`Unknown mutation operator: ${operatorName}`);
    }
    
    return operator.apply(test, mutation);
  }
}

// Mutation Test Generator
class MutationTestGenerator {
  constructor(operators) {
    this.operators = operators;
    this.mutations = [];
  }
  
  // Generate mutations for a test
  generateMutations(test) {
    const mutations = [];
    
    // Status code mutations
    if (test.expectedStatus) {
      const statusMutations = this.generateStatusMutations(test.expectedStatus);
      statusMutations.forEach(mutation => {
        mutations.push({
          operator: 'status_code_change',
          mutation,
          test: { ...test }
        });
      });
    }
    
    // Response body mutations
    if (test.expectedBody) {
      const bodyMutations = this.generateBodyMutations(test.expectedBody);
      bodyMutations.forEach(mutation => {
        mutations.push({
          operator: 'response_body_change',
          mutation,
          test: { ...test }
        });
      });
    }
    
    // Header mutations
    if (test.expectedHeaders) {
      const headerMutations = this.generateHeaderMutations(test.expectedHeaders);
      headerMutations.forEach(mutation => {
        mutations.push({
          operator: 'header_change',
          mutation,
          test: { ...test }
        });
      });
    }
    
    // Method mutations
    if (test.method) {
      const methodMutations = this.generateMethodMutations(test.method);
      methodMutations.forEach(mutation => {
        mutations.push({
          operator: 'method_change',
          mutation,
          test: { ...test }
        });
      });
    }
    
    // URL mutations
    if (test.url) {
      const urlMutations = this.generateURLMutations(test.url);
      urlMutations.forEach(mutation => {
        mutations.push({
          operator: 'url_change',
          mutation,
          test: { ...test }
        });
      });
    }
    
    // Request body mutations
    if (test.requestBody) {
      const requestBodyMutations = this.generateRequestBodyMutations(test.requestBody);
      requestBodyMutations.forEach(mutation => {
        mutations.push({
          operator: 'request_body_change',
          mutation,
          test: { ...test }
        });
      });
    }
    
    // Query parameter mutations
    if (test.queryParams) {
      const queryMutations = this.generateQueryMutations(test.queryParams);
      queryMutations.forEach(mutation => {
        mutations.push({
          operator: 'query_param_change',
          mutation,
          test: { ...test }
        });
      });
    }
    
    // Assertion mutations
    if (test.assertions) {
      const assertionMutations = this.generateAssertionMutations(test.assertions);
      assertionMutations.forEach(mutation => {
        mutations.push({
          operator: 'assertion_change',
          mutation,
          test: { ...test }
        });
      });
    }
    
    // Timeout mutations
    if (test.timeout) {
      const timeoutMutations = this.generateTimeoutMutations(test.timeout);
      timeoutMutations.forEach(mutation => {
        mutations.push({
          operator: 'timeout_change',
          mutation,
          test: { ...test }
        });
      });
    }
    
    // Authentication mutations
    if (test.authentication) {
      const authMutations = this.generateAuthMutations(test.authentication);
      authMutations.forEach(mutation => {
        mutations.push({
          operator: 'auth_change',
          mutation,
          test: { ...test }
        });
      });
    }
    
    return mutations;
  }
  
  // Generate status code mutations
  generateStatusMutations(originalStatus) {
    const commonStatuses = [200, 201, 204, 400, 401, 403, 404, 422, 500];
    return commonStatuses
      .filter(status => status !== originalStatus)
      .map(status => ({ newStatus: status }));
  }
  
  // Generate response body mutations
  generateBodyMutations(originalBody) {
    const mutations = [];
    
    // Change string values
    if (typeof originalBody === 'object') {
      for (const [key, value] of Object.entries(originalBody)) {
        if (typeof value === 'string') {
          mutations.push({
            newBody: { ...originalBody, [key]: 'mutated_value' }
          });
        } else if (typeof value === 'number') {
          mutations.push({
            newBody: { ...originalBody, [key]: value + 1 }
          });
        } else if (typeof value === 'boolean') {
          mutations.push({
            newBody: { ...originalBody, [key]: !value }
          });
        }
      }
    }
    
    return mutations;
  }
  
  // Generate header mutations
  generateHeaderMutations(originalHeaders) {
    const mutations = [];
    
    // Change existing headers
    for (const [key, value] of Object.entries(originalHeaders)) {
      mutations.push({
        newHeaders: { ...originalHeaders, [key]: 'mutated_value' }
      });
    }
    
    // Add new headers
    mutations.push({
      newHeaders: { ...originalHeaders, 'X-Mutated': 'true' }
    });
    
    return mutations;
  }
  
  // Generate method mutations
  generateMethodMutations(originalMethod) {
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
    return methods
      .filter(method => method !== originalMethod)
      .map(method => ({ newMethod: method }));
  }
  
  // Generate URL mutations
  generateURLMutations(originalUrl) {
    const mutations = [];
    
    // Change path
    mutations.push({
      newUrl: originalUrl.replace(/\/[^\/]+$/, '/mutated')
    });
    
    // Add query parameter
    mutations.push({
      newUrl: originalUrl + '?mutated=true'
    });
    
    // Change path parameter
    if (originalUrl.includes('/')) {
      mutations.push({
        newUrl: originalUrl.replace(/\d+/, '999')
      });
    }
    
    return mutations;
  }
  
  // Generate request body mutations
  generateRequestBodyMutations(originalBody) {
    const mutations = [];
    
    if (typeof originalBody === 'object') {
      for (const [key, value] of Object.entries(originalBody)) {
        if (typeof value === 'string') {
          mutations.push({
            newBody: { ...originalBody, [key]: 'mutated_value' }
          });
        } else if (typeof value === 'number') {
          mutations.push({
            newBody: { ...originalBody, [key]: value + 1 }
          });
        }
      }
    }
    
    return mutations;
  }
  
  // Generate query parameter mutations
  generateQueryMutations(originalParams) {
    const mutations = [];
    
    // Change existing parameters
    for (const [key, value] of Object.entries(originalParams)) {
      mutations.push({
        newParams: { ...originalParams, [key]: 'mutated_value' }
      });
    }
    
    // Add new parameters
    mutations.push({
      newParams: { ...originalParams, mutated: 'true' }
    });
    
    return mutations;
  }
  
  // Generate assertion mutations
  generateAssertionMutations(originalAssertions) {
    const mutations = [];
    
    // Change assertion type
    mutations.push({
      newAssertions: originalAssertions.map(assertion => ({
        ...assertion,
        type: assertion.type === 'equals' ? 'notEquals' : 'equals'
      }))
    });
    
    // Change assertion value
    mutations.push({
      newAssertions: originalAssertions.map(assertion => ({
        ...assertion,
        expected: 'mutated_value'
      }))
    });
    
    return mutations;
  }
  
  // Generate timeout mutations
  generateTimeoutMutations(originalTimeout) {
    return [
      { newTimeout: originalTimeout * 2 },
      { newTimeout: originalTimeout / 2 },
      { newTimeout: 0 }
    ];
  }
  
  // Generate authentication mutations
  generateAuthMutations(originalAuth) {
    const mutations = [];
    
    // Change token
    if (originalAuth.token) {
      mutations.push({
        newAuth: { ...originalAuth, token: 'mutated_token' }
      });
    }
    
    // Remove authentication
    mutations.push({
      newAuth: null
    });
    
    return mutations;
  }
}

// Mutation Test Runner
class MutationTestRunner {
  constructor(client) {
    this.client = client;
    this.results = new Map();
  }
  
  // Run mutation test
  async runMutationTest(originalTest, mutation) {
    try {
      // Apply mutation
      const mutatedTest = { ...mutation.test };
      const operator = new APIMutationOperators();
      operator.applyMutation(mutatedTest, mutation.operator, mutation.mutation);
      
      // Run original test
      const originalResult = await this.runTest(originalTest);
      
      // Run mutated test
      const mutatedResult = await this.runTest(mutatedTest);
      
      // Compare results
      const comparison = this.compareResults(originalResult, mutatedResult);
      
      return {
        mutation,
        originalResult,
        mutatedResult,
        comparison,
        killed: comparison.different
      };
      
    } catch (error) {
      return {
        mutation,
        error: error.message,
        killed: true // Error means mutation was killed
      };
    }
  }
  
  // Run individual test
  async runTest(test) {
    const startTime = Date.now();
    
    try {
      let response;
      
      // Set up request
      const request = this.client[test.method.toLowerCase()](test.url);
      
      // Add headers
      if (test.headers) {
        Object.entries(test.headers).forEach(([key, value]) => {
          request.set(key, value);
        });
      }
      
      // Add query parameters
      if (test.queryParams) {
        request.query(test.queryParams);
      }
      
      // Add request body
      if (test.requestBody && ['POST', 'PUT', 'PATCH'].includes(test.method.toUpperCase())) {
        request.send(test.requestBody);
      }
      
      // Set timeout
      if (test.timeout) {
        request.timeout(test.timeout);
      }
      
      // Add authentication
      if (test.authentication && test.authentication.token) {
        request.set('Authorization', `Bearer ${test.authentication.token}`);
      }
      
      // Execute request
      response = await request;
      
      const endTime = Date.now();
      
      return {
        success: true,
        status: response.status,
        body: response.body,
        headers: response.headers,
        responseTime: endTime - startTime,
        error: null
      };
      
    } catch (error) {
      const endTime = Date.now();
      
      return {
        success: false,
        status: error.status || 0,
        body: null,
        headers: {},
        responseTime: endTime - startTime,
        error: error.message
      };
    }
  }
  
  // Compare test results
  compareResults(original, mutated) {
    const differences = [];
    
    // Compare status codes
    if (original.status !== mutated.status) {
      differences.push({
        field: 'status',
        original: original.status,
        mutated: mutated.status
      });
    }
    
    // Compare response bodies
    if (JSON.stringify(original.body) !== JSON.stringify(mutated.body)) {
      differences.push({
        field: 'body',
        original: original.body,
        mutated: mutated.body
      });
    }
    
    // Compare headers
    if (JSON.stringify(original.headers) !== JSON.stringify(mutated.headers)) {
      differences.push({
        field: 'headers',
        original: original.headers,
        mutated: mutated.headers
      });
    }
    
    // Compare success status
    if (original.success !== mutated.success) {
      differences.push({
        field: 'success',
        original: original.success,
        mutated: mutated.success
      });
    }
    
    return {
      different: differences.length > 0,
      differences
    };
  }
  
  // Run all mutations for a test
  async runAllMutations(originalTest, mutations) {
    const results = [];
    
    for (const mutation of mutations) {
      const result = await this.runMutationTest(originalTest, mutation);
      results.push(result);
    }
    
    return results;
  }
}

// Mutation Analysis
class MutationAnalysis {
  constructor() {
    this.results = [];
  }
  
  // Analyze mutation results
  analyzeResults(results) {
    const analysis = {
      totalMutations: results.length,
      killedMutations: results.filter(r => r.killed).length,
      survivedMutations: results.filter(r => !r.killed).length,
      errorMutations: results.filter(r => r.error).length,
      mutationScore: 0,
      operatorAnalysis: new Map(),
      recommendations: []
    };
    
    // Calculate mutation score
    analysis.mutationScore = analysis.totalMutations > 0 ? 
      (analysis.killedMutations / analysis.totalMutations) * 100 : 0;
    
    // Analyze by operator
    for (const result of results) {
      const operator = result.mutation.operator;
      if (!analysis.operatorAnalysis.has(operator)) {
        analysis.operatorAnalysis.set(operator, {
          total: 0,
          killed: 0,
          survived: 0,
          errors: 0
        });
      }
      
      const operatorStats = analysis.operatorAnalysis.get(operator);
      operatorStats.total++;
      
      if (result.error) {
        operatorStats.errors++;
      } else if (result.killed) {
        operatorStats.killed++;
      } else {
        operatorStats.survived++;
      }
    }
    
    // Generate recommendations
    analysis.recommendations = this.generateRecommendations(analysis);
    
    return analysis;
  }
  
  // Generate recommendations
  generateRecommendations(analysis) {
    const recommendations = [];
    
    // Overall mutation score
    if (analysis.mutationScore < 70) {
      recommendations.push({
        type: 'mutation_score',
        severity: 'high',
        message: `Mutation score is too low (${analysis.mutationScore.toFixed(2)}%)`,
        suggestion: 'Add more test cases to kill surviving mutations'
      });
    }
    
    // Operator-specific recommendations
    for (const [operator, stats] of analysis.operatorAnalysis.entries()) {
      const operatorScore = stats.total > 0 ? (stats.killed / stats.total) * 100 : 0;
      
      if (operatorScore < 50) {
        recommendations.push({
          type: 'operator_coverage',
          severity: 'medium',
          message: `Low coverage for ${operator} mutations (${operatorScore.toFixed(2)}%)`,
          suggestion: `Add tests to cover ${operator} scenarios`
        });
      }
    }
    
    // Surviving mutations
    if (analysis.survivedMutations > 0) {
      recommendations.push({
        type: 'surviving_mutations',
        severity: 'medium',
        message: `${analysis.survivedMutations} mutations survived`,
        suggestion: 'Review surviving mutations and add appropriate test cases'
      });
    }
    
    return recommendations;
  }
  
  // Generate detailed report
  generateReport(analysis) {
    return {
      summary: {
        mutationScore: analysis.mutationScore,
        totalMutations: analysis.totalMutations,
        killedMutations: analysis.killedMutations,
        survivedMutations: analysis.survivedMutations,
        errorMutations: analysis.errorMutations
      },
      operatorBreakdown: Object.fromEntries(analysis.operatorAnalysis),
      recommendations: analysis.recommendations,
      quality: this.assessQuality(analysis.mutationScore)
    };
  }
  
  // Assess test quality
  assessQuality(mutationScore) {
    if (mutationScore >= 90) return 'excellent';
    if (mutationScore >= 80) return 'good';
    if (mutationScore >= 70) return 'acceptable';
    if (mutationScore >= 50) return 'poor';
    return 'very_poor';
  }
}

// Exercises and Tests
describe("Mutation Testing for API Automation", () => {
  let operators;
  let generator;
  let runner;
  let analysis;
  let client;
  
  beforeEach(() => {
    operators = new APIMutationOperators();
    generator = new MutationTestGenerator(operators);
    client = new EnhancedSupertestClient("https://api.example.com");
    runner = new MutationTestRunner(client);
    analysis = new MutationAnalysis();
  });
  
  it("should create mutation operators", () => {
    const allOperators = operators.getAllOperators();
    
    expect(allOperators).to.be.an('array');
    expect(allOperators.length).to.be.greaterThan(0);
    
    const statusOperator = operators.getOperator('status_code_change');
    expect(statusOperator).to.exist;
    expect(statusOperator.name).to.equal('Status Code Change');
  });
  
  it("should generate mutations for a test", () => {
    const test = {
      method: 'GET',
      url: '/users/1',
      expectedStatus: 200,
      expectedBody: { id: 1, name: 'John Doe' },
      expectedHeaders: { 'Content-Type': 'application/json' },
      queryParams: { page: 1 },
      requestBody: { name: 'Test User' },
      timeout: 5000,
      authentication: { token: 'valid_token' }
    };
    
    const mutations = generator.generateMutations(test);
    
    expect(mutations).to.be.an('array');
    expect(mutations.length).to.be.greaterThan(0);
    
    // Check for status code mutations
    const statusMutations = mutations.filter(m => m.operator === 'status_code_change');
    expect(statusMutations.length).to.be.greaterThan(0);
    
    // Check for method mutations
    const methodMutations = mutations.filter(m => m.operator === 'method_change');
    expect(methodMutations.length).to.be.greaterThan(0);
  });
  
  it("should generate status code mutations", () => {
    const mutations = generator.generateStatusMutations(200);
    
    expect(mutations).to.be.an('array');
    expect(mutations.length).to.be.greaterThan(0);
    expect(mutations.every(m => m.newStatus !== 200)).to.be.true;
  });
  
  it("should generate response body mutations", () => {
    const body = { id: 1, name: 'John Doe', active: true };
    const mutations = generator.generateBodyMutations(body);
    
    expect(mutations).to.be.an('array');
    expect(mutations.length).to.be.greaterThan(0);
    
    // Check for string mutation
    const stringMutation = mutations.find(m => m.newBody.name === 'mutated_value');
    expect(stringMutation).to.exist;
    
    // Check for number mutation
    const numberMutation = mutations.find(m => m.newBody.id === 2);
    expect(numberMutation).to.exist;
    
    // Check for boolean mutation
    const booleanMutation = mutations.find(m => m.newBody.active === false);
    expect(booleanMutation).to.exist;
  });
  
  it("should generate method mutations", () => {
    const mutations = generator.generateMethodMutations('GET');
    
    expect(mutations).to.be.an('array');
    expect(mutations.length).to.be.greaterThan(0);
    expect(mutations.every(m => m.newMethod !== 'GET')).to.be.true;
    expect(mutations.some(m => m.newMethod === 'POST')).to.be.true;
  });
  
  it("should generate URL mutations", () => {
    const mutations = generator.generateURLMutations('/users/1');
    
    expect(mutations).to.be.an('array');
    expect(mutations.length).to.be.greaterThan(0);
    
    // Check for path mutation
    const pathMutation = mutations.find(m => m.newUrl.includes('/mutated'));
    expect(pathMutation).to.exist;
    
    // Check for query parameter mutation
    const queryMutation = mutations.find(m => m.newUrl.includes('?mutated=true'));
    expect(queryMutation).to.exist;
  });
  
  it("should run mutation test", async () => {
    const originalTest = {
      method: 'GET',
      url: '/users/1',
      expectedStatus: 200
    };
    
    const mutation = {
      operator: 'status_code_change',
      mutation: { newStatus: 404 },
      test: { ...originalTest }
    };
    
    const result = await runner.runMutationTest(originalTest, mutation);
    
    expect(result).to.have.property('mutation');
    expect(result).to.have.property('originalResult');
    expect(result).to.have.property('mutatedResult');
    expect(result).to.have.property('comparison');
    expect(result).to.have.property('killed');
  });
  
  it("should compare test results", () => {
    const original = {
      success: true,
      status: 200,
      body: { id: 1, name: 'John' },
      headers: { 'Content-Type': 'application/json' }
    };
    
    const mutated = {
      success: true,
      status: 404,
      body: { id: 1, name: 'John' },
      headers: { 'Content-Type': 'application/json' }
    };
    
    const comparison = runner.compareResults(original, mutated);
    
    expect(comparison.different).to.be.true;
    expect(comparison.differences).to.have.length(1);
    expect(comparison.differences[0].field).to.equal('status');
  });
  
  it("should analyze mutation results", () => {
    const mockResults = [
      { killed: true, mutation: { operator: 'status_code_change' } },
      { killed: false, mutation: { operator: 'status_code_change' } },
      { killed: true, mutation: { operator: 'method_change' } },
      { error: 'Network error', mutation: { operator: 'method_change' } }
    ];
    
    const analysisResult = analysis.analyzeResults(mockResults);
    
    expect(analysisResult.totalMutations).to.equal(4);
    expect(analysisResult.killedMutations).to.equal(2);
    expect(analysisResult.survivedMutations).to.equal(1);
    expect(analysisResult.errorMutations).to.equal(1);
    expect(analysisResult.mutationScore).to.equal(50);
  });
  
  it("should generate mutation recommendations", () => {
    const mockAnalysis = {
      mutationScore: 60,
      totalMutations: 10,
      killedMutations: 6,
      survivedMutations: 4,
      errorMutations: 0,
      operatorAnalysis: new Map([
        ['status_code_change', { total: 5, killed: 3, survived: 2, errors: 0 }],
        ['method_change', { total: 5, killed: 3, survived: 2, errors: 0 }]
      ])
    };
    
    const recommendations = analysis.generateRecommendations(mockAnalysis);
    
    expect(recommendations).to.be.an('array');
    expect(recommendations.length).to.be.greaterThan(0);
    
    const scoreRec = recommendations.find(r => r.type === 'mutation_score');
    expect(scoreRec).to.exist;
    expect(scoreRec.severity).to.equal('high');
  });
  
  it("should generate detailed mutation report", () => {
    const mockAnalysis = {
      mutationScore: 85,
      totalMutations: 20,
      killedMutations: 17,
      survivedMutations: 3,
      errorMutations: 0,
      operatorAnalysis: new Map([
        ['status_code_change', { total: 10, killed: 9, survived: 1, errors: 0 }],
        ['method_change', { total: 10, killed: 8, survived: 2, errors: 0 }]
      ]),
      recommendations: []
    };
    
    const report = analysis.generateReport(mockAnalysis);
    
    expect(report).to.have.property('summary');
    expect(report).to.have.property('operatorBreakdown');
    expect(report).to.have.property('recommendations');
    expect(report).to.have.property('quality');
    
    expect(report.summary.mutationScore).to.equal(85);
    expect(report.quality).to.equal('good');
  });
});

export { 
  APIMutationOperators, 
  MutationTestGenerator, 
  MutationTestRunner, 
  MutationAnalysis 
};




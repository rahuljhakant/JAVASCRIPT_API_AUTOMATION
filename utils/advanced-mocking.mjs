/**
 * ADVANCED MOCKING AND STUBBING
 * Comprehensive mocking capabilities for API testing
 * 
 * Features:
 * - HTTP request mocking with nock
 * - Function stubbing with sinon
 * - Mock data generation
 * - Response simulation
 * - Error scenario testing
 */

import { expect } from "chai";
import nock from "nock";
import sinon from "sinon";

console.log("=== ADVANCED MOCKING AND STUBBING ===");

// HTTP Mock Manager
class HTTPMockManager {
  constructor() {
    this.mocks = new Map();
    this.activeMocks = [];
    this.defaultBaseUrl = 'https://api.example.com';
  }
  
  // Create HTTP mock
  createMock(baseUrl = this.defaultBaseUrl) {
    const mock = nock(baseUrl);
    this.activeMocks.push(mock);
    return mock;
  }
  
  // Mock GET request
  mockGet(path, response, options = {}) {
    const mock = this.createMock(options.baseUrl);
    const mockInstance = mock.get(path);
    
    if (options.query) {
      mockInstance.query(options.query);
    }
    
    if (options.headers) {
      mockInstance.matchHeader(options.headers);
    }
    
    if (options.delay) {
      mockInstance.delay(options.delay);
    }
    
    if (options.times) {
      mockInstance.times(options.times);
    }
    
    if (options.persist) {
      mockInstance.persist();
    }
    
    return mockInstance.reply(options.status || 200, response);
  }
  
  // Mock POST request
  mockPost(path, requestBody, response, options = {}) {
    const mock = this.createMock(options.baseUrl);
    const mockInstance = mock.post(path);
    
    if (requestBody) {
      mockInstance.matchHeader('content-type', 'application/json');
    }
    
    if (options.headers) {
      mockInstance.matchHeader(options.headers);
    }
    
    if (options.delay) {
      mockInstance.delay(options.delay);
    }
    
    if (options.times) {
      mockInstance.times(options.times);
    }
    
    if (options.persist) {
      mockInstance.persist();
    }
    
    return mockInstance.reply(options.status || 201, response);
  }
  
  // Mock PUT request
  mockPut(path, requestBody, response, options = {}) {
    const mock = this.createMock(options.baseUrl);
    const mockInstance = mock.put(path);
    
    if (requestBody) {
      mockInstance.matchHeader('content-type', 'application/json');
    }
    
    if (options.headers) {
      mockInstance.matchHeader(options.headers);
    }
    
    if (options.delay) {
      mockInstance.delay(options.delay);
    }
    
    if (options.times) {
      mockInstance.times(options.times);
    }
    
    if (options.persist) {
      mockInstance.persist();
    }
    
    return mockInstance.reply(options.status || 200, response);
  }
  
  // Mock DELETE request
  mockDelete(path, response, options = {}) {
    const mock = this.createMock(options.baseUrl);
    const mockInstance = mock.delete(path);
    
    if (options.headers) {
      mockInstance.matchHeader(options.headers);
    }
    
    if (options.delay) {
      mockInstance.delay(options.delay);
    }
    
    if (options.times) {
      mockInstance.times(options.times);
    }
    
    if (options.persist) {
      mockInstance.persist();
    }
    
    return mockInstance.reply(options.status || 204, response);
  }
  
  // Mock error response
  mockError(path, method = 'GET', error, options = {}) {
    const mock = this.createMock(options.baseUrl);
    const mockInstance = mock[method.toLowerCase()](path);
    
    if (options.headers) {
      mockInstance.matchHeader(options.headers);
    }
    
    if (options.delay) {
      mockInstance.delay(options.delay);
    }
    
    if (options.times) {
      mockInstance.times(options.times);
    }
    
    if (options.persist) {
      mockInstance.persist();
    }
    
    return mockInstance.replyWithError(error);
  }
  
  // Mock timeout
  mockTimeout(path, method = 'GET', options = {}) {
    const mock = this.createMock(options.baseUrl);
    const mockInstance = mock[method.toLowerCase()](path);
    
    if (options.headers) {
      mockInstance.matchHeader(options.headers);
    }
    
    if (options.times) {
      mockInstance.times(options.times);
    }
    
    if (options.persist) {
      mockInstance.persist();
    }
    
    return mockInstance.replyWithError({ code: 'ETIMEDOUT' });
  }
  
  // Mock network error
  mockNetworkError(path, method = 'GET', options = {}) {
    const mock = this.createMock(options.baseUrl);
    const mockInstance = mock[method.toLowerCase()](path);
    
    if (options.headers) {
      mockInstance.matchHeader(options.headers);
    }
    
    if (options.times) {
      mockInstance.times(options.times);
    }
    
    if (options.persist) {
      mockInstance.persist();
    }
    
    return mockInstance.replyWithError({ code: 'ECONNREFUSED' });
  }
  
  // Mock rate limiting
  mockRateLimit(path, method = 'GET', options = {}) {
    const mock = this.createMock(options.baseUrl);
    const mockInstance = mock[method.toLowerCase()](path);
    
    if (options.headers) {
      mockInstance.matchHeader(options.headers);
    }
    
    if (options.times) {
      mockInstance.times(options.times);
    }
    
    if (options.persist) {
      mockInstance.persist();
    }
    
    return mockInstance.reply(429, { error: 'Rate limit exceeded' }, {
      'Retry-After': '60',
      'X-RateLimit-Limit': '100',
      'X-RateLimit-Remaining': '0',
      'X-RateLimit-Reset': Math.floor(Date.now() / 1000) + 60
    });
  }
  
  // Mock authentication failure
  mockAuthFailure(path, method = 'GET', options = {}) {
    const mock = this.createMock(options.baseUrl);
    const mockInstance = mock[method.toLowerCase()](path);
    
    if (options.headers) {
      mockInstance.matchHeader(options.headers);
    }
    
    if (options.times) {
      mockInstance.times(options.times);
    }
    
    if (options.persist) {
      mockInstance.persist();
    }
    
    return mockInstance.reply(401, { error: 'Unauthorized' });
  }
  
  // Mock validation error
  mockValidationError(path, method = 'POST', errors, options = {}) {
    const mock = this.createMock(options.baseUrl);
    const mockInstance = mock[method.toLowerCase()](path);
    
    if (options.headers) {
      mockInstance.matchHeader(options.headers);
    }
    
    if (options.times) {
      mockInstance.times(options.times);
    }
    
    if (options.persist) {
      mockInstance.persist();
    }
    
    return mockInstance.reply(422, { errors });
  }
  
  // Mock server error
  mockServerError(path, method = 'GET', options = {}) {
    const mock = this.createMock(options.baseUrl);
    const mockInstance = mock[method.toLowerCase()](path);
    
    if (options.headers) {
      mockInstance.matchHeader(options.headers);
    }
    
    if (options.times) {
      mockInstance.times(options.times);
    }
    
    if (options.persist) {
      mockInstance.persist();
    }
    
    return mockInstance.reply(500, { error: 'Internal Server Error' });
  }
  
  // Mock paginated response
  mockPaginated(path, data, options = {}) {
    const page = options.page || 1;
    const perPage = options.perPage || 10;
    const total = options.total || data.length;
    
    const startIndex = (page - 1) * perPage;
    const endIndex = startIndex + perPage;
    const paginatedData = data.slice(startIndex, endIndex);
    
    const response = {
      data: paginatedData,
      meta: {
        pagination: {
          page,
          per_page: perPage,
          total,
          total_pages: Math.ceil(total / perPage)
        }
      }
    };
    
    return this.mockGet(path, response, options);
  }
  
  // Mock streaming response
  mockStreaming(path, data, options = {}) {
    const mock = this.createMock(options.baseUrl);
    const mockInstance = mock.get(path);
    
    if (options.headers) {
      mockInstance.matchHeader(options.headers);
    }
    
    if (options.times) {
      mockInstance.times(options.times);
    }
    
    if (options.persist) {
      mockInstance.persist();
    }
    
    return mockInstance.reply(200, data, {
      'Content-Type': 'application/x-ndjson',
      'Transfer-Encoding': 'chunked'
    });
  }
  
  // Mock WebSocket connection
  mockWebSocket(path, options = {}) {
    const mock = this.createMock(options.baseUrl);
    const mockInstance = mock.get(path);
    
    if (options.headers) {
      mockInstance.matchHeader(options.headers);
    }
    
    if (options.times) {
      mockInstance.times(options.times);
    }
    
    if (options.persist) {
      mockInstance.persist();
    }
    
    return mockInstance.reply(101, null, {
      'Upgrade': 'websocket',
      'Connection': 'Upgrade',
      'Sec-WebSocket-Accept': 'test'
    });
  }
  
  // Verify all mocks were called
  verifyMocks() {
    const results = [];
    
    for (const mock of this.activeMocks) {
      try {
        mock.done();
        results.push({ mock, verified: true, error: null });
      } catch (error) {
        results.push({ mock, verified: false, error: error.message });
      }
    }
    
    return results;
  }
  
  // Clean up all mocks
  cleanup() {
    nock.cleanAll();
    this.activeMocks = [];
    this.mocks.clear();
  }
  
  // Get mock statistics
  getStatistics() {
    return {
      activeMocks: this.activeMocks.length,
      totalMocks: this.mocks.size,
      pendingMocks: nock.pendingMocks().length
    };
  }
}

// Function Stub Manager
class FunctionStubManager {
  constructor() {
    this.stubs = new Map();
    this.spies = new Map();
  }
  
  // Create function stub
  createStub(target, method) {
    const key = `${target.constructor.name}.${method}`;
    const stub = sinon.stub(target, method);
    this.stubs.set(key, stub);
    return stub;
  }
  
  // Create spy
  createSpy(target, method) {
    const key = `${target.constructor.name}.${method}`;
    const spy = sinon.spy(target, method);
    this.spies.set(key, spy);
    return spy;
  }
  
  // Stub with return value
  stubWithReturn(target, method, returnValue) {
    const stub = this.createStub(target, method);
    stub.returns(returnValue);
    return stub;
  }
  
  // Stub with promise
  stubWithPromise(target, method, resolvedValue, rejectedValue = null) {
    const stub = this.createStub(target, method);
    if (rejectedValue) {
      stub.rejects(rejectedValue);
    } else {
      stub.resolves(resolvedValue);
    }
    return stub;
  }
  
  // Stub with callback
  stubWithCallback(target, method, callback) {
    const stub = this.createStub(target, method);
    stub.callsFake(callback);
    return stub;
  }
  
  // Stub with error
  stubWithError(target, method, error) {
    const stub = this.createStub(target, method);
    stub.throws(error);
    return stub;
  }
  
  // Stub with delay
  stubWithDelay(target, method, delay, returnValue) {
    const stub = this.createStub(target, method);
    stub.callsFake(() => {
      return new Promise(resolve => {
        setTimeout(() => resolve(returnValue), delay);
      });
    });
    return stub;
  }
  
  // Stub with conditional behavior
  stubWithCondition(target, method, condition, trueValue, falseValue) {
    const stub = this.createStub(target, method);
    stub.callsFake((...args) => {
      return condition(...args) ? trueValue : falseValue;
    });
    return stub;
  }
  
  // Stub with call count limit
  stubWithCallLimit(target, method, maxCalls, returnValue, errorAfterLimit) {
    const stub = this.createStub(target, method);
    let callCount = 0;
    
    stub.callsFake(() => {
      callCount++;
      if (callCount > maxCalls) {
        if (errorAfterLimit) {
          throw new Error('Call limit exceeded');
        }
        return null;
      }
      return returnValue;
    });
    
    return stub;
  }
  
  // Verify stub calls
  verifyStub(target, method, expectedCalls) {
    const key = `${target.constructor.name}.${method}`;
    const stub = this.stubs.get(key);
    
    if (!stub) {
      throw new Error(`Stub not found: ${key}`);
    }
    
    if (expectedCalls) {
      expect(stub.callCount).to.equal(expectedCalls);
    }
    
    return stub;
  }
  
  // Verify spy calls
  verifySpy(target, method, expectedCalls) {
    const key = `${target.constructor.name}.${method}`;
    const spy = this.spies.get(key);
    
    if (!spy) {
      throw new Error(`Spy not found: ${key}`);
    }
    
    if (expectedCalls) {
      expect(spy.callCount).to.equal(expectedCalls);
    }
    
    return spy;
  }
  
  // Get stub call history
  getStubHistory(target, method) {
    const key = `${target.constructor.name}.${method}`;
    const stub = this.stubs.get(key);
    
    if (!stub) {
      throw new Error(`Stub not found: ${key}`);
    }
    
    return stub.getCalls();
  }
  
  // Get spy call history
  getSpyHistory(target, method) {
    const key = `${target.constructor.name}.${method}`;
    const spy = this.spies.get(key);
    
    if (!spy) {
      throw new Error(`Spy not found: ${key}`);
    }
    
    return spy.getCalls();
  }
  
  // Restore all stubs and spies
  restoreAll() {
    for (const stub of this.stubs.values()) {
      stub.restore();
    }
    
    for (const spy of this.spies.values()) {
      spy.restore();
    }
    
    this.stubs.clear();
    this.spies.clear();
  }
  
  // Get statistics
  getStatistics() {
    return {
      activeStubs: this.stubs.size,
      activeSpies: this.spies.size,
      totalCalls: Array.from(this.stubs.values()).reduce((sum, stub) => sum + stub.callCount, 0)
    };
  }
}

// Mock Data Generator
class MockDataGenerator {
  constructor() {
    this.templates = new Map();
    this.setupTemplates();
  }
  
  // Setup data templates
  setupTemplates() {
    this.templates.set('user', {
      id: () => Math.floor(Math.random() * 10000),
      name: () => `User ${Math.floor(Math.random() * 1000)}`,
      email: () => `user${Math.floor(Math.random() * 1000)}@example.com`,
      active: () => Math.random() > 0.5,
      createdAt: () => new Date().toISOString()
    });
    
    this.templates.set('product', {
      id: () => Math.floor(Math.random() * 10000),
      name: () => `Product ${Math.floor(Math.random() * 1000)}`,
      price: () => Math.floor(Math.random() * 1000) + 10,
      category: () => ['electronics', 'clothing', 'books', 'home'][Math.floor(Math.random() * 4)],
      inStock: () => Math.random() > 0.3
    });
    
    this.templates.set('order', {
      id: () => Math.floor(Math.random() * 10000),
      userId: () => Math.floor(Math.random() * 1000),
      total: () => Math.floor(Math.random() * 1000) + 10,
      status: () => ['pending', 'processing', 'shipped', 'delivered'][Math.floor(Math.random() * 4)],
      items: () => Array.from({ length: Math.floor(Math.random() * 5) + 1 }, () => ({
        productId: Math.floor(Math.random() * 1000),
        quantity: Math.floor(Math.random() * 10) + 1,
        price: Math.floor(Math.random() * 100) + 10
      }))
    });
  }
  
  // Generate mock data
  generate(template, count = 1, overrides = {}) {
    const templateData = this.templates.get(template);
    if (!templateData) {
      throw new Error(`Template not found: ${template}`);
    }
    
    if (count === 1) {
      return this.generateSingle(templateData, overrides);
    }
    
    return Array.from({ length: count }, () => this.generateSingle(templateData, overrides));
  }
  
  // Generate single item
  generateSingle(templateData, overrides) {
    const data = {};
    
    for (const [key, generator] of Object.entries(templateData)) {
      data[key] = generator();
    }
    
    return { ...data, ...overrides };
  }
  
  // Add custom template
  addTemplate(name, template) {
    this.templates.set(name, template);
  }
  
  // Generate error response
  generateErrorResponse(type, message, details = {}) {
    const errorTypes = {
      validation: { status: 422, code: 'VALIDATION_ERROR' },
      authentication: { status: 401, code: 'AUTH_ERROR' },
      authorization: { status: 403, code: 'AUTHZ_ERROR' },
      notFound: { status: 404, code: 'NOT_FOUND' },
      conflict: { status: 409, code: 'CONFLICT' },
      server: { status: 500, code: 'SERVER_ERROR' }
    };
    
    const errorType = errorTypes[type] || errorTypes.server;
    
    return {
      error: {
        code: errorType.code,
        message,
        details,
        timestamp: new Date().toISOString()
      }
    };
  }
  
  // Generate paginated response
  generatePaginatedResponse(data, page = 1, perPage = 10) {
    const startIndex = (page - 1) * perPage;
    const endIndex = startIndex + perPage;
    const paginatedData = data.slice(startIndex, endIndex);
    
    return {
      data: paginatedData,
      meta: {
        pagination: {
          page,
          per_page: perPage,
          total: data.length,
          total_pages: Math.ceil(data.length / perPage)
        }
      }
    };
  }
}

// Mock Scenario Builder
class MockScenarioBuilder {
  constructor() {
    this.httpMock = new HTTPMockManager();
    this.functionStub = new FunctionStubManager();
    this.dataGenerator = new MockDataGenerator();
    this.scenarios = new Map();
  }
  
  // Create scenario
  createScenario(name) {
    const scenario = {
      name,
      httpMocks: [],
      functionStubs: [],
      setup: [],
      teardown: []
    };
    
    this.scenarios.set(name, scenario);
    return scenario;
  }
  
  // Add HTTP mock to scenario
  addHttpMock(scenarioName, mockConfig) {
    const scenario = this.scenarios.get(scenarioName);
    if (!scenario) {
      throw new Error(`Scenario not found: ${scenarioName}`);
    }
    
    scenario.httpMocks.push(mockConfig);
    return this;
  }
  
  // Add function stub to scenario
  addFunctionStub(scenarioName, stubConfig) {
    const scenario = this.scenarios.get(scenarioName);
    if (!scenario) {
      throw new Error(`Scenario not found: ${scenarioName}`);
    }
    
    scenario.functionStubs.push(stubConfig);
    return this;
  }
  
  // Add setup function
  addSetup(scenarioName, setupFunction) {
    const scenario = this.scenarios.get(scenarioName);
    if (!scenario) {
      throw new Error(`Scenario not found: ${scenarioName}`);
    }
    
    scenario.setup.push(setupFunction);
    return this;
  }
  
  // Add teardown function
  addTeardown(scenarioName, teardownFunction) {
    const scenario = this.scenarios.get(scenarioName);
    if (!scenario) {
      throw new Error(`Scenario not found: ${scenarioName}`);
    }
    
    scenario.teardown.push(teardownFunction);
    return this;
  }
  
  // Setup scenario
  async setupScenario(scenarioName) {
    const scenario = this.scenarios.get(scenarioName);
    if (!scenario) {
      throw new Error(`Scenario not found: ${scenarioName}`);
    }
    
    // Setup HTTP mocks
    for (const mockConfig of scenario.httpMocks) {
      this.setupHttpMock(mockConfig);
    }
    
    // Setup function stubs
    for (const stubConfig of scenario.functionStubs) {
      this.setupFunctionStub(stubConfig);
    }
    
    // Run setup functions
    for (const setupFunction of scenario.setup) {
      await setupFunction();
    }
  }
  
  // Teardown scenario
  async teardownScenario(scenarioName) {
    const scenario = this.scenarios.get(scenarioName);
    if (!scenario) {
      throw new Error(`Scenario not found: ${scenarioName}`);
    }
    
    // Run teardown functions
    for (const teardownFunction of scenario.teardown) {
      await teardownFunction();
    }
    
    // Cleanup mocks and stubs
    this.httpMock.cleanup();
    this.functionStub.restoreAll();
  }
  
  // Setup HTTP mock
  setupHttpMock(mockConfig) {
    const { method, path, response, options } = mockConfig;
    
    switch (method.toUpperCase()) {
      case 'GET':
        return this.httpMock.mockGet(path, response, options);
      case 'POST':
        return this.httpMock.mockPost(path, mockConfig.requestBody, response, options);
      case 'PUT':
        return this.httpMock.mockPut(path, mockConfig.requestBody, response, options);
      case 'DELETE':
        return this.httpMock.mockDelete(path, response, options);
      default:
        throw new Error(`Unsupported HTTP method: ${method}`);
    }
  }
  
  // Setup function stub
  setupFunctionStub(stubConfig) {
    const { target, method, behavior, value } = stubConfig;
    
    switch (behavior) {
      case 'return':
        return this.functionStub.stubWithReturn(target, method, value);
      case 'promise':
        return this.functionStub.stubWithPromise(target, method, value);
      case 'error':
        return this.functionStub.stubWithError(target, method, value);
      case 'callback':
        return this.functionStub.stubWithCallback(target, method, value);
      default:
        throw new Error(`Unsupported stub behavior: ${behavior}`);
    }
  }
  
  // Get scenario
  getScenario(scenarioName) {
    return this.scenarios.get(scenarioName);
  }
  
  // Get all scenarios
  getAllScenarios() {
    return Array.from(this.scenarios.values());
  }
  
  // Cleanup all scenarios
  cleanupAll() {
    this.httpMock.cleanup();
    this.functionStub.restoreAll();
    this.scenarios.clear();
  }
}

// Exercises and Tests
describe("Advanced Mocking and Stubbing", () => {
  let httpMock;
  let functionStub;
  let dataGenerator;
  let scenarioBuilder;
  
  beforeEach(() => {
    httpMock = new HTTPMockManager();
    functionStub = new FunctionStubManager();
    dataGenerator = new MockDataGenerator();
    scenarioBuilder = new MockScenarioBuilder();
  });
  
  afterEach(() => {
    httpMock.cleanup();
    functionStub.restoreAll();
    scenarioBuilder.cleanupAll();
  });
  
  it("should create HTTP mocks", () => {
    const mock = httpMock.mockGet('/users', { users: [] });
    expect(mock).to.exist;
  });
  
  it("should mock GET request with response", () => {
    const response = { id: 1, name: 'John Doe' };
    httpMock.mockGet('/users/1', response);
    
    // In real test, you would make actual HTTP request here
    expect(httpMock.getStatistics().activeMocks).to.equal(1);
  });
  
  it("should mock POST request with request body", () => {
    const requestBody = { name: 'Jane Doe', email: 'jane@example.com' };
    const response = { id: 2, ...requestBody };
    
    httpMock.mockPost('/users', requestBody, response);
    
    expect(httpMock.getStatistics().activeMocks).to.equal(1);
  });
  
  it("should mock error responses", () => {
    httpMock.mockError('/users/999', 'GET', { code: 'NOT_FOUND' });
    
    expect(httpMock.getStatistics().activeMocks).to.equal(1);
  });
  
  it("should mock rate limiting", () => {
    httpMock.mockRateLimit('/api/endpoint', 'GET');
    
    expect(httpMock.getStatistics().activeMocks).to.equal(1);
  });
  
  it("should mock authentication failure", () => {
    httpMock.mockAuthFailure('/protected', 'GET');
    
    expect(httpMock.getStatistics().activeMocks).to.equal(1);
  });
  
  it("should mock validation errors", () => {
    const errors = [
      { field: 'email', message: 'Invalid email format' },
      { field: 'name', message: 'Name is required' }
    ];
    
    httpMock.mockValidationError('/users', 'POST', errors);
    
    expect(httpMock.getStatistics().activeMocks).to.equal(1);
  });
  
  it("should mock paginated responses", () => {
    const data = Array.from({ length: 25 }, (_, i) => ({ id: i + 1, name: `User ${i + 1}` }));
    httpMock.mockPaginated('/users', data, { page: 1, perPage: 10 });
    
    expect(httpMock.getStatistics().activeMocks).to.equal(1);
  });
  
  it("should create function stubs", () => {
    const target = { method: () => 'original' };
    const stub = functionStub.createStub(target, 'method');
    
    expect(stub).to.exist;
    expect(stub.callCount).to.equal(0);
  });
  
  it("should stub with return value", () => {
    const target = { method: () => 'original' };
    const stub = functionStub.stubWithReturn(target, 'method', 'stubbed');
    
    expect(target.method()).to.equal('stubbed');
    expect(stub.callCount).to.equal(1);
  });
  
  it("should stub with promise", async () => {
    const target = { method: () => Promise.resolve('original') };
    const stub = functionStub.stubWithPromise(target, 'method', 'resolved');
    
    const result = await target.method();
    expect(result).to.equal('resolved');
    expect(stub.callCount).to.equal(1);
  });
  
  it("should stub with error", () => {
    const target = { method: () => 'original' };
    const error = new Error('Stubbed error');
    const stub = functionStub.stubWithError(target, 'method', error);
    
    expect(() => target.method()).to.throw('Stubbed error');
    expect(stub.callCount).to.equal(1);
  });
  
  it("should stub with callback", () => {
    const target = { method: () => 'original' };
    const stub = functionStub.stubWithCallback(target, 'method', (arg) => `callback: ${arg}`);
    
    expect(target.method('test')).to.equal('callback: test');
    expect(stub.callCount).to.equal(1);
  });
  
  it("should stub with delay", async () => {
    const target = { method: () => 'original' };
    const stub = functionStub.stubWithDelay(target, 'method', 100, 'delayed');
    
    const startTime = Date.now();
    const result = await target.method();
    const endTime = Date.now();
    
    expect(result).to.equal('delayed');
    expect(endTime - startTime).to.be.at.least(100);
    expect(stub.callCount).to.equal(1);
  });
  
  it("should create spies", () => {
    const target = { method: () => 'original' };
    const spy = functionStub.createSpy(target, 'method');
    
    target.method();
    expect(spy.callCount).to.equal(1);
  });
  
  it("should generate mock data", () => {
    const user = dataGenerator.generate('user');
    
    expect(user).to.have.property('id');
    expect(user).to.have.property('name');
    expect(user).to.have.property('email');
    expect(user).to.have.property('active');
  });
  
  it("should generate multiple mock data items", () => {
    const users = dataGenerator.generate('user', 3);
    
    expect(users).to.be.an('array');
    expect(users).to.have.length(3);
    users.forEach(user => {
      expect(user).to.have.property('id');
      expect(user).to.have.property('name');
    });
  });
  
  it("should generate error responses", () => {
    const errorResponse = dataGenerator.generateErrorResponse('validation', 'Invalid input', {
      field: 'email',
      value: 'invalid-email'
    });
    
    expect(errorResponse.error.code).to.equal('VALIDATION_ERROR');
    expect(errorResponse.error.message).to.equal('Invalid input');
    expect(errorResponse.error.details.field).to.equal('email');
  });
  
  it("should generate paginated responses", () => {
    const data = Array.from({ length: 25 }, (_, i) => ({ id: i + 1, name: `User ${i + 1}` }));
    const paginatedResponse = dataGenerator.generatePaginatedResponse(data, 2, 10);
    
    expect(paginatedResponse.data).to.have.length(10);
    expect(paginatedResponse.meta.pagination.page).to.equal(2);
    expect(paginatedResponse.meta.pagination.total).to.equal(25);
  });
  
  it("should create and setup scenarios", async () => {
    const scenario = scenarioBuilder.createScenario('user-scenario');
    
    scenarioBuilder.addHttpMock('user-scenario', {
      method: 'GET',
      path: '/users/1',
      response: { id: 1, name: 'John Doe' }
    });
    
    scenarioBuilder.addFunctionStub('user-scenario', {
      target: { method: () => 'original' },
      method: 'method',
      behavior: 'return',
      value: 'stubbed'
    });
    
    await scenarioBuilder.setupScenario('user-scenario');
    
    const setupScenario = scenarioBuilder.getScenario('user-scenario');
    expect(setupScenario.httpMocks).to.have.length(1);
    expect(setupScenario.functionStubs).to.have.length(1);
  });
  
  it("should teardown scenarios", async () => {
    const scenario = scenarioBuilder.createScenario('test-scenario');
    
    scenarioBuilder.addHttpMock('test-scenario', {
      method: 'GET',
      path: '/test',
      response: { success: true }
    });
    
    await scenarioBuilder.setupScenario('test-scenario');
    await scenarioBuilder.teardownScenario('test-scenario');
    
    expect(httpMock.getStatistics().activeMocks).to.equal(0);
    expect(functionStub.getStatistics().activeStubs).to.equal(0);
  });
  
  it("should get mock statistics", () => {
    httpMock.mockGet('/test1', {});
    httpMock.mockGet('/test2', {});
    
    const stats = httpMock.getStatistics();
    expect(stats.activeMocks).to.equal(2);
  });
  
  it("should get stub statistics", () => {
    const target = { method: () => 'original' };
    functionStub.createStub(target, 'method');
    functionStub.createSpy(target, 'method');
    
    const stats = functionStub.getStatistics();
    expect(stats.activeStubs).to.equal(1);
    expect(stats.activeSpies).to.equal(1);
  });
});

export { 
  HTTPMockManager, 
  FunctionStubManager, 
  MockDataGenerator, 
  MockScenarioBuilder 
};




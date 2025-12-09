/**
 * PHASE 2.5: DESIGN PATTERNS FOUNDATION
 * Module 1: Creational Patterns
 * Lesson 2: Builder Pattern - Request Builder
 * 
 * Learning Objectives:
 * - Understand the Builder Pattern
 * - Build complex API requests step by step
 * - Create flexible and readable request construction
 */

import { expect } from "chai";

console.log("=== BUILDER PATTERN: REQUEST BUILDER ===");

// Request data structure
class APIRequest {
  constructor() {
    this.method = 'GET';
    this.url = '';
    this.headers = {};
    this.body = null;
    this.params = {};
    this.timeout = 5000;
    this.retries = 0;
    this.retryDelay = 1000;
    this.auth = null;
    this.cookies = {};
    this.followRedirects = true;
    this.validateSSL = true;
  }
}

// Base Builder class
class RequestBuilder {
  constructor() {
    this.request = new APIRequest();
  }
  
  // HTTP Method
  method(method) {
    this.request.method = method.toUpperCase();
    return this;
  }
  
  // URL
  url(url) {
    this.request.url = url;
    return this;
  }
  
  // Headers
  headers(headers) {
    this.request.headers = { ...this.request.headers, ...headers };
    return this;
  }
  
  header(key, value) {
    this.request.headers[key] = value;
    return this;
  }
  
  // Body
  body(body) {
    this.request.body = body;
    return this;
  }
  
  jsonBody(data) {
    this.request.body = JSON.stringify(data);
    this.request.headers['Content-Type'] = 'application/json';
    return this;
  }
  
  formBody(data) {
    this.request.body = new URLSearchParams(data).toString();
    this.request.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    return this;
  }
  
  // Query Parameters
  params(params) {
    this.request.params = { ...this.request.params, ...params };
    return this;
  }
  
  param(key, value) {
    this.request.params[key] = value;
    return this;
  }
  
  // Timeout
  timeout(ms) {
    this.request.timeout = ms;
    return this;
  }
  
  // Retry Configuration
  retries(count) {
    this.request.retries = count;
    return this;
  }
  
  retryDelay(ms) {
    this.request.retryDelay = ms;
    return this;
  }
  
  // Authentication
  auth(type, credentials) {
    this.request.auth = { type, credentials };
    return this;
  }
  
  bearerToken(token) {
    this.request.headers['Authorization'] = `Bearer ${token}`;
    return this;
  }
  
  basicAuth(username, password) {
    const credentials = Buffer.from(`${username}:${password}`).toString('base64');
    this.request.headers['Authorization'] = `Basic ${credentials}`;
    return this;
  }
  
  apiKey(key, headerName = 'X-API-Key') {
    this.request.headers[headerName] = key;
    return this;
  }
  
  // Cookies
  cookies(cookieObj) {
    this.request.cookies = { ...this.request.cookies, ...cookieObj };
    return this;
  }
  
  cookie(name, value) {
    this.request.cookies[name] = value;
    return this;
  }
  
  // SSL and Redirects
  followRedirects(follow = true) {
    this.request.followRedirects = follow;
    return this;
  }
  
  validateSSL(validate = true) {
    this.request.validateSSL = validate;
    return this;
  }
  
  // Build the final request
  build() {
    return this.request;
  }
}

// Specialized Builders
class GETRequestBuilder extends RequestBuilder {
  constructor() {
    super();
    this.method('GET');
  }
  
  // GET-specific methods
  withPagination(page, limit) {
    return this.param('page', page).param('limit', limit);
  }
  
  withSort(field, order = 'asc') {
    return this.param('sort', `${field}:${order}`);
  }
  
  withFilter(filters) {
    Object.entries(filters).forEach(([key, value]) => {
      this.param(key, value);
    });
    return this;
  }
}

class POSTRequestBuilder extends RequestBuilder {
  constructor() {
    super();
    this.method('POST');
  }
  
  // POST-specific methods
  withUserData(userData) {
    return this.jsonBody(userData);
  }
  
  withFileUpload(filePath) {
    // In real implementation, this would handle file uploads
    this.request.body = filePath;
    this.request.headers['Content-Type'] = 'multipart/form-data';
    return this;
  }
}

class PUTRequestBuilder extends RequestBuilder {
  constructor() {
    super();
    this.method('PUT');
  }
  
  // PUT-specific methods
  withFullUpdate(data) {
    return this.jsonBody(data);
  }
}

class PATCHRequestBuilder extends RequestBuilder {
  constructor() {
    super();
    this.method('PATCH');
  }
  
  // PATCH-specific methods
  withPartialUpdate(updates) {
    return this.jsonBody(updates);
  }
}

class DELETERequestBuilder extends RequestBuilder {
  constructor() {
    super();
    this.method('DELETE');
  }
  
  // DELETE-specific methods
  withConfirmation(confirm = true) {
    return this.param('confirm', confirm);
  }
}

// Factory for specialized builders
class RequestBuilderFactory {
  static create(type) {
    switch (type.toLowerCase()) {
      case 'get':
        return new GETRequestBuilder();
      case 'post':
        return new POSTRequestBuilder();
      case 'put':
        return new PUTRequestBuilder();
      case 'patch':
        return new PATCHRequestBuilder();
      case 'delete':
        return new DELETERequestBuilder();
      default:
        return new RequestBuilder();
    }
  }
  
  // Predefined request templates
  static createUserCreationRequest(userData) {
    return new POSTRequestBuilder()
      .url('/api/users')
      .jsonBody(userData)
      .header('Accept', 'application/json')
      .timeout(10000);
  }
  
  static createUserRetrievalRequest(userId, includeProfile = false) {
    const builder = new GETRequestBuilder()
      .url(`/api/users/${userId}`)
      .header('Accept', 'application/json');
    
    if (includeProfile) {
      builder.param('include', 'profile');
    }
    
    return builder;
  }
  
  static createUserUpdateRequest(userId, updates) {
    return new PATCHRequestBuilder()
      .url(`/api/users/${userId}`)
      .withPartialUpdate(updates)
      .header('Accept', 'application/json');
  }
  
  static createUserDeletionRequest(userId) {
    return new DELETERequestBuilder()
      .url(`/api/users/${userId}`)
      .withConfirmation(true)
      .header('Accept', 'application/json');
  }
}

// Exercises and Tests
describe("Builder Pattern - Request Builder", () => {
  it("should build a simple GET request", () => {
    const request = new RequestBuilder()
      .method('GET')
      .url('/api/users')
      .build();
    
    expect(request.method).to.equal('GET');
    expect(request.url).to.equal('/api/users');
    expect(request.headers).to.be.an('object');
  });

  it("should build a POST request with JSON body", () => {
    const userData = { name: 'John Doe', email: 'john@example.com' };
    const request = new RequestBuilder()
      .method('POST')
      .url('/api/users')
      .jsonBody(userData)
      .build();
    
    expect(request.method).to.equal('POST');
    expect(request.url).to.equal('/api/users');
    expect(request.body).to.equal(JSON.stringify(userData));
    expect(request.headers['Content-Type']).to.equal('application/json');
  });

  it("should build a request with authentication", () => {
    const request = new RequestBuilder()
      .method('GET')
      .url('/api/protected')
      .bearerToken('token123')
      .build();
    
    expect(request.headers['Authorization']).to.equal('Bearer token123');
  });

  it("should build a request with query parameters", () => {
    const request = new RequestBuilder()
      .method('GET')
      .url('/api/users')
      .param('page', 1)
      .param('limit', 10)
      .param('status', 'active')
      .build();
    
    expect(request.params).to.deep.equal({
      page: 1,
      limit: 10,
      status: 'active'
    });
  });

  it("should build a request with timeout and retries", () => {
    const request = new RequestBuilder()
      .method('POST')
      .url('/api/users')
      .timeout(15000)
      .retries(3)
      .retryDelay(2000)
      .build();
    
    expect(request.timeout).to.equal(15000);
    expect(request.retries).to.equal(3);
    expect(request.retryDelay).to.equal(2000);
  });
});

// Specialized Builder Tests
describe("Specialized Request Builders", () => {
  it("should build GET request with pagination", () => {
    const request = new GETRequestBuilder()
      .url('/api/users')
      .withPagination(2, 20)
      .withSort('created_at', 'desc')
      .build();
    
    expect(request.method).to.equal('GET');
    expect(request.params.page).to.equal(2);
    expect(request.params.limit).to.equal(20);
    expect(request.params.sort).to.equal('created_at:desc');
  });

  it("should build POST request with user data", () => {
    const userData = { name: 'Jane Doe', email: 'jane@example.com' };
    const request = new POSTRequestBuilder()
      .url('/api/users')
      .withUserData(userData)
      .build();
    
    expect(request.method).to.equal('POST');
    expect(request.body).to.equal(JSON.stringify(userData));
  });

  it("should build PATCH request with partial updates", () => {
    const updates = { status: 'active', lastLogin: new Date().toISOString() };
    const request = new PATCHRequestBuilder()
      .url('/api/users/123')
      .withPartialUpdate(updates)
      .build();
    
    expect(request.method).to.equal('PATCH');
    expect(request.body).to.equal(JSON.stringify(updates));
  });

  it("should build DELETE request with confirmation", () => {
    const request = new DELETERequestBuilder()
      .url('/api/users/123')
      .withConfirmation(true)
      .build();
    
    expect(request.method).to.equal('DELETE');
    expect(request.params.confirm).to.be.true;
  });
});

// Factory Tests
describe("Request Builder Factory", () => {
  it("should create specialized builders", () => {
    const getBuilder = RequestBuilderFactory.create('get');
    const postBuilder = RequestBuilderFactory.create('post');
    const putBuilder = RequestBuilderFactory.create('put');
    
    expect(getBuilder).to.be.instanceOf(GETRequestBuilder);
    expect(postBuilder).to.be.instanceOf(POSTRequestBuilder);
    expect(putBuilder).to.be.instanceOf(PUTRequestBuilder);
  });

  it("should create predefined request templates", () => {
    const userData = { name: 'Test User', email: 'test@example.com' };
    const createRequest = RequestBuilderFactory.createUserCreationRequest(userData);
    const retrieveRequest = RequestBuilderFactory.createUserRetrievalRequest(123);
    const updateRequest = RequestBuilderFactory.createUserUpdateRequest(123, { status: 'active' });
    const deleteRequest = RequestBuilderFactory.createUserDeletionRequest(123);
    
    expect(createRequest.build().method).to.equal('POST');
    expect(createRequest.build().url).to.equal('/api/users');
    
    expect(retrieveRequest.build().method).to.equal('GET');
    expect(retrieveRequest.build().url).to.equal('/api/users/123');
    
    expect(updateRequest.build().method).to.equal('PATCH');
    expect(updateRequest.build().url).to.equal('/api/users/123');
    
    expect(deleteRequest.build().method).to.equal('DELETE');
    expect(deleteRequest.build().url).to.equal('/api/users/123');
  });
});

// Advanced Builder Patterns
describe("Advanced Builder Patterns", () => {
  it("should chain multiple operations", () => {
    const request = new RequestBuilder()
      .method('POST')
      .url('/api/users')
      .header('Accept', 'application/json')
      .header('User-Agent', 'MyApp/1.0')
      .jsonBody({ name: 'John Doe' })
      .timeout(10000)
      .retries(2)
      .bearerToken('token123')
      .build();
    
    expect(request.method).to.equal('POST');
    expect(request.headers['Accept']).to.equal('application/json');
    expect(request.headers['User-Agent']).to.equal('MyApp/1.0');
    expect(request.timeout).to.equal(10000);
    expect(request.retries).to.equal(2);
    expect(request.headers['Authorization']).to.equal('Bearer token123');
  });

  it("should handle complex authentication scenarios", () => {
    const request = new RequestBuilder()
      .method('GET')
      .url('/api/protected')
      .basicAuth('username', 'password')
      .apiKey('api-key-123', 'X-API-Key')
      .cookie('sessionId', 'session-123')
      .build();
    
    expect(request.headers['Authorization']).to.include('Basic');
    expect(request.headers['X-API-Key']).to.equal('api-key-123');
    expect(request.cookies.sessionId).to.equal('session-123');
  });

  it("should build requests with filters and pagination", () => {
    const request = new GETRequestBuilder()
      .url('/api/users')
      .withPagination(1, 25)
      .withSort('name', 'asc')
      .withFilter({ status: 'active', role: 'user' })
      .header('Accept', 'application/json')
      .timeout(5000)
      .build();
    
    expect(request.params.page).to.equal(1);
    expect(request.params.limit).to.equal(25);
    expect(request.params.sort).to.equal('name:asc');
    expect(request.params.status).to.equal('active');
    expect(request.params.role).to.equal('user');
  });
});

export { 
  RequestBuilder, 
  GETRequestBuilder, 
  POSTRequestBuilder, 
  PUTRequestBuilder, 
  PATCHRequestBuilder, 
  DELETERequestBuilder,
  RequestBuilderFactory 
};

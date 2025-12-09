/**
 * ADVANCED SUPERTEST EXTENSIONS
 * Enhanced Supertest capabilities for comprehensive API testing
 * 
 * Features:
 * - Advanced request/response handling
 * - Custom matchers and assertions
 * - Request/response interceptors
 * - Retry mechanisms with exponential backoff
 * - Request/response caching
 * - Custom timeout handling
 */

import supertest from "supertest";
import { expect } from "chai";

// Enhanced Supertest Client with advanced features
class EnhancedSupertestClient {
  constructor(app, options = {}) {
    this.app = app;
    this.client = supertest(app);
    this.options = {
      timeout: 10000,
      retries: 3,
      retryDelay: 1000,
      cache: false,
      interceptors: [],
      ...options
    };
    this.cache = new Map();
    this.requestHistory = [];
  }
  
  // Enhanced GET request with advanced features
  async get(url, options = {}) {
    return await this.makeRequest('GET', url, null, options);
  }
  
  // Enhanced POST request with advanced features
  async post(url, data = null, options = {}) {
    return await this.makeRequest('POST', url, data, options);
  }
  
  // Enhanced PUT request with advanced features
  async put(url, data = null, options = {}) {
    return await this.makeRequest('PUT', url, data, options);
  }
  
  // Enhanced DELETE request with advanced features
  async delete(url, options = {}) {
    return await this.makeRequest('DELETE', url, null, options);
  }
  
  // Enhanced PATCH request with advanced features
  async patch(url, data = null, options = {}) {
    return await this.makeRequest('PATCH', url, data, options);
  }
  
  // Core request method with all enhancements
  async makeRequest(method, url, data = null, options = {}) {
    const requestOptions = { ...this.options, ...options };
    const requestId = this.generateRequestId();
    
    // Check cache first
    if (requestOptions.cache) {
      const cacheKey = this.generateCacheKey(method, url, data);
      const cachedResponse = this.cache.get(cacheKey);
      if (cachedResponse && !this.isCacheExpired(cachedResponse)) {
        return cachedResponse;
      }
    }
    
    // Apply request interceptors
    const interceptedRequest = await this.applyRequestInterceptors({
      method,
      url,
      data,
      options: requestOptions,
      requestId
    });
    
    let lastError;
    let attempt = 0;
    
    // Retry mechanism with exponential backoff
    while (attempt < requestOptions.retries) {
      try {
        const startTime = Date.now();
        
        let request = this.client[method.toLowerCase()](interceptedRequest.url);
        
        // Apply headers
        if (interceptedRequest.options.headers) {
          Object.entries(interceptedRequest.options.headers).forEach(([key, value]) => {
            request = request.set(key, value);
          });
        }
        
        // Apply query parameters
        if (interceptedRequest.options.query) {
          request = request.query(interceptedRequest.options.query);
        }
        
        // Apply body data
        if (data && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
          request = request.send(data);
        }
        
        // Set timeout
        if (requestOptions.timeout) {
          request = request.timeout(requestOptions.timeout);
        }
        
        const response = await request;
        const endTime = Date.now();
        
        // Enhance response with additional metadata
        const enhancedResponse = this.enhanceResponse(response, {
          requestId,
          startTime,
          endTime,
          attempt,
          method,
          url,
          data
        });
        
        // Apply response interceptors
        const interceptedResponse = await this.applyResponseInterceptors(enhancedResponse);
        
        // Cache response if enabled
        if (requestOptions.cache) {
          this.cache.set(cacheKey, interceptedResponse);
        }
        
        // Record request history
        this.recordRequestHistory(interceptedRequest, interceptedResponse);
        
        return interceptedResponse;
        
      } catch (error) {
        lastError = error;
        attempt++;
        
        if (attempt < requestOptions.retries) {
          const delay = requestOptions.retryDelay * Math.pow(2, attempt - 1);
          await this.sleep(delay);
        }
      }
    }
    
    throw lastError;
  }
  
  // Generate unique request ID
  generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  
  // Generate cache key
  generateCacheKey(method, url, data) {
    return `${method}:${url}:${JSON.stringify(data || {})}`;
  }
  
  // Check if cache is expired
  isCacheExpired(cachedResponse) {
    const cacheExpiry = 5 * 60 * 1000; // 5 minutes
    return Date.now() - cachedResponse.timestamp > cacheExpiry;
  }
  
  // Apply request interceptors
  async applyRequestInterceptors(request) {
    let interceptedRequest = { ...request };
    
    for (const interceptor of this.options.interceptors) {
      if (interceptor.request) {
        interceptedRequest = await interceptor.request(interceptedRequest);
      }
    }
    
    return interceptedRequest;
  }
  
  // Apply response interceptors
  async applyResponseInterceptors(response) {
    let interceptedResponse = { ...response };
    
    for (const interceptor of this.options.interceptors) {
      if (interceptor.response) {
        interceptedResponse = await interceptor.response(interceptedResponse);
      }
    }
    
    return interceptedResponse;
  }
  
  // Enhance response with metadata
  enhanceResponse(response, metadata) {
    return {
      ...response,
      requestId: metadata.requestId,
      responseTime: metadata.endTime - metadata.startTime,
      attempt: metadata.attempt,
      method: metadata.method,
      url: metadata.url,
      timestamp: new Date().toISOString(),
      metadata
    };
  }
  
  // Record request history
  recordRequestHistory(request, response) {
    this.requestHistory.push({
      request: {
        method: request.method,
        url: request.url,
        data: request.data,
        timestamp: new Date().toISOString()
      },
      response: {
        status: response.status,
        responseTime: response.responseTime,
        timestamp: response.timestamp
      }
    });
    
    // Keep only last 100 requests
    if (this.requestHistory.length > 100) {
      this.requestHistory = this.requestHistory.slice(-100);
    }
  }
  
  // Sleep utility
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  // Get request history
  getRequestHistory() {
    return this.requestHistory;
  }
  
  // Clear cache
  clearCache() {
    this.cache.clear();
  }
  
  // Clear request history
  clearHistory() {
    this.requestHistory = [];
  }
}

// Custom Matchers for Enhanced Assertions
class CustomMatchers {
  // Response time matcher
  static responseTime(expectedTime) {
    return function(response) {
      expect(response.responseTime).to.be.lessThan(expectedTime);
    };
  }
  
  // Status code range matcher
  static statusInRange(min, max) {
    return function(response) {
      expect(response.status).to.be.at.least(min).and.at.most(max);
    };
  }
  
  // Header exists matcher
  static hasHeader(headerName) {
    return function(response) {
      expect(response.headers).to.have.property(headerName.toLowerCase());
    };
  }
  
  // JSON schema matcher
  static matchesSchema(schema) {
    return function(response) {
      // In real implementation, use ajv or similar schema validator
      expect(response.body).to.be.an('object');
      // Add schema validation logic here
    };
  }
  
  // Response size matcher
  static responseSize(maxSize) {
    return function(response) {
      const responseSize = JSON.stringify(response.body).length;
      expect(responseSize).to.be.lessThan(maxSize);
    };
  }
  
  // Content type matcher
  static contentType(expectedType) {
    return function(response) {
      expect(response.headers['content-type']).to.include(expectedType);
    };
  }
  
  // Error message matcher
  static hasErrorMessage(expectedMessage) {
    return function(response) {
      expect(response.body).to.have.property('message');
      expect(response.body.message).to.include(expectedMessage);
    };
  }
}

// Request/Response Interceptors
class Interceptors {
  // Authentication interceptor
  static auth(token) {
    return {
      request: (request) => {
        request.options.headers = {
          ...request.options.headers,
          'Authorization': `Bearer ${token}`
        };
        return request;
      }
    };
  }
  
  // Logging interceptor
  static logging(level = 'info') {
    return {
      request: (request) => {
        console.log(`[${level.toUpperCase()}] Request: ${request.method} ${request.url}`);
        return request;
      },
      response: (response) => {
        console.log(`[${level.toUpperCase()}] Response: ${response.status} (${response.responseTime}ms)`);
        return response;
      }
    };
  }
  
  // Rate limiting interceptor
  static rateLimit(requestsPerSecond = 10) {
    let lastRequestTime = 0;
    const minInterval = 1000 / requestsPerSecond;
    
    return {
      request: async (request) => {
        const now = Date.now();
        const timeSinceLastRequest = now - lastRequestTime;
        
        if (timeSinceLastRequest < minInterval) {
          const delay = minInterval - timeSinceLastRequest;
          await new Promise(resolve => setTimeout(resolve, delay));
        }
        
        lastRequestTime = Date.now();
        return request;
      }
    };
  }
  
  // Retry on specific errors interceptor
  static retryOnErrors(errorCodes = [500, 502, 503, 504]) {
    return {
      response: (response) => {
        if (errorCodes.includes(response.status)) {
          throw new Error(`Retryable error: ${response.status}`);
        }
        return response;
      }
    };
  }
}

// Batch Request Handler
class BatchRequestHandler {
  constructor(client) {
    this.client = client;
  }
  
  // Execute multiple requests in parallel
  async executeParallel(requests) {
    const promises = requests.map(request => 
      this.client.makeRequest(request.method, request.url, request.data, request.options)
    );
    
    return await Promise.allSettled(promises);
  }
  
  // Execute requests in sequence
  async executeSequence(requests) {
    const results = [];
    
    for (const request of requests) {
      try {
        const result = await this.client.makeRequest(request.method, request.url, request.data, request.options);
        results.push({ success: true, result });
      } catch (error) {
        results.push({ success: false, error });
        if (request.stopOnError) break;
      }
    }
    
    return results;
  }
  
  // Execute requests with dependencies
  async executeWithDependencies(requests) {
    const results = new Map();
    const executed = new Set();
    
    const executeRequest = async (request) => {
      if (executed.has(request.id)) {
        return results.get(request.id);
      }
      
      // Execute dependencies first
      if (request.dependencies) {
        for (const depId of request.dependencies) {
          const depRequest = requests.find(r => r.id === depId);
          if (depRequest) {
            await executeRequest(depRequest);
          }
        }
      }
      
      // Execute current request
      const result = await this.client.makeRequest(request.method, request.url, request.data, request.options);
      results.set(request.id, result);
      executed.add(request.id);
      
      return result;
    };
    
    // Execute all requests
    for (const request of requests) {
      await executeRequest(request);
    }
    
    return results;
  }
}

// Export enhanced classes
export { 
  EnhancedSupertestClient, 
  CustomMatchers, 
  Interceptors, 
  BatchRequestHandler 
};





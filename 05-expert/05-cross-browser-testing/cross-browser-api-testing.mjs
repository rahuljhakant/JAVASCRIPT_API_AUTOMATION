/**
 * PHASE 5: EXPERT LEVEL
 * Module 5: Cross-Browser Testing
 * Lesson 1: Cross-Browser API Testing
 * 
 * Learning Objectives:
 * - Implement cross-browser API testing
 * - Test API compatibility across different browsers
 * - Handle browser-specific API behaviors
 * - Test WebSocket and real-time APIs
 */

import { expect } from "chai";
import { chromium, firefox, webkit } from "playwright";
import { EnhancedSupertestClient } from "../../utils/advanced-supertest-extensions.mjs";

console.log("=== CROSS-BROWSER API TESTING ===");

// Browser Configuration
const BROWSER_CONFIGS = {
  chromium: {
    name: 'Chromium',
    engine: chromium,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    features: ['fetch', 'websocket', 'serviceworker', 'push']
  },
  firefox: {
    name: 'Firefox',
    engine: firefox,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    features: ['fetch', 'websocket', 'serviceworker']
  },
  webkit: {
    name: 'WebKit',
    engine: webkit,
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    features: ['fetch', 'websocket']
  }
};

// Cross-Browser API Tester
class CrossBrowserAPITester {
  constructor() {
    this.browsers = new Map();
    this.results = new Map();
    this.config = {
      headless: true,
      timeout: 30000,
      viewport: { width: 1280, height: 720 }
    };
  }
  
  // Initialize browsers
  async initializeBrowsers(browserNames = ['chromium', 'firefox', 'webkit']) {
    for (const browserName of browserNames) {
      const browserConfig = BROWSER_CONFIGS[browserName];
      if (!browserConfig) {
        throw new Error(`Unsupported browser: ${browserName}`);
      }
      
      const browser = await browserConfig.engine.launch({
        headless: this.config.headless,
        timeout: this.config.timeout
      });
      
      this.browsers.set(browserName, {
        browser,
        config: browserConfig
      });
    }
  }
  
  // Test API endpoint across browsers
  async testAPIEndpoint(endpoint, options = {}) {
    const results = new Map();
    
    for (const [browserName, browserInfo] of this.browsers.entries()) {
      try {
        const result = await this.testInBrowser(browserName, browserInfo, endpoint, options);
        results.set(browserName, result);
      } catch (error) {
        results.set(browserName, {
          success: false,
          error: error.message,
          browser: browserName
        });
      }
    }
    
    return results;
  }
  
  // Test in specific browser
  async testInBrowser(browserName, browserInfo, endpoint, options) {
    const context = await browserInfo.browser.newContext({
      userAgent: browserInfo.config.userAgent,
      viewport: this.config.viewport
    });
    
    const page = await context.newPage();
    
    try {
      // Set up request interception if needed
      if (options.interceptRequests) {
        await this.setupRequestInterception(page, options.interceptRequests);
      }
      
      // Navigate to test page or make direct API call
      if (options.testPage) {
        await page.goto(options.testPage);
        await page.waitForLoadState('networkidle');
      }
      
      // Execute API test
      const result = await this.executeAPITest(page, endpoint, options);
      
      return {
        success: true,
        browser: browserName,
        result,
        userAgent: browserInfo.config.userAgent,
        features: browserInfo.config.features
      };
      
    } finally {
      await context.close();
    }
  }
  
  // Execute API test in browser
  async executeAPITest(page, endpoint, options) {
    const testScript = `
      async function testAPI() {
        const results = {
          fetch: null,
          xhr: null,
          websocket: null,
          errors: []
        };
        
        try {
          // Test Fetch API
          if (typeof fetch !== 'undefined') {
            const fetchResponse = await fetch('${endpoint}', {
              method: '${options.method || 'GET'}',
              headers: ${JSON.stringify(options.headers || {})},
              body: ${options.body ? JSON.stringify(options.body) : 'null'}
            });
            
            results.fetch = {
              status: fetchResponse.status,
              statusText: fetchResponse.statusText,
              headers: Object.fromEntries(fetchResponse.headers.entries()),
              body: await fetchResponse.text()
            };
          }
          
          // Test XMLHttpRequest
          if (typeof XMLHttpRequest !== 'undefined') {
            results.xhr = await new Promise((resolve, reject) => {
              const xhr = new XMLHttpRequest();
              xhr.open('${options.method || 'GET'}', '${endpoint}');
              
              // Set headers
              ${Object.entries(options.headers || {}).map(([key, value]) => 
                `xhr.setRequestHeader('${key}', '${value}');`
              ).join('\n')}
              
              xhr.onload = () => {
                resolve({
                  status: xhr.status,
                  statusText: xhr.statusText,
                  responseText: xhr.responseText,
                  responseHeaders: xhr.getAllResponseHeaders()
                });
              };
              
              xhr.onerror = () => {
                reject(new Error('XHR request failed'));
              };
              
              xhr.send(${options.body ? JSON.stringify(options.body) : 'null'});
            });
          }
          
          // Test WebSocket if endpoint supports it
          if ('${endpoint}'.startsWith('ws://') || '${endpoint}'.startsWith('wss://')) {
            results.websocket = await new Promise((resolve, reject) => {
              const ws = new WebSocket('${endpoint}');
              const timeout = setTimeout(() => {
                ws.close();
                reject(new Error('WebSocket connection timeout'));
              }, 5000);
              
              ws.onopen = () => {
                clearTimeout(timeout);
                ws.send('test message');
                resolve({ connected: true, readyState: ws.readyState });
              };
              
              ws.onerror = (error) => {
                clearTimeout(timeout);
                reject(error);
              };
              
              ws.onmessage = (event) => {
                ws.close();
                resolve({ connected: true, message: event.data });
              };
            });
          }
          
        } catch (error) {
          results.errors.push(error.message);
        }
        
        return results;
      }
      
      return testAPI();
    `;
    
    return await page.evaluate(testScript);
  }
  
  // Setup request interception
  async setupRequestInterception(page, interceptConfig) {
    await page.route('**/*', async (route) => {
      const request = route.request();
      const url = request.url();
      
      // Check if request should be intercepted
      if (interceptConfig.pattern && !url.match(interceptConfig.pattern)) {
        await route.continue();
        return;
      }
      
      // Mock response if configured
      if (interceptConfig.mockResponse) {
        await route.fulfill({
          status: interceptConfig.mockResponse.status || 200,
          contentType: interceptConfig.mockResponse.contentType || 'application/json',
          body: JSON.stringify(interceptConfig.mockResponse.body || {})
        });
      } else {
        await route.continue();
      }
    });
  }
  
  // Test WebSocket across browsers
  async testWebSocket(wsUrl, options = {}) {
    const results = new Map();
    
    for (const [browserName, browserInfo] of this.browsers.entries()) {
      try {
        const result = await this.testWebSocketInBrowser(browserName, browserInfo, wsUrl, options);
        results.set(browserName, result);
      } catch (error) {
        results.set(browserName, {
          success: false,
          error: error.message,
          browser: browserName
        });
      }
    }
    
    return results;
  }
  
  // Test WebSocket in specific browser
  async testWebSocketInBrowser(browserName, browserInfo, wsUrl, options) {
    const context = await browserInfo.browser.newContext({
      userAgent: browserInfo.config.userAgent,
      viewport: this.config.viewport
    });
    
    const page = await context.newPage();
    
    try {
      const result = await page.evaluate(async (url, testOptions) => {
        return new Promise((resolve, reject) => {
          const ws = new WebSocket(url);
          const results = {
            connected: false,
            messages: [],
            errors: [],
            readyState: null,
            connectionTime: null
          };
          
          const startTime = Date.now();
          const timeout = setTimeout(() => {
            ws.close();
            reject(new Error('WebSocket connection timeout'));
          }, testOptions.timeout || 10000);
          
          ws.onopen = () => {
            results.connected = true;
            results.readyState = ws.readyState;
            results.connectionTime = Date.now() - startTime;
            
            // Send test messages
            if (testOptions.messages) {
              testOptions.messages.forEach((message, index) => {
                setTimeout(() => {
                  ws.send(JSON.stringify(message));
                }, index * 100);
              });
            }
            
            // Close after test
            setTimeout(() => {
              clearTimeout(timeout);
              ws.close();
              resolve(results);
            }, testOptions.duration || 2000);
          };
          
          ws.onmessage = (event) => {
            results.messages.push({
              data: event.data,
              timestamp: Date.now() - startTime
            });
          };
          
          ws.onerror = (error) => {
            results.errors.push(error.message || 'WebSocket error');
          };
          
          ws.onclose = (event) => {
            results.readyState = ws.readyState;
            results.closeCode = event.code;
            results.closeReason = event.reason;
          };
        });
      }, wsUrl, options);
      
      return {
        success: true,
        browser: browserName,
        result
      };
      
    } finally {
      await context.close();
    }
  }
  
  // Test Service Worker API
  async testServiceWorker(swUrl, options = {}) {
    const results = new Map();
    
    for (const [browserName, browserInfo] of this.browsers.entries()) {
      // Skip browsers that don't support Service Workers
      if (!browserInfo.config.features.includes('serviceworker')) {
        results.set(browserName, {
          success: false,
          error: 'Service Worker not supported',
          browser: browserName
        });
        continue;
      }
      
      try {
        const result = await this.testServiceWorkerInBrowser(browserName, browserInfo, swUrl, options);
        results.set(browserName, result);
      } catch (error) {
        results.set(browserName, {
          success: false,
          error: error.message,
          browser: browserName
        });
      }
    }
    
    return results;
  }
  
  // Test Service Worker in specific browser
  async testServiceWorkerInBrowser(browserName, browserInfo, swUrl, options) {
    const context = await browserInfo.browser.newContext({
      userAgent: browserInfo.config.userAgent,
      viewport: this.config.viewport
    });
    
    const page = await context.newPage();
    
    try {
      const result = await page.evaluate(async (url, testOptions) => {
        const results = {
          supported: false,
          registered: false,
          activated: false,
          errors: []
        };
        
        try {
          // Check if Service Worker is supported
          if ('serviceWorker' in navigator) {
            results.supported = true;
            
            // Register Service Worker
            const registration = await navigator.serviceWorker.register(url);
            results.registered = true;
            
            // Wait for activation
            if (registration.active) {
              results.activated = true;
            } else {
              await new Promise((resolve) => {
                navigator.serviceWorker.addEventListener('controllerchange', resolve);
              });
              results.activated = true;
            }
            
            // Test Service Worker functionality
            if (testOptions.testFetch) {
              const response = await fetch(testOptions.testFetch.url, {
                method: testOptions.testFetch.method || 'GET'
              });
              results.fetchResult = {
                status: response.status,
                statusText: response.statusText
              };
            }
            
            // Unregister Service Worker
            await registration.unregister();
            
          } else {
            results.errors.push('Service Worker not supported');
          }
          
        } catch (error) {
          results.errors.push(error.message);
        }
        
        return results;
      }, swUrl, options);
      
      return {
        success: true,
        browser: browserName,
        result
      };
      
    } finally {
      await context.close();
    }
  }
  
  // Test Push API
  async testPushAPI(options = {}) {
    const results = new Map();
    
    for (const [browserName, browserInfo] of this.browsers.entries()) {
      // Skip browsers that don't support Push API
      if (!browserInfo.config.features.includes('push')) {
        results.set(browserName, {
          success: false,
          error: 'Push API not supported',
          browser: browserName
        });
        continue;
      }
      
      try {
        const result = await this.testPushAPIInBrowser(browserName, browserInfo, options);
        results.set(browserName, result);
      } catch (error) {
        results.set(browserName, {
          success: false,
          error: error.message,
          browser: browserName
        });
      }
    }
    
    return results;
  }
  
  // Test Push API in specific browser
  async testPushAPIInBrowser(browserName, browserInfo, options) {
    const context = await browserInfo.browser.newContext({
      userAgent: browserInfo.config.userAgent,
      viewport: this.config.viewport
    });
    
    const page = await context.newPage();
    
    try {
      const result = await page.evaluate(async (testOptions) => {
        const results = {
          supported: false,
          permission: null,
          subscription: null,
          errors: []
        };
        
        try {
          // Check if Push API is supported
          if ('PushManager' in window) {
            results.supported = true;
            
            // Check permission
            const permission = await Notification.requestPermission();
            results.permission = permission;
            
            // Subscribe to push notifications
            if (permission === 'granted') {
              const registration = await navigator.serviceWorker.ready;
              const subscription = await registration.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: testOptions.vapidKey || 'test-key'
              });
              
              results.subscription = {
                endpoint: subscription.endpoint,
                keys: subscription.getKey ? {
                  p256dh: subscription.getKey('p256dh'),
                  auth: subscription.getKey('auth')
                } : null
              };
            }
            
          } else {
            results.errors.push('Push API not supported');
          }
          
        } catch (error) {
          results.errors.push(error.message);
        }
        
        return results;
      }, options);
      
      return {
        success: true,
        browser: browserName,
        result
      };
      
    } finally {
      await context.close();
    }
  }
  
  // Compare results across browsers
  compareResults(results) {
    const comparison = {
      consistent: true,
      differences: [],
      summary: {
        totalBrowsers: results.size,
        successfulTests: 0,
        failedTests: 0
      }
    };
    
    const firstResult = results.values().next().value;
    if (!firstResult) return comparison;
    
    for (const [browserName, result] of results.entries()) {
      if (result.success) {
        comparison.summary.successfulTests++;
        
        // Compare with first result
        if (browserName !== results.keys().next().value) {
          const differences = this.findDifferences(firstResult.result, result.result);
          if (differences.length > 0) {
            comparison.consistent = false;
            comparison.differences.push({
              browser: browserName,
              differences
            });
          }
        }
      } else {
        comparison.summary.failedTests++;
      }
    }
    
    return comparison;
  }
  
  // Find differences between results
  findDifferences(result1, result2) {
    const differences = [];
    
    // Compare fetch results
    if (result1.fetch && result2.fetch) {
      if (result1.fetch.status !== result2.fetch.status) {
        differences.push({
          type: 'fetch_status',
          result1: result1.fetch.status,
          result2: result2.fetch.status
        });
      }
    }
    
    // Compare XHR results
    if (result1.xhr && result2.xhr) {
      if (result1.xhr.status !== result2.xhr.status) {
        differences.push({
          type: 'xhr_status',
          result1: result1.xhr.status,
          result2: result2.xhr.status
        });
      }
    }
    
    // Compare WebSocket results
    if (result1.websocket && result2.websocket) {
      if (result1.websocket.connected !== result2.websocket.connected) {
        differences.push({
          type: 'websocket_connection',
          result1: result1.websocket.connected,
          result2: result2.websocket.connected
        });
      }
    }
    
    return differences;
  }
  
  // Generate cross-browser report
  generateReport(results) {
    const report = {
      timestamp: new Date().toISOString(),
      browsers: Array.from(results.keys()),
      results: Object.fromEntries(results),
      comparison: this.compareResults(results),
      recommendations: this.generateRecommendations(results)
    };
    
    return report;
  }
  
  // Generate recommendations
  generateRecommendations(results) {
    const recommendations = [];
    
    for (const [browserName, result] of results.entries()) {
      if (!result.success) {
        recommendations.push({
          type: 'browser_support',
          browser: browserName,
          issue: result.error,
          suggestion: `Fix compatibility issues for ${browserName}`
        });
      }
    }
    
    const comparison = this.compareResults(results);
    if (!comparison.consistent) {
      recommendations.push({
        type: 'consistency',
        issue: 'Inconsistent behavior across browsers',
        suggestion: 'Standardize API responses and error handling'
      });
    }
    
    return recommendations;
  }
  
  // Cleanup browsers
  async cleanup() {
    for (const [browserName, browserInfo] of this.browsers.entries()) {
      await browserInfo.browser.close();
    }
    this.browsers.clear();
  }
}

// Exercises and Tests
describe("Cross-Browser API Testing", () => {
  let crossBrowserTester;
  
  beforeEach(async () => {
    crossBrowserTester = new CrossBrowserAPITester();
    await crossBrowserTester.initializeBrowsers(['chromium']); // Use only Chromium for testing
  });
  
  afterEach(async () => {
    await crossBrowserTester.cleanup();
  });
  
  it("should initialize browsers", async () => {
    expect(crossBrowserTester.browsers.size).to.be.greaterThan(0);
    expect(crossBrowserTester.browsers.has('chromium')).to.be.true;
  });
  
  it("should test API endpoint across browsers", async () => {
    const results = await crossBrowserTester.testAPIEndpoint('https://httpbin.org/get', {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });
    
    expect(results.size).to.be.greaterThan(0);
    expect(results.has('chromium')).to.be.true;
    
    const chromiumResult = results.get('chromium');
    expect(chromiumResult.success).to.be.true;
    expect(chromiumResult.result).to.have.property('fetch');
  });
  
  it("should test WebSocket across browsers", async () => {
    const results = await crossBrowserTester.testWebSocket('wss://echo.websocket.org', {
      messages: [{ type: 'test', data: 'hello' }],
      timeout: 5000
    });
    
    expect(results.size).to.be.greaterThan(0);
    expect(results.has('chromium')).to.be.true;
    
    const chromiumResult = results.get('chromium');
    expect(chromiumResult.success).to.be.true;
    expect(chromiumResult.result).to.have.property('connected');
  });
  
  it("should test Service Worker API", async () => {
    const results = await crossBrowserTester.testServiceWorker('/sw.js', {
      testFetch: {
        url: 'https://httpbin.org/get',
        method: 'GET'
      }
    });
    
    expect(results.size).to.be.greaterThan(0);
    expect(results.has('chromium')).to.be.true;
    
    const chromiumResult = results.get('chromium');
    expect(chromiumResult.success).to.be.true;
    expect(chromiumResult.result).to.have.property('supported');
  });
  
  it("should test Push API", async () => {
    const results = await crossBrowserTester.testPushAPI({
      vapidKey: 'test-vapid-key'
    });
    
    expect(results.size).to.be.greaterThan(0);
    expect(results.has('chromium')).to.be.true;
    
    const chromiumResult = results.get('chromium');
    expect(chromiumResult.success).to.be.true;
    expect(chromiumResult.result).to.have.property('supported');
  });
  
  it("should compare results across browsers", () => {
    const mockResults = new Map([
      ['chromium', { success: true, result: { fetch: { status: 200 } } }],
      ['firefox', { success: true, result: { fetch: { status: 200 } } }],
      ['webkit', { success: true, result: { fetch: { status: 200 } } }]
    ]);
    
    const comparison = crossBrowserTester.compareResults(mockResults);
    
    expect(comparison.consistent).to.be.true;
    expect(comparison.summary.totalBrowsers).to.equal(3);
    expect(comparison.summary.successfulTests).to.equal(3);
  });
  
  it("should find differences between results", () => {
    const result1 = { fetch: { status: 200 }, xhr: { status: 200 } };
    const result2 = { fetch: { status: 404 }, xhr: { status: 200 } };
    
    const differences = crossBrowserTester.findDifferences(result1, result2);
    
    expect(differences).to.have.length(1);
    expect(differences[0].type).to.equal('fetch_status');
    expect(differences[0].result1).to.equal(200);
    expect(differences[0].result2).to.equal(404);
  });
  
  it("should generate cross-browser report", () => {
    const mockResults = new Map([
      ['chromium', { success: true, result: { fetch: { status: 200 } } }],
      ['firefox', { success: false, error: 'Connection failed' }]
    ]);
    
    const report = crossBrowserTester.generateReport(mockResults);
    
    expect(report).to.have.property('timestamp');
    expect(report).to.have.property('browsers');
    expect(report).to.have.property('results');
    expect(report).to.have.property('comparison');
    expect(report).to.have.property('recommendations');
    
    expect(report.browsers).to.include('chromium');
    expect(report.browsers).to.include('firefox');
  });
  
  it("should generate recommendations", () => {
    const mockResults = new Map([
      ['chromium', { success: true, result: { fetch: { status: 200 } } }],
      ['firefox', { success: false, error: 'Connection failed' }]
    ]);
    
    const recommendations = crossBrowserTester.generateRecommendations(mockResults);
    
    expect(recommendations).to.be.an('array');
    expect(recommendations.length).to.be.greaterThan(0);
    
    const browserRec = recommendations.find(r => r.type === 'browser_support');
    expect(browserRec).to.exist;
    expect(browserRec.browser).to.equal('firefox');
  });
});

export { CrossBrowserAPITester, BROWSER_CONFIGS };




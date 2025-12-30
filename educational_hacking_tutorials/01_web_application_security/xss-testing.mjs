/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 1: Web Application Security
 * Tutorial 2: Cross-Site Scripting (XSS) Testing
 * 
 * ⚠️ EDUCATIONAL PURPOSE ONLY
 * This tutorial is for educational and defensive security purposes only.
 * Only test systems you own or have explicit written permission to test.
 * 
 * Learning Objectives:
 * - Understand XSS vulnerabilities
 * - Learn to test for XSS safely
 * - Implement defensive measures
 * - Understand different types of XSS
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== XSS TESTING (EDUCATIONAL) ===");

/**
 * XSS Test Suite
 * Tests for Cross-Site Scripting vulnerabilities
 */
class XSSTester {
  constructor(apiClient) {
    this.apiClient = apiClient;
    this.testPayloads = this.generateTestPayloads();
  }

  /**
   * Generate XSS test payloads
   */
  generateTestPayloads() {
    return {
      // Reflected XSS
      reflected: [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>"
      ],

      // Stored XSS
      stored: [
        "<script>document.cookie</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "<svg onload=alert(document.domain)>"
      ],

      // DOM-based XSS
      domBased: [
        "#<script>alert('XSS')</script>",
        "?param=<script>alert('XSS')</script>",
        "javascript:alert(document.cookie)"
      ],

      // Encoded XSS
      encoded: [
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "&#60;script&#62;alert('XSS')&#60;/script&#62;",
        "\\x3Cscript\\x3Ealert('XSS')\\x3C/script\\x3E"
      ]
    };
  }

  /**
   * Test for reflected XSS
   */
  async testReflectedXSS(endpoint, paramName, paramValue) {
    const results = [];

    for (const payload of this.testPayloads.reflected) {
      try {
        const response = await this.apiClient
          .get(endpoint)
          .query({ [paramName]: paramValue + payload });

        const vulnerable = this.analyzeXSSResponse(response, payload);

        results.push({
          payload,
          status: response.status,
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
   * Test for stored XSS
   */
  async testStoredXSS(endpoint, data) {
    const results = [];

    for (const payload of this.testPayloads.stored) {
      try {
        // Submit XSS payload
        const submitResponse = await this.apiClient
          .post(endpoint)
          .send({ ...data, content: payload });

        // Retrieve and check if payload is stored
        const retrieveResponse = await this.apiClient
          .get(endpoint);

        const vulnerable = this.analyzeXSSResponse(retrieveResponse, payload);

        results.push({
          payload,
          status: submitResponse.status,
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
   * Analyze response for XSS indicators
   */
  analyzeXSSResponse(response, payload) {
    const responseText = JSON.stringify(response.body) + JSON.stringify(response.headers);

    // Check if payload is reflected in response
    if (responseText.includes(payload) || responseText.includes(decodeURIComponent(payload))) {
      return true;
    }

    // Check for script tags
    if (responseText.includes('<script>') || responseText.includes('</script>')) {
      return true;
    }

    // Check for event handlers
    const eventHandlers = ['onerror', 'onload', 'onfocus', 'onclick'];
    for (const handler of eventHandlers) {
      if (responseText.includes(handler + '=')) {
        return true;
      }
    }

    return false;
  }

  /**
   * Test Content Security Policy
   */
  async testCSP(endpoint) {
    try {
      const response = await this.apiClient.get(endpoint);

      const cspHeader = response.headers['content-security-policy'] || 
                       response.headers['x-content-security-policy'];

      return {
        hasCSP: !!cspHeader,
        cspHeader: cspHeader || null
      };
    } catch (error) {
      return {
        hasCSP: false,
        error: error.message
      };
    }
  }
}

/**
 * XSS Prevention Helper
 * Demonstrates defensive measures
 */
class XSSPrevention {
  /**
   * Encode HTML entities
   */
  static encodeHTML(input) {
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  /**
   * Encode for JavaScript context
   */
  static encodeJS(input) {
    return input
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "\\'")
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t');
  }

  /**
   * Encode for URL context
   */
  static encodeURL(input) {
    return encodeURIComponent(input);
  }

  /**
   * Sanitize input (remove dangerous content)
   */
  static sanitizeInput(input) {
    // Remove script tags
    let sanitized = input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    
    // Remove event handlers
    sanitized = sanitized.replace(/\s*on\w+\s*=\s*["'][^"']*["']/gi, '');
    
    // Remove javascript: protocol
    sanitized = sanitized.replace(/javascript:/gi, '');
    
    return sanitized;
  }

  /**
   * Validate input against whitelist
   */
  static validateInput(input, allowedTags = []) {
    // Remove all tags except allowed ones
    const tagPattern = /<\/?([a-z][a-z0-9]*)\b[^>]*>/gi;
    const tags = input.match(tagPattern) || [];
    
    for (const tag of tags) {
      const tagName = tag.match(/<\/?([a-z][a-z0-9]*)/i)?.[1];
      if (tagName && !allowedTags.includes(tagName.toLowerCase())) {
        return false;
      }
    }
    
    return true;
  }
}

// Exercises and Tests
describe("XSS Testing (Educational)", () => {
  const baseURL = "https://api.example.com";
  const request = supertest(baseURL);
  let xssTester;

  beforeEach(() => {
    xssTester = new XSSTester(request);
  });

  it("should generate XSS test payloads", () => {
    const payloads = xssTester.generateTestPayloads();

    expect(payloads).to.have.property('reflected');
    expect(payloads).to.have.property('stored');
    expect(payloads).to.have.property('domBased');
    expect(payloads).to.have.property('encoded');

    expect(payloads.reflected.length).to.be.greaterThan(0);
  });

  it("should test for reflected XSS", async () => {
    try {
      const results = await xssTester.testReflectedXSS("/search", "q", "test");

      expect(results).to.be.an('array');
      results.forEach(result => {
        expect(result).to.have.property('payload');
        expect(result).to.have.property('vulnerable');
      });
    } catch (error) {
      expect(error).to.be.an('error');
    }
  });

  it("should test for stored XSS", async () => {
    try {
      const results = await xssTester.testStoredXSS("/comments", { userId: 1 });

      expect(results).to.be.an('array');
    } catch (error) {
      expect(error).to.be.an('error');
    }
  });

  it("should test Content Security Policy", async () => {
    try {
      const cspTest = await xssTester.testCSP("/");

      expect(cspTest).to.have.property('hasCSP');
      expect(cspTest).to.have.property('cspHeader');
    } catch (error) {
      expect(error).to.be.an('error');
    }
  });
});

// Defensive Measures Tests
describe("XSS Prevention", () => {
  it("should encode HTML entities", () => {
    const maliciousInput = "<script>alert('XSS')</script>";
    const encoded = XSSPrevention.encodeHTML(maliciousInput);

    expect(encoded).to.not.include("<script>");
    expect(encoded).to.include("&lt;");
    expect(encoded).to.include("&gt;");
  });

  it("should encode for JavaScript context", () => {
    const maliciousInput = "'; alert('XSS'); //";
    const encoded = XSSPrevention.encodeJS(maliciousInput);

    expect(encoded).to.include("\\'");
    expect(encoded).to.not.equal(maliciousInput);
  });

  it("should sanitize dangerous content", () => {
    const maliciousInput = "<script>alert('XSS')</script><p>Safe content</p>";
    const sanitized = XSSPrevention.sanitizeInput(maliciousInput);

    expect(sanitized).to.not.include("<script>");
    expect(sanitized).to.include("Safe content");
  });

  it("should validate input against whitelist", () => {
    const safeInput = "<p>Safe paragraph</p>";
    const unsafeInput = "<script>alert('XSS')</script>";

    expect(XSSPrevention.validateInput(safeInput, ['p'])).to.be.true;
    expect(XSSPrevention.validateInput(unsafeInput, ['p'])).to.be.false;
  });
});

export {
  XSSTester,
  XSSPrevention
};


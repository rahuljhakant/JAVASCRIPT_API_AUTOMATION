/**
 * PHASE 2: INTERMEDIATE LEVEL
 * Module 3: Data Validation
 * Lesson 2: Response Structure Validation
 * 
 * Learning Objectives:
 * - Validate response structure
 * - Check required fields
 * - Validate data types
 * - Verify response format
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== RESPONSE STRUCTURE VALIDATION ===");

// API client setup
const request = supertest("https://jsonplaceholder.typicode.com");

// Validate response structure
function validateResponseStructure(response, expectedStructure) {
  const errors = [];
  
  function checkStructure(data, structure, path = '') {
    if (typeof structure === 'object' && structure !== null) {
      if (Array.isArray(structure)) {
        // Array validation
        if (!Array.isArray(data)) {
          errors.push(`Expected array at ${path}, got ${typeof data}`);
          return;
        }
        
        if (structure.length > 0) {
          data.forEach((item, index) => {
            checkStructure(item, structure[0], `${path}[${index}]`);
          });
        }
      } else {
        // Object validation
        if (typeof data !== 'object' || data === null || Array.isArray(data)) {
          errors.push(`Expected object at ${path}, got ${typeof data}`);
          return;
        }
        
        Object.keys(structure).forEach(key => {
          const fullPath = path ? `${path}.${key}` : key;
          
          if (structure[key].required && !(key in data)) {
            errors.push(`Missing required field: ${fullPath}`);
          } else if (key in data) {
            const expectedType = structure[key].type;
            const actualType = Array.isArray(data[key]) ? 'array' : typeof data[key];
            
            if (expectedType && actualType !== expectedType) {
              errors.push(`Type mismatch at ${fullPath}: expected ${expectedType}, got ${actualType}`);
            }
            
            if (structure[key].structure) {
              checkStructure(data[key], structure[key].structure, fullPath);
            }
          }
        });
      }
    }
  }
  
  checkStructure(response.body, expectedStructure);
  
  return {
    valid: errors.length === 0,
    errors
  };
}

// Expected response structures
const postStructure = {
  id: { type: 'number', required: true },
  title: { type: 'string', required: true },
  body: { type: 'string', required: true },
  userId: { type: 'number', required: true }
};

const userStructure = {
  id: { type: 'number', required: true },
  name: { type: 'string', required: true },
  username: { type: 'string', required: true },
  email: { type: 'string', required: true },
  address: {
    type: 'object',
    required: false,
    structure: {
      street: { type: 'string', required: false },
      city: { type: 'string', required: false },
      zipcode: { type: 'string', required: false }
    }
  }
};

// Exercises and Tests
describe("Response Structure Validation", () => {
  it("should validate post response structure", async () => {
    const response = await request.get("/posts/1");
    
    expect(response.status).to.equal(200);
    
    const validation = validateResponseStructure(response, postStructure);
    expect(validation.valid).to.be.true;
    expect(validation.errors).to.have.length(0);
  });

  it("should validate user response structure", async () => {
    const response = await request.get("/users/1");
    
    expect(response.status).to.equal(200);
    
    const validation = validateResponseStructure(response, userStructure);
    expect(validation.valid).to.be.true;
  });

  it("should detect missing required fields", () => {
    const invalidResponse = {
      body: {
        id: 1,
        // Missing required fields: title, body, userId
      }
    };
    
    const validation = validateResponseStructure(invalidResponse, postStructure);
    expect(validation.valid).to.be.false;
    expect(validation.errors.length).to.be.greaterThan(0);
  });

  it("should detect type mismatches", () => {
    const invalidResponse = {
      body: {
        id: "not-a-number",
        title: "Test",
        body: "Test body",
        userId: 1
      }
    };
    
    const validation = validateResponseStructure(invalidResponse, postStructure);
    expect(validation.valid).to.be.false;
    expect(validation.errors.some(e => e.includes('Type mismatch'))).to.be.true;
  });

  it("should validate array responses", async () => {
    const response = await request.get("/posts");
    
    expect(response.status).to.equal(200);
    expect(response.body).to.be.an('array');
    
    response.body.forEach((post, index) => {
      const validation = validateResponseStructure({ body: post }, postStructure);
      expect(validation.valid).to.be.true;
    });
  });
});

// Response Validator Class
class ResponseValidator {
  static validateFields(response, requiredFields) {
    const missing = requiredFields.filter(field => !(field in response.body));
    
    return {
      valid: missing.length === 0,
      missingFields: missing
    };
  }
  
  static validateTypes(response, fieldTypes) {
    const errors = [];
    
    Object.keys(fieldTypes).forEach(field => {
      if (field in response.body) {
        const expectedType = fieldTypes[field];
        const actualType = Array.isArray(response.body[field]) 
          ? 'array' 
          : typeof response.body[field];
        
        if (actualType !== expectedType) {
          errors.push({
            field,
            expected: expectedType,
            actual: actualType
          });
        }
      }
    });
    
    return {
      valid: errors.length === 0,
      errors
    };
  }
  
  static validateResponse(response, structure) {
    return validateResponseStructure(response, structure);
  }
}

// Advanced Validation Examples
describe("Advanced Response Validation", () => {
  it("should use ResponseValidator class", async () => {
    const response = await request.get("/posts/1");
    
    const fieldValidation = ResponseValidator.validateFields(response, ['id', 'title', 'body', 'userId']);
    expect(fieldValidation.valid).to.be.true;
    
    const typeValidation = ResponseValidator.validateTypes(response, {
      id: 'number',
      title: 'string',
      body: 'string',
      userId: 'number'
    });
    expect(typeValidation.valid).to.be.true;
  });
});

// Export functions and classes
export { 
  validateResponseStructure, 
  postStructure, 
  userStructure,
  ResponseValidator 
};


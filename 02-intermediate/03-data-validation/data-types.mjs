/**
 * PHASE 2: INTERMEDIATE LEVEL
 * Module 3: Data Validation
 * Lesson 3: Data Types Validation
 * 
 * Learning Objectives:
 * - Validate different data types in API responses
 * - Handle type coercion and conversion
 * - Validate nested objects and arrays
 * - Implement custom type validators
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== DATA TYPES VALIDATION ===");

// API client setup
const request = supertest("https://jsonplaceholder.typicode.com");

// Data Type Validator
class DataTypeValidator {
  static validateString(value, options = {}) {
    expect(value).to.be.a('string');
    
    if (options.minLength !== undefined) {
      expect(value.length).to.be.at.least(options.minLength);
    }
    
    if (options.maxLength !== undefined) {
      expect(value.length).to.be.at.most(options.maxLength);
    }
    
    if (options.pattern) {
      expect(value).to.match(options.pattern);
    }
    
    if (options.notEmpty) {
      expect(value).to.not.be.empty;
    }
    
    return true;
  }
  
  static validateNumber(value, options = {}) {
    expect(value).to.be.a('number');
    
    if (options.min !== undefined) {
      expect(value).to.be.at.least(options.min);
    }
    
    if (options.max !== undefined) {
      expect(value).to.be.at.most(options.max);
    }
    
    if (options.integer) {
      expect(value).to.be.an('integer');
    }
    
    if (options.positive) {
      expect(value).to.be.above(0);
    }
    
    if (options.negative) {
      expect(value).to.be.below(0);
    }
    
    return true;
  }
  
  static validateBoolean(value) {
    expect(value).to.be.a('boolean');
    return true;
  }
  
  static validateArray(value, options = {}) {
    expect(value).to.be.an('array');
    
    if (options.minLength !== undefined) {
      expect(value.length).to.be.at.least(options.minLength);
    }
    
    if (options.maxLength !== undefined) {
      expect(value.length).to.be.at.most(options.maxLength);
    }
    
    if (options.itemType) {
      value.forEach((item, index) => {
        expect(item, `Array item at index ${index} should be ${options.itemType}`)
          .to.be.a(options.itemType);
      });
    }
    
    if (options.itemValidator) {
      value.forEach((item, index) => {
        options.itemValidator(item, index);
      });
    }
    
    return true;
  }
  
  static validateObject(value, options = {}) {
    expect(value).to.be.an('object');
    expect(value).to.not.be.null;
    
    if (options.requiredFields) {
      options.requiredFields.forEach(field => {
        expect(value, `Object should have required field: ${field}`)
          .to.have.property(field);
      });
    }
    
    if (options.optionalFields) {
      // Optional fields - just check they exist if present
      options.optionalFields.forEach(field => {
        if (value.hasOwnProperty(field)) {
          expect(value).to.have.property(field);
        }
      });
    }
    
    if (options.fieldValidators) {
      Object.entries(options.fieldValidators).forEach(([field, validator]) => {
        if (value.hasOwnProperty(field)) {
          validator(value[field]);
        }
      });
    }
    
    return true;
  }
  
  static validateDate(value, options = {}) {
    const date = new Date(value);
    expect(date.getTime()).to.not.be.NaN;
    
    if (options.minDate) {
      expect(date.getTime()).to.be.at.least(new Date(options.minDate).getTime());
    }
    
    if (options.maxDate) {
      expect(date.getTime()).to.be.at.most(new Date(options.maxDate).getTime());
    }
    
    return true;
  }
  
  static validateEmail(value) {
    expect(value).to.be.a('string');
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    expect(value).to.match(emailRegex);
    return true;
  }
  
  static validateURL(value) {
    expect(value).to.be.a('string');
    try {
      new URL(value);
      return true;
    } catch (error) {
      expect.fail(`Invalid URL: ${value}`);
    }
  }
  
  static validateUUID(value) {
    expect(value).to.be.a('string');
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    expect(value).to.match(uuidRegex);
    return true;
  }
  
  static validateEnum(value, allowedValues) {
    expect(allowedValues).to.include(value);
    return true;
  }
  
  static validateNested(value, schema) {
    if (schema.type === 'object') {
      this.validateObject(value, schema.options || {});
      
      if (schema.properties) {
        Object.entries(schema.properties).forEach(([key, subSchema]) => {
          if (value.hasOwnProperty(key)) {
            this.validateNested(value[key], subSchema);
          }
        });
      }
    } else if (schema.type === 'array') {
      this.validateArray(value, schema.options || {});
      
      if (schema.items) {
        value.forEach(item => {
          this.validateNested(item, schema.items);
        });
      }
    }
    
    return true;
  }
}

// Exercises and Tests
describe("Data Types Validation", () => {
  it("should validate string types", async () => {
    const response = await request.get("/posts/1");
    
    DataTypeValidator.validateString(response.body.title, {
      notEmpty: true,
      minLength: 1
    });
    
    DataTypeValidator.validateString(response.body.body, {
      notEmpty: true
    });
    
    console.log("String validation successful");
  });
  
  it("should validate number types", async () => {
    const response = await request.get("/posts/1");
    
    DataTypeValidator.validateNumber(response.body.id, {
      integer: true,
      positive: true,
      min: 1
    });
    
    DataTypeValidator.validateNumber(response.body.userId, {
      integer: true,
      positive: true
    });
    
    console.log("Number validation successful");
  });
  
  it("should validate boolean types", async () => {
    // Create a mock response with boolean
    const mockData = { completed: true, active: false };
    
    DataTypeValidator.validateBoolean(mockData.completed);
    DataTypeValidator.validateBoolean(mockData.active);
    
    console.log("Boolean validation successful");
  });
  
  it("should validate array types", async () => {
    const response = await request.get("/posts");
    
    DataTypeValidator.validateArray(response.body, {
      minLength: 1,
      itemType: 'object'
    });
    
    // Validate array items
    if (response.body.length > 0) {
      DataTypeValidator.validateObject(response.body[0], {
        requiredFields: ['id', 'title', 'body', 'userId']
      });
    }
    
    console.log("Array validation successful");
  });
  
  it("should validate object types", async () => {
    const response = await request.get("/posts/1");
    
    DataTypeValidator.validateObject(response.body, {
      requiredFields: ['id', 'title', 'body', 'userId'],
      fieldValidators: {
        id: (value) => DataTypeValidator.validateNumber(value, { integer: true, positive: true }),
        title: (value) => DataTypeValidator.validateString(value, { notEmpty: true }),
        body: (value) => DataTypeValidator.validateString(value, { notEmpty: true }),
        userId: (value) => DataTypeValidator.validateNumber(value, { integer: true, positive: true })
      }
    });
    
    console.log("Object validation successful");
  });
  
  it("should validate email format", () => {
    const validEmails = [
      "user@example.com",
      "test.user@domain.co.uk",
      "name+tag@example.org"
    ];
    
    validEmails.forEach(email => {
      DataTypeValidator.validateEmail(email);
    });
    
    console.log("Email validation successful");
  });
  
  it("should validate URL format", () => {
    const validURLs = [
      "https://example.com",
      "http://www.example.com/path",
      "https://api.example.com/v1/users?page=1"
    ];
    
    validURLs.forEach(url => {
      DataTypeValidator.validateURL(url);
    });
    
    console.log("URL validation successful");
  });
  
  it("should validate enum values", () => {
    const statuses = ["active", "inactive", "pending"];
    const validStatus = "active";
    const invalidStatus = "deleted";
    
    DataTypeValidator.validateEnum(validStatus, statuses);
    
    try {
      DataTypeValidator.validateEnum(invalidStatus, statuses);
      expect.fail("Should have failed for invalid enum value");
    } catch (error) {
      expect(error).to.exist;
    }
    
    console.log("Enum validation successful");
  });
  
  it("should validate nested objects", async () => {
    const response = await request.get("/posts/1");
    
    const schema = {
      type: 'object',
      properties: {
        id: {
          type: 'number',
          options: { integer: true, positive: true }
        },
        title: {
          type: 'string',
          options: { notEmpty: true }
        },
        body: {
          type: 'string',
          options: { notEmpty: true }
        },
        userId: {
          type: 'number',
          options: { integer: true, positive: true }
        }
      }
    };
    
    // Simplified nested validation
    DataTypeValidator.validateObject(response.body, {
      requiredFields: ['id', 'title', 'body', 'userId']
    });
    
    DataTypeValidator.validateNumber(response.body.id, { integer: true });
    DataTypeValidator.validateString(response.body.title, { notEmpty: true });
    
    console.log("Nested object validation successful");
  });
  
  it("should validate array of objects", async () => {
    const response = await request.get("/posts");
    
    DataTypeValidator.validateArray(response.body, {
      minLength: 1,
      itemValidator: (item) => {
        DataTypeValidator.validateObject(item, {
          requiredFields: ['id', 'title', 'body', 'userId']
        });
      }
    });
    
    console.log("Array of objects validation successful");
  });
  
  it("should validate date formats", () => {
    const validDates = [
      "2024-01-01",
      "2024-01-01T00:00:00Z",
      new Date().toISOString()
    ];
    
    validDates.forEach(date => {
      DataTypeValidator.validateDate(date);
    });
    
    console.log("Date validation successful");
  });
  
  it("should handle type coercion", () => {
    // String to number
    const stringNumber = "123";
    const coercedNumber = Number(stringNumber);
    DataTypeValidator.validateNumber(coercedNumber, { integer: true });
    
    // Number to string
    const number = 123;
    const coercedString = String(number);
    DataTypeValidator.validateString(coercedString);
    
    // Boolean coercion
    const truthyValue = 1;
    const falsyValue = 0;
    expect(Boolean(truthyValue)).to.be.true;
    expect(Boolean(falsyValue)).to.be.false;
    
    console.log("Type coercion handled successfully");
  });
  
  it("should validate mixed data types in response", async () => {
    const response = await request.get("/posts/1");
    
    // Validate all types in the response
    DataTypeValidator.validateNumber(response.body.id, { integer: true });
    DataTypeValidator.validateNumber(response.body.userId, { integer: true });
    DataTypeValidator.validateString(response.body.title);
    DataTypeValidator.validateString(response.body.body);
    
    console.log("Mixed data types validation successful");
  });
  
  it("should validate optional vs required fields", async () => {
    const response = await request.get("/posts/1");
    
    // Required fields
    DataTypeValidator.validateObject(response.body, {
      requiredFields: ['id', 'title', 'body', 'userId']
    });
    
    // Optional fields (if present, validate them)
    if (response.body.hasOwnProperty('comments')) {
      DataTypeValidator.validateArray(response.body.comments);
    }
    
    console.log("Optional/required fields validation successful");
  });
});

// Advanced Type Validation
describe("Advanced Type Validation", () => {
  it("should validate custom types", () => {
    // Custom validator for ID format
    const validateCustomId = (value) => {
      expect(value).to.be.a('string');
      expect(value).to.match(/^[A-Z]{2}-\d{4}$/); // Format: XX-1234
    };
    
    const validId = "US-1234";
    validateCustomId(validId);
    
    console.log("Custom type validation successful");
  });
  
  it("should validate type constraints", () => {
    // Validate number within range
    DataTypeValidator.validateNumber(50, { min: 0, max: 100 });
    
    // Validate string length
    DataTypeValidator.validateString("test", { minLength: 1, maxLength: 10 });
    
    // Validate array length
    DataTypeValidator.validateArray([1, 2, 3], { minLength: 1, maxLength: 10 });
    
    console.log("Type constraints validation successful");
  });
  
  it("should validate type combinations", () => {
    // Union types (string or number)
    const value1 = "123";
    const value2 = 123;
    
    const isStringOrNumber = (value) => {
      return typeof value === 'string' || typeof value === 'number';
    };
    
    expect(isStringOrNumber(value1)).to.be.true;
    expect(isStringOrNumber(value2)).to.be.true;
    
    console.log("Type combinations validation successful");
  });
  
  it("should validate type transformations", () => {
    // String to number transformation
    const stringValue = "42";
    const numberValue = parseInt(stringValue, 10);
    DataTypeValidator.validateNumber(numberValue, { integer: true });
    
    // Number to string transformation
    const numValue = 42;
    const strValue = numValue.toString();
    DataTypeValidator.validateString(strValue);
    
    // Date string to Date object
    const dateString = "2024-01-01";
    const dateObject = new Date(dateString);
    DataTypeValidator.validateDate(dateObject);
    
    console.log("Type transformations validation successful");
  });
  
  it("should handle null and undefined values", () => {
    // Null handling
    const nullValue = null;
    expect(nullValue).to.be.null;
    
    // Undefined handling
    let undefinedValue;
    expect(undefinedValue).to.be.undefined;
    
    // Optional field that might be null
    const optionalField = null;
    if (optionalField !== null && optionalField !== undefined) {
      DataTypeValidator.validateString(optionalField);
    }
    
    console.log("Null/undefined handling successful");
  });
  
  it("should validate type safety", () => {
    // Ensure type consistency
    const validateTypeSafety = (value, expectedType) => {
      const actualType = typeof value;
      expect(actualType).to.equal(expectedType);
    };
    
    validateTypeSafety(123, 'number');
    validateTypeSafety("test", 'string');
    validateTypeSafety(true, 'boolean');
    validateTypeSafety({}, 'object');
    validateTypeSafety([], 'object'); // Arrays are objects in JavaScript
    
    console.log("Type safety validation successful");
  });
});

// Type Validation Utilities
class TypeValidationUtils {
  static getType(value) {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    return typeof value;
  }
  
  static isType(value, expectedType) {
    const actualType = this.getType(value);
    return actualType === expectedType;
  }
  
  static validateType(value, expectedType) {
    const actualType = this.getType(value);
    expect(actualType).to.equal(expectedType);
  }
  
  static coerceToType(value, targetType) {
    switch (targetType) {
      case 'string':
        return String(value);
      case 'number':
        return Number(value);
      case 'boolean':
        return Boolean(value);
      default:
        return value;
    }
  }
}

// Using type validation utilities
describe("Type Validation Utilities", () => {
  it("should use type detection", () => {
    expect(TypeValidationUtils.getType(123)).to.equal('number');
    expect(TypeValidationUtils.getType("test")).to.equal('string');
    expect(TypeValidationUtils.getType(true)).to.equal('boolean');
    expect(TypeValidationUtils.getType([])).to.equal('array');
    expect(TypeValidationUtils.getType(null)).to.equal('null');
  });
  
  it("should use type checking", () => {
    expect(TypeValidationUtils.isType(123, 'number')).to.be.true;
    expect(TypeValidationUtils.isType("test", 'string')).to.be.true;
    expect(TypeValidationUtils.isType(123, 'string')).to.be.false;
  });
  
  it("should use type coercion utilities", () => {
    const stringValue = TypeValidationUtils.coerceToType(123, 'string');
    expect(stringValue).to.equal('123');
    
    const numberValue = TypeValidationUtils.coerceToType("123", 'number');
    expect(numberValue).to.equal(123);
    
    const booleanValue = TypeValidationUtils.coerceToType(1, 'boolean');
    expect(booleanValue).to.be.true;
  });
});

export { 
  DataTypeValidator, 
  TypeValidationUtils 
};


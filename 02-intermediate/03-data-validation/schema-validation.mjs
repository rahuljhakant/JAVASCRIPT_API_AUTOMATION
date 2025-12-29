/**
 * PHASE 2: INTERMEDIATE LEVEL
 * Module 3: Data Validation
 * Lesson 1: Schema Validation
 * 
 * Learning Objectives:
 * - Validate API responses with Joi
 * - Create validation schemas
 * - Handle validation errors
 * - Validate nested objects
 */

import { expect } from "chai";
import supertest from "supertest";
import Joi from "joi";

console.log("=== SCHEMA VALIDATION ===");

// API client setup
const request = supertest("https://jsonplaceholder.typicode.com");

// User schema validation
const userSchema = Joi.object({
  id: Joi.number().integer().required(),
  name: Joi.string().required(),
  username: Joi.string().required(),
  email: Joi.string().email().required(),
  address: Joi.object({
    street: Joi.string(),
    city: Joi.string(),
    zipcode: Joi.string(),
    geo: Joi.object({
      lat: Joi.string(),
      lng: Joi.string()
    })
  }).optional(),
  phone: Joi.string().optional(),
  website: Joi.string().uri().optional(),
  company: Joi.object({
    name: Joi.string(),
    catchPhrase: Joi.string(),
    bs: Joi.string()
  }).optional()
});

// Post schema validation
const postSchema = Joi.object({
  id: Joi.number().integer().required(),
  title: Joi.string().required(),
  body: Joi.string().required(),
  userId: Joi.number().integer().required()
});

// Validate response against schema
function validateSchema(data, schema) {
  const { error, value } = schema.validate(data, { abortEarly: false });
  
  if (error) {
    return {
      valid: false,
      errors: error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }))
    };
  }
  
  return {
    valid: true,
    value
  };
}

// Exercises and Tests
describe("Schema Validation", () => {
  it("should validate user schema", async () => {
    const response = await request.get("/users/1");
    
    expect(response.status).to.equal(200);
    
    const validation = validateSchema(response.body, userSchema);
    expect(validation.valid).to.be.true;
  });

  it("should validate post schema", async () => {
    const response = await request.get("/posts/1");
    
    expect(response.status).to.equal(200);
    
    const validation = validateSchema(response.body, postSchema);
    expect(validation.valid).to.be.true;
  });

  it("should detect validation errors", () => {
    const invalidData = {
      id: "not-a-number",
      name: "",
      email: "invalid-email"
    };
    
    const validation = validateSchema(invalidData, userSchema);
    expect(validation.valid).to.be.false;
    expect(validation.errors).to.be.an('array');
    expect(validation.errors.length).to.be.greaterThan(0);
  });

  it("should validate array of objects", async () => {
    const response = await request.get("/users");
    
    expect(response.status).to.equal(200);
    expect(response.body).to.be.an('array');
    
    response.body.forEach(user => {
      const validation = validateSchema(user, userSchema);
      expect(validation.valid).to.be.true;
    });
  });
});

// Schema Validator Class
class SchemaValidator {
  constructor() {
    this.schemas = new Map();
  }
  
  registerSchema(name, schema) {
    this.schemas.set(name, schema);
  }
  
  validate(data, schemaName) {
    const schema = this.schemas.get(schemaName);
    if (!schema) {
      throw new Error(`Schema '${schemaName}' not found`);
    }
    
    return validateSchema(data, schema);
  }
  
  validateArray(dataArray, schemaName) {
    return dataArray.map((item, index) => {
      const validation = this.validate(item, schemaName);
      return {
        index,
        ...validation
      };
    });
  }
}

// Advanced Validation Examples
describe("Advanced Schema Validation", () => {
  it("should use SchemaValidator class", () => {
    const validator = new SchemaValidator();
    validator.registerSchema('user', userSchema);
    
    const validUser = {
      id: 1,
      name: "John Doe",
      username: "johndoe",
      email: "john@example.com"
    };
    
    const validation = validator.validate(validUser, 'user');
    expect(validation.valid).to.be.true;
  });

  it("should validate array of items", async () => {
    const response = await request.get("/users");
    const validator = new SchemaValidator();
    validator.registerSchema('user', userSchema);
    
    const validations = validator.validateArray(response.body, 'user');
    
    validations.forEach(validation => {
      expect(validation.valid).to.be.true;
    });
  });
});

// Export functions and classes
export { 
  validateSchema, 
  userSchema, 
  postSchema,
  SchemaValidator 
};


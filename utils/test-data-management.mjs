/**
 * COMPREHENSIVE TEST DATA MANAGEMENT
 * Advanced test data generation, management, and cleanup
 * 
 * Features:
 * - Dynamic test data generation
 * - Test data isolation and cleanup
 * - Data factories and builders
 * - Test data versioning
 * - Cross-test data sharing
 */

import { expect } from "chai";
import { faker } from "@faker-js/faker";

console.log("=== TEST DATA MANAGEMENT ===");

// Test Data Factory
class TestDataFactory {
  constructor() {
    this.generators = new Map();
    this.setupDefaultGenerators();
  }
  
  // Setup default data generators
  setupDefaultGenerators() {
    this.generators.set('user', () => ({
      id: faker.number.int({ min: 1, max: 10000 }),
      name: faker.person.fullName(),
      email: faker.internet.email(),
      username: faker.internet.userName(),
      phone: faker.phone.number(),
      website: faker.internet.url(),
      address: {
        street: faker.location.streetAddress(),
        city: faker.location.city(),
        zipcode: faker.location.zipCode(),
        geo: {
          lat: faker.location.latitude(),
          lng: faker.location.longitude()
        }
      },
      company: {
        name: faker.company.name(),
        catchPhrase: faker.company.catchPhrase(),
        bs: faker.company.buzzPhrase()
      }
    }));
    
    this.generators.set('product', () => ({
      id: faker.number.int({ min: 1, max: 10000 }),
      title: faker.commerce.productName(),
      price: parseFloat(faker.commerce.price()),
      description: faker.commerce.productDescription(),
      category: faker.commerce.department(),
      image: faker.image.url(),
      rating: {
        rate: faker.number.float({ min: 0, max: 5, fractionDigits: 1 }),
        count: faker.number.int({ min: 0, max: 1000 })
      }
    }));
    
    this.generators.set('order', () => ({
      id: faker.number.int({ min: 1, max: 10000 }),
      userId: faker.number.int({ min: 1, max: 100 }),
      date: faker.date.recent().toISOString(),
      products: Array.from({ length: faker.number.int({ min: 1, max: 5 }) }, () => ({
        productId: faker.number.int({ min: 1, max: 100 }),
        quantity: faker.number.int({ min: 1, max: 10 })
      })),
      total: faker.number.float({ min: 10, max: 1000, fractionDigits: 2 })
    }));
    
    this.generators.set('post', () => ({
      id: faker.number.int({ min: 1, max: 10000 }),
      title: faker.lorem.sentence(),
      body: faker.lorem.paragraphs(3),
      userId: faker.number.int({ min: 1, max: 100 }),
      tags: faker.lorem.words(3).split(' '),
      published: faker.datatype.boolean(),
      createdAt: faker.date.past().toISOString(),
      updatedAt: faker.date.recent().toISOString()
    }));
  }
  
  // Generate test data
  generate(type, count = 1, overrides = {}) {
    const generator = this.generators.get(type);
    if (!generator) {
      throw new Error(`Unknown data type: ${type}`);
    }
    
    if (count === 1) {
      return this.applyOverrides(generator(), overrides);
    }
    
    return Array.from({ length: count }, () => 
      this.applyOverrides(generator(), overrides)
    );
  }
  
  // Apply overrides to generated data
  applyOverrides(data, overrides) {
    return { ...data, ...overrides };
  }
  
  // Add custom generator
  addGenerator(type, generator) {
    this.generators.set(type, generator);
  }
  
  // Generate with specific constraints
  generateWithConstraints(type, constraints) {
    const data = this.generate(type);
    return this.applyConstraints(data, constraints);
  }
  
  // Apply constraints to data
  applyConstraints(data, constraints) {
    const constrained = { ...data };
    
    for (const [field, constraint] of Object.entries(constraints)) {
      if (constraint.type === 'range') {
        constrained[field] = faker.number.int({
          min: constraint.min,
          max: constraint.max
        });
      } else if (constraint.type === 'enum') {
        constrained[field] = faker.helpers.arrayElement(constraint.values);
      } else if (constraint.type === 'pattern') {
        constrained[field] = faker.string.alphanumeric(constraint.length);
      }
    }
    
    return constrained;
  }
}

// Test Data Builder
class TestDataBuilder {
  constructor(factory) {
    this.factory = factory;
    this.data = {};
    this.overrides = {};
  }
  
  // Start building data
  static for(type) {
    const builder = new TestDataBuilder(new TestDataFactory());
    builder.type = type;
    return builder;
  }
  
  // Set specific field
  with(field, value) {
    this.overrides[field] = value;
    return this;
  }
  
  // Set multiple fields
  withFields(fields) {
    Object.assign(this.overrides, fields);
    return this;
  }
  
  // Set nested field
  withNested(path, value) {
    const keys = path.split('.');
    let current = this.overrides;
    
    for (let i = 0; i < keys.length - 1; i++) {
      if (!current[keys[i]]) {
        current[keys[i]] = {};
      }
      current = current[keys[i]];
    }
    
    current[keys[keys.length - 1]] = value;
    return this;
  }
  
  // Set array field
  withArray(field, items) {
    this.overrides[field] = items;
    return this;
  }
  
  // Set date field
  withDate(field, date) {
    this.overrides[field] = date instanceof Date ? date.toISOString() : date;
    return this;
  }
  
  // Set email field
  withEmail(field, email) {
    this.overrides[field] = email || faker.internet.email();
    return this;
  }
  
  // Set phone field
  withPhone(field, phone) {
    this.overrides[field] = phone || faker.phone.number();
    return this;
  }
  
  // Set address field
  withAddress(field, address) {
    this.overrides[field] = address || {
      street: faker.location.streetAddress(),
      city: faker.location.city(),
      zipcode: faker.location.zipCode()
    };
    return this;
  }
  
  // Build the data
  build() {
    if (!this.type) {
      throw new Error('Data type must be specified');
    }
    
    return this.factory.generate(this.type, 1, this.overrides);
  }
  
  // Build multiple items
  buildMany(count) {
    if (!this.type) {
      throw new Error('Data type must be specified');
    }
    
    return this.factory.generate(this.type, count, this.overrides);
  }
}

// Test Data Manager
class TestDataManager {
  constructor() {
    this.factory = new TestDataFactory();
    this.dataStore = new Map();
    this.cleanupTasks = [];
    this.isolation = new Map();
  }
  
  // Create test data with isolation
  async createData(type, count = 1, overrides = {}) {
    const testId = this.generateTestId();
    const data = this.factory.generate(type, count, overrides);
    
    this.dataStore.set(testId, {
      type,
      data,
      createdAt: new Date(),
      testId
    });
    
    // Add cleanup task
    this.cleanupTasks.push({
      testId,
      type,
      action: 'delete',
      data: Array.isArray(data) ? data : [data]
    });
    
    return { testId, data };
  }
  
  // Create data with builder
  async createWithBuilder(builder) {
    const data = builder.build();
    const testId = this.generateTestId();
    
    this.dataStore.set(testId, {
      type: builder.type,
      data,
      createdAt: new Date(),
      testId
    });
    
    return { testId, data };
  }
  
  // Get data by test ID
  getData(testId) {
    const stored = this.dataStore.get(testId);
    return stored ? stored.data : null;
  }
  
  // Update data
  async updateData(testId, updates) {
    const stored = this.dataStore.get(testId);
    if (!stored) {
      throw new Error(`Test data not found: ${testId}`);
    }
    
    if (Array.isArray(stored.data)) {
      stored.data = stored.data.map(item => ({ ...item, ...updates }));
    } else {
      stored.data = { ...stored.data, ...updates };
    }
    
    stored.updatedAt = new Date();
    this.dataStore.set(testId, stored);
    
    return stored.data;
  }
  
  // Delete data
  async deleteData(testId) {
    const stored = this.dataStore.get(testId);
    if (stored) {
      this.dataStore.delete(testId);
      
      // Remove from cleanup tasks
      this.cleanupTasks = this.cleanupTasks.filter(task => task.testId !== testId);
      
      return true;
    }
    return false;
  }
  
  // Cleanup all test data
  async cleanup() {
    const cleanupResults = [];
    
    for (const task of this.cleanupTasks) {
      try {
        const result = await this.executeCleanupTask(task);
        cleanupResults.push({ task, result, success: true });
      } catch (error) {
        cleanupResults.push({ task, error: error.message, success: false });
      }
    }
    
    this.cleanupTasks = [];
    this.dataStore.clear();
    
    return cleanupResults;
  }
  
  // Execute cleanup task
  async executeCleanupTask(task) {
    // In real implementation, this would make actual API calls to delete data
    console.log(`Cleaning up ${task.type} data for test ${task.testId}`);
    return { deleted: task.data.length };
  }
  
  // Generate test ID
  generateTestId() {
    return `test_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  
  // Create data isolation
  createIsolation(testName) {
    const isolationId = `iso_${testName}_${Date.now()}`;
    this.isolation.set(isolationId, {
      testName,
      createdAt: new Date(),
      dataIds: []
    });
    
    return isolationId;
  }
  
  // Add data to isolation
  addToIsolation(isolationId, testId) {
    const isolation = this.isolation.get(isolationId);
    if (isolation) {
      isolation.dataIds.push(testId);
    }
  }
  
  // Cleanup isolation
  async cleanupIsolation(isolationId) {
    const isolation = this.isolation.get(isolationId);
    if (isolation) {
      for (const testId of isolation.dataIds) {
        await this.deleteData(testId);
      }
      this.isolation.delete(isolationId);
    }
  }
  
  // Get data statistics
  getStatistics() {
    const stats = {
      totalDataItems: this.dataStore.size,
      totalCleanupTasks: this.cleanupTasks.length,
      activeIsolations: this.isolation.size,
      dataTypes: new Map()
    };
    
    for (const [testId, stored] of this.dataStore.entries()) {
      const count = stats.dataTypes.get(stored.type) || 0;
      stats.dataTypes.set(stored.type, count + 1);
    }
    
    return stats;
  }
}

// Test Data Validator
class TestDataValidator {
  constructor() {
    this.validators = new Map();
    this.setupDefaultValidators();
  }
  
  // Setup default validators
  setupDefaultValidators() {
    this.validators.set('user', (data) => {
      const errors = [];
      
      if (!data.name || typeof data.name !== 'string') {
        errors.push('Name is required and must be a string');
      }
      
      if (!data.email || !this.isValidEmail(data.email)) {
        errors.push('Valid email is required');
      }
      
      if (data.phone && !this.isValidPhone(data.phone)) {
        errors.push('Phone number format is invalid');
      }
      
      return {
        valid: errors.length === 0,
        errors
      };
    });
    
    this.validators.set('product', (data) => {
      const errors = [];
      
      if (!data.title || typeof data.title !== 'string') {
        errors.push('Title is required and must be a string');
      }
      
      if (!data.price || typeof data.price !== 'number' || data.price <= 0) {
        errors.push('Price is required and must be a positive number');
      }
      
      if (data.rating && (data.rating.rate < 0 || data.rating.rate > 5)) {
        errors.push('Rating must be between 0 and 5');
      }
      
      return {
        valid: errors.length === 0,
        errors
      };
    });
  }
  
  // Validate data
  validate(type, data) {
    const validator = this.validators.get(type);
    if (!validator) {
      return { valid: true, errors: [] };
    }
    
    return validator(data);
  }
  
  // Validate multiple items
  validateMany(type, dataArray) {
    const results = dataArray.map((data, index) => ({
      index,
      ...this.validate(type, data)
    }));
    
    return {
      valid: results.every(r => r.valid),
      results
    };
  }
  
  // Add custom validator
  addValidator(type, validator) {
    this.validators.set(type, validator);
  }
  
  // Email validation
  isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
  
  // Phone validation
  isValidPhone(phone) {
    const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
    return phoneRegex.test(phone.replace(/[\s\-\(\)]/g, ''));
  }
}

// Test Data Seeder
class TestDataSeeder {
  constructor(manager, validator) {
    this.manager = manager;
    this.validator = validator;
    this.seeds = new Map();
  }
  
  // Add seed data
  addSeed(name, type, data) {
    this.seeds.set(name, { type, data });
  }
  
  // Seed data
  async seed(name, overrides = {}) {
    const seed = this.seeds.get(name);
    if (!seed) {
      throw new Error(`Seed not found: ${name}`);
    }
    
    const data = Array.isArray(seed.data) ? 
      seed.data.map(item => ({ ...item, ...overrides })) :
      { ...seed.data, ...overrides };
    
    // Validate data
    const validation = this.validator.validate(seed.type, data);
    if (!validation.valid) {
      throw new Error(`Seed validation failed: ${validation.errors.join(', ')}`);
    }
    
    return await this.manager.createData(seed.type, Array.isArray(data) ? data.length : 1, data);
  }
  
  // Seed multiple
  async seedMany(seeds) {
    const results = [];
    
    for (const seed of seeds) {
      try {
        const result = await this.seed(seed.name, seed.overrides);
        results.push({ seed: seed.name, result, success: true });
      } catch (error) {
        results.push({ seed: seed.name, error: error.message, success: false });
      }
    }
    
    return results;
  }
}

// Exercises and Tests
describe("Test Data Management", () => {
  let factory;
  let manager;
  let validator;
  let seeder;
  
  beforeEach(() => {
    factory = new TestDataFactory();
    manager = new TestDataManager();
    validator = new TestDataValidator();
    seeder = new TestDataSeeder(manager, validator);
  });
  
  it("should generate user test data", () => {
    const user = factory.generate('user');
    
    expect(user).to.have.property('id');
    expect(user).to.have.property('name');
    expect(user).to.have.property('email');
    expect(user).to.have.property('address');
    expect(user.address).to.have.property('street');
  });
  
  it("should generate multiple test data items", () => {
    const users = factory.generate('user', 3);
    
    expect(users).to.be.an('array');
    expect(users).to.have.length(3);
    users.forEach(user => {
      expect(user).to.have.property('id');
      expect(user).to.have.property('name');
    });
  });
  
  it("should apply overrides to generated data", () => {
    const user = factory.generate('user', 1, { name: 'John Doe', email: 'john@example.com' });
    
    expect(user.name).to.equal('John Doe');
    expect(user.email).to.equal('john@example.com');
  });
  
  it("should build data with builder pattern", () => {
    const user = TestDataBuilder.for('user')
      .with('name', 'Jane Doe')
      .with('email', 'jane@example.com')
      .withNested('address.city', 'New York')
      .build();
    
    expect(user.name).to.equal('Jane Doe');
    expect(user.email).to.equal('jane@example.com');
    expect(user.address.city).to.equal('New York');
  });
  
  it("should create and manage test data", async () => {
    const { testId, data } = await manager.createData('user', 1, { name: 'Test User' });
    
    expect(testId).to.be.a('string');
    expect(data).to.have.property('name', 'Test User');
    
    const retrieved = manager.getData(testId);
    expect(retrieved).to.deep.equal(data);
  });
  
  it("should validate test data", () => {
    const validUser = { name: 'John Doe', email: 'john@example.com' };
    const invalidUser = { name: '', email: 'invalid-email' };
    
    const validResult = validator.validate('user', validUser);
    const invalidResult = validator.validate('user', invalidUser);
    
    expect(validResult.valid).to.be.true;
    expect(invalidResult.valid).to.be.false;
    expect(invalidResult.errors).to.have.length.greaterThan(0);
  });
  
  it("should seed test data", async () => {
    seeder.addSeed('admin-user', 'user', {
      name: 'Admin User',
      email: 'admin@example.com',
      role: 'admin'
    });
    
    const { testId, data } = await seeder.seed('admin-user');
    
    expect(data.name).to.equal('Admin User');
    expect(data.email).to.equal('admin@example.com');
    expect(data.role).to.equal('admin');
  });
  
  it("should cleanup test data", async () => {
    const { testId } = await manager.createData('user', 1);
    
    const statsBefore = manager.getStatistics();
    expect(statsBefore.totalDataItems).to.equal(1);
    
    await manager.cleanup();
    
    const statsAfter = manager.getStatistics();
    expect(statsAfter.totalDataItems).to.equal(0);
  });
  
  it("should manage data isolation", async () => {
    const isolationId = manager.createIsolation('test-suite-1');
    
    const { testId } = await manager.createData('user', 1);
    manager.addToIsolation(isolationId, testId);
    
    const stats = manager.getStatistics();
    expect(stats.activeIsolations).to.equal(1);
    
    await manager.cleanupIsolation(isolationId);
    
    const statsAfter = manager.getStatistics();
    expect(statsAfter.activeIsolations).to.equal(0);
  });
});

export { 
  TestDataFactory, 
  TestDataBuilder, 
  TestDataManager, 
  TestDataValidator, 
  TestDataSeeder 
};




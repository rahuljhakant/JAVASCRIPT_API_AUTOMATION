# API Documentation

This document provides comprehensive documentation for the API testing examples and utilities in this project.

## Table of Contents

- [Getting Started](#getting-started)
- [API Clients](#api-clients)
- [Authentication](#authentication)
- [Test Utilities](#test-utilities)
- [Examples by Level](#examples-by-level)

## Getting Started

### Prerequisites

- Node.js >= 16.0.0
- npm >= 8.0.0

### Installation

```bash
cd super-api-tests
npm install
```

### Environment Setup

Copy `.env.example` to `.env` and configure your API credentials:

```bash
cp .env.example .env
```

## API Clients

### Supertest Client

The project uses Supertest for HTTP assertions:

```javascript
import supertest from "supertest";

const request = supertest("https://api.example.com");
const response = await request.get("/endpoint");
```

### Factory Pattern Client

Use the API Client Factory for flexible client creation:

```javascript
import { APIClientFactory } from "./02.5-design-patterns/01-creational-patterns/factory-pattern/api-client-factory.mjs";

const client = APIClientFactory.createSupertestClient("https://api.example.com");
const response = await client.get("/endpoint");
```

## Authentication

### Bearer Token Authentication

```javascript
const response = await request
  .get("/protected-endpoint")
  .set("Authorization", `Bearer ${process.env.API_TOKEN}`);
```

See `02-intermediate/02-authentication/bearer-token.mjs` for complete examples.

## Test Utilities

### Test Data Management

Generate test data using the TestDataFactory:

```javascript
import { TestDataFactory } from "./utils/test-data-management.mjs";

const factory = new TestDataFactory();
const user = factory.generate('user');
```

### Request Builder

Build complex requests using the Builder pattern:

```javascript
import { RequestBuilder } from "./02.5-design-patterns/01-creational-patterns/builder-pattern/request-builder.mjs";

const request = new RequestBuilder()
  .setMethod('POST')
  .setUrl('/users')
  .setHeaders({ 'Content-Type': 'application/json' })
  .setBody({ name: 'John Doe' })
  .build();
```

## Examples by Level

### Beginner Level

- **HTTP Basics**: Understanding HTTP methods and status codes
- **First API Call**: Making your first API request
- **Response Handling**: Understanding response structure

### Intermediate Level

- **CRUD Operations**: Complete Create, Read, Update, Delete examples
- **Authentication**: Bearer tokens, API keys, session management
- **Data Validation**: Schema validation and response structure

### Advanced Level

- **Complex Scenarios**: Bulk operations, pagination, filtering
- **Performance Testing**: Load testing with Artillery
- **Contract Testing**: API schema validation
- **Allure Reporting**: Professional test reporting

### Professional Level

- **Security Testing**: OWASP Top 10 compliance testing
- **Parallel Execution**: Running tests in parallel
- **Docker Integration**: Containerized testing

### Expert Level

- **AI-Powered Testing**: Test case generation
- **Cloud-Native Testing**: Kubernetes integration
- **Performance Engineering**: K6 load testing

## Best Practices

1. **Use Environment Variables**: Never hardcode API tokens or credentials
2. **Test Isolation**: Ensure tests don't depend on each other
3. **Error Handling**: Always handle errors gracefully
4. **Data Cleanup**: Clean up test data after tests complete
5. **Documentation**: Document complex test scenarios

## Additional Resources

- [Learning Path Guide](learning-path.md)
- [Security Testing Guide](security-testing-guide.md)
- [Performance Testing Guide](performance-testing-guide.md)


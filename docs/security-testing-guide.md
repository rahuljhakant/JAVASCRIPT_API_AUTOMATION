# Security Testing Guide

This guide covers security testing practices and examples in the JavaScript API Automation project.

## Table of Contents

- [Overview](#overview)
- [OWASP Top 10 Testing](#owasp-top-10-testing)
- [Authentication Testing](#authentication-testing)
- [Authorization Testing](#authorization-testing)
- [Input Validation Testing](#input-validation-testing)
- [Security Best Practices](#security-best-practices)

## Overview

Security testing is crucial for ensuring API security. This project includes comprehensive security testing examples covering OWASP Top 10 vulnerabilities and more.

## OWASP Top 10 Testing

### A01: Broken Access Control

Test for unauthorized access:

```javascript
// Test unauthorized access
const response = await request
  .get("/admin/users")
  .set("Authorization", `Bearer ${userToken}`);

expect(response.status).to.equal(403);
```

### A02: Cryptographic Failures

Test for proper encryption:

```javascript
// Verify HTTPS is used
expect(requestUrl).to.match(/^https:/);

// Verify sensitive data is encrypted
expect(response.body.password).to.be.undefined;
```

### A03: Injection

Test for SQL/NoSQL injection:

```javascript
const maliciousInput = "'; DROP TABLE users; --";
const response = await request
  .post("/users")
  .send({ name: maliciousInput });

expect(response.status).to.equal(400);
```

### A04: Insecure Design

Test business logic vulnerabilities:

```javascript
// Test for privilege escalation
const response = await request
  .put("/users/1")
  .set("Authorization", `Bearer ${lowPrivilegeToken}`)
  .send({ role: "admin" });

expect(response.status).to.equal(403);
```

### A05: Security Misconfiguration

Test for exposed sensitive information:

```javascript
// Check for debug information
const response = await request.get("/error");
expect(response.body).to.not.have.property('stack');
```

## Authentication Testing

### Token Validation

```javascript
// Test invalid token
const response = await request
  .get("/protected")
  .set("Authorization", "Bearer invalid-token");

expect(response.status).to.equal(401);
```

### Token Expiration

```javascript
// Test expired token
const expiredToken = generateExpiredToken();
const response = await request
  .get("/protected")
  .set("Authorization", `Bearer ${expiredToken}`);

expect(response.status).to.equal(401);
```

## Authorization Testing

### Role-Based Access Control

```javascript
// Test user role permissions
const userResponse = await request
  .get("/admin/users")
  .set("Authorization", `Bearer ${userToken}`);

expect(userResponse.status).to.equal(403);

const adminResponse = await request
  .get("/admin/users")
  .set("Authorization", `Bearer ${adminToken}`);

expect(adminResponse.status).to.equal(200);
```

## Input Validation Testing

### XSS Testing

```javascript
const xssPayload = "<script>alert('XSS')</script>";
const response = await request
  .post("/comments")
  .send({ content: xssPayload });

// Verify input is sanitized
expect(response.body.content).to.not.include("<script>");
```

### Path Traversal

```javascript
const maliciousPath = "../../../etc/passwd";
const response = await request
  .get(`/files/${maliciousPath}`);

expect(response.status).to.equal(400);
```

## Security Best Practices

1. **Never Hardcode Credentials**: Use environment variables
2. **Test All Authentication Flows**: Login, logout, token refresh
3. **Validate All Inputs**: Test boundary conditions
4. **Check Error Messages**: Ensure no sensitive data leakage
5. **Test Rate Limiting**: Verify DDoS protection
6. **Verify HTTPS**: Ensure all endpoints use HTTPS
7. **Check CORS Configuration**: Verify proper CORS setup

## Security Testing Examples

See the following files for complete examples:

- `04-professional/02-security-testing/01-owasp-top-10/owasp-comprehensive-testing.mjs`
- `04-professional/02-security-testing/02-penetration-testing/penetration-testing-suite.mjs`
- `04-professional/02-security-testing/03-vulnerability-scanning/vulnerability-assessment.mjs`

## Tools and Resources

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **OWASP API Security**: https://owasp.org/www-project-api-security/
- **Security Headers**: Check for proper security headers

## Reporting Security Issues

If you discover a security vulnerability, please:

1. **Do NOT** create a public issue
2. Email security concerns privately
3. Provide detailed information about the vulnerability
4. Allow time for the issue to be addressed before disclosure


# Web Application Security Testing Tutorials

## ⚠️ IMPORTANT DISCLAIMER

**These tutorials are for EDUCATIONAL AND SECURITY TESTING PURPOSES ONLY.**

- Only test applications you own or have explicit written permission to test
- Never use these techniques on systems without authorization
- Unauthorized access to computer systems is illegal
- Use these skills responsibly and ethically

## Tutorials

### 1. SQL Injection Testing
**File:** `01_sql_injection_testing.mjs`

**Learning Objectives:**
- Understand SQL injection vulnerabilities
- Test for SQL injection in API endpoints
- Implement proper input validation
- Learn defensive coding practices

**Steps:**
1. Understanding SQL Injection
2. Testing for SQL Injection
3. Input Sanitization
4. Input Validation
5. Parameterized Queries
6. Best Practices

**Key Concepts:**
- SQL injection payloads
- Error-based detection
- Time-based detection
- Blind SQL injection
- Input validation
- Parameterized queries

## Running the Tutorials

```bash
# Run SQL injection testing tutorial
npm test -- educational_hacking_tutorials/01_web_application_security/01_sql_injection_testing.mjs
```

## Security Best Practices

1. **Always use parameterized queries** - Never concatenate user input into SQL queries
2. **Validate all inputs** - Check type, format, and range
3. **Sanitize inputs** - Remove or escape dangerous characters
4. **Use least privilege** - Database accounts should have minimal permissions
5. **Implement input whitelisting** - Only allow known good values
6. **Regular security testing** - Include security tests in CI/CD pipeline
7. **Error handling** - Don't expose SQL errors to users
8. **Keep software updated** - Apply security patches promptly

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

## Legal and Ethical Guidelines

- ✅ Test only systems you own or have permission to test
- ✅ Report vulnerabilities responsibly
- ✅ Follow responsible disclosure practices
- ❌ Never access systems without authorization
- ❌ Never cause damage or data loss
- ❌ Never use knowledge for malicious purposes


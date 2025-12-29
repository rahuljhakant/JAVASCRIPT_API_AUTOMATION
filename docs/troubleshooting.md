# Troubleshooting Guide

This guide helps resolve common issues when working with the JavaScript API Automation project.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Test Execution Issues](#test-execution-issues)
- [Configuration Issues](#configuration-issues)
- [Docker Issues](#docker-issues)
- [Performance Issues](#performance-issues)
- [Common Errors](#common-errors)

## Installation Issues

### Node.js Version Mismatch

**Problem**: Error about Node.js version

**Solution**:
```bash
# Check Node.js version
node --version

# Should be >= 16.0.0
# Install correct version using nvm
nvm install 18
nvm use 18
```

### npm Install Fails

**Problem**: `npm install` fails with errors

**Solutions**:
```bash
# Clear npm cache
npm cache clean --force

# Delete node_modules and package-lock.json
rm -rf node_modules package-lock.json

# Reinstall
npm install
```

### Permission Errors

**Problem**: Permission denied errors

**Solution**:
```bash
# Fix npm permissions (Linux/Mac)
sudo chown -R $(whoami) ~/.npm
sudo chown -R $(whoami) /usr/local/lib/node_modules

# Or use nvm to avoid permission issues
```

## Test Execution Issues

### Tests Not Found

**Problem**: Mocha can't find test files

**Solution**:
```bash
# Check test file paths
# Ensure files have .mjs extension
# Run from correct directory
cd super-api-tests
npm test
```

### Environment Variables Not Loading

**Problem**: `process.env` variables are undefined

**Solution**:
```bash
# Ensure .env file exists
cp .env.example .env

# Verify dotenv is imported
import dotenv from "dotenv";
dotenv.config();

# Check .env file is in correct location
```

### API Connection Errors

**Problem**: Cannot connect to API endpoints

**Solutions**:
1. Check internet connection
2. Verify API base URL in `.env`
3. Check API token is valid
4. Verify API endpoint is accessible:
   ```bash
   curl https://api.example.com/health
   ```

### Timeout Errors

**Problem**: Tests timeout before completion

**Solution**:
```javascript
// Increase timeout in test
it("should complete", async function() {
  this.timeout(10000); // 10 seconds
  // test code
});
```

## Configuration Issues

### ESLint Errors

**Problem**: ESLint reports errors

**Solution**:
```bash
# Auto-fix issues
npm run lint:fix

# Or manually fix according to .eslintrc.js rules
```

### Prettier Formatting Issues

**Problem**: Code formatting doesn't match

**Solution**:
```bash
# Format all files
npm run format

# Check formatting
npx prettier --check .
```

### Mocha Configuration

**Problem**: Mocha not using correct configuration

**Solution**:
- Check `mocharc.yaml` or `mocharc.json`
- Verify configuration file location
- Check for conflicting configurations

## Docker Issues

### Docker Build Fails

**Problem**: `docker build` fails

**Solutions**:
```bash
# Check Dockerfile syntax
docker build --no-cache -t api-automation .

# Check Docker daemon is running
docker info

# Clear Docker cache
docker system prune -a
```

### Container Won't Start

**Problem**: Docker container exits immediately

**Solution**:
```bash
# Check logs
docker-compose logs api-automation

# Run container interactively
docker run -it api-automation /bin/sh

# Check environment variables
docker-compose config
```

### Port Conflicts

**Problem**: Port already in use

**Solution**:
```bash
# Find process using port
lsof -i :3000

# Kill process or change port in docker-compose.yml
# Update port mapping: "3001:3000"
```

### Docker Compose Issues

**Problem**: Services don't start correctly

**Solution**:
```bash
# Stop all services
docker-compose down

# Remove volumes
docker-compose down -v

# Rebuild and start
docker-compose up --build
```

## Performance Issues

### Slow Test Execution

**Problem**: Tests run very slowly

**Solutions**:
1. Run tests in parallel:
   ```bash
   npm run test:parallel
   ```
2. Reduce test data size
3. Use test timeouts appropriately
4. Check network latency

### Memory Issues

**Problem**: Out of memory errors

**Solution**:
```bash
# Increase Node.js memory
node --max-old-space-size=4096 node_modules/.bin/mocha

# Or in package.json
"test": "node --max-old-space-size=4096 node_modules/.bin/mocha"
```

## Common Errors

### "Cannot find module"

**Error**: `Error: Cannot find module 'module-name'`

**Solution**:
```bash
# Install missing module
npm install module-name

# Or reinstall all dependencies
rm -rf node_modules package-lock.json
npm install
```

### "SyntaxError: Unexpected token"

**Error**: Syntax errors in .mjs files

**Solution**:
- Ensure file has `.mjs` extension
- Check for ES6+ syntax compatibility
- Verify `"type": "module"` in package.json

### "EADDRINUSE: address already in use"

**Error**: Port already in use

**Solution**:
```bash
# Find and kill process
lsof -ti:3000 | xargs kill -9

# Or use different port
PORT=3001 npm start
```

### "ENOTFOUND" Errors

**Error**: DNS resolution fails

**Solution**:
- Check internet connection
- Verify API URL is correct
- Check DNS settings
- Try using IP address instead of domain

### Authentication Errors

**Error**: 401 Unauthorized

**Solution**:
1. Verify API token in `.env`
2. Check token hasn't expired
3. Verify token format (Bearer token)
4. Check authorization header format

## Getting Help

### Check Logs

```bash
# Application logs
tail -f logs/app.log

# Docker logs
docker-compose logs -f

# Test output
npm test -- --reporter spec
```

### Debug Mode

```bash
# Enable debug logging
DEBUG=* npm test

# Or set log level
LOG_LEVEL=debug npm test
```

### Common Commands

```bash
# Check Node.js version
node --version

# Check npm version
npm --version

# List installed packages
npm list --depth=0

# Check for outdated packages
npm outdated

# Verify environment
printenv | grep API
```

## Additional Resources

- [Node.js Troubleshooting](https://nodejs.org/en/docs/guides/troubleshooting/)
- [Mocha Documentation](https://mochajs.org/)
- [Docker Troubleshooting](https://docs.docker.com/config/troubleshooting/)

## Still Having Issues?

1. Check [GitHub Issues](https://github.com/your-username/javascript-api-automation/issues)
2. Review project documentation
3. Check example files for reference
4. Create a new issue with:
   - Error message
   - Steps to reproduce
   - Environment details
   - Relevant code snippets


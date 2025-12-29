# Performance Testing Guide

This guide covers performance testing practices and tools in the JavaScript API Automation project.

## Table of Contents

- [Overview](#overview)
- [Performance Testing Types](#performance-testing-types)
- [Tools and Frameworks](#tools-and-frameworks)
- [Performance Metrics](#performance-metrics)
- [Best Practices](#best-practices)

## Overview

Performance testing ensures APIs meet performance requirements under various load conditions.

## Performance Testing Types

### Load Testing

Test API performance under expected load:

```javascript
// Artillery load test example
const artillery = require('artillery');
const testScript = {
  config: {
    target: 'https://api.example.com',
    phases: [
      { duration: 60, arrivalRate: 10 }
    ]
  },
  scenarios: [{
    name: 'Get users',
    flow: [
      { get: { url: '/users' } }
    ]
  }]
};
```

### Stress Testing

Test API behavior beyond normal capacity:

```javascript
// Stress test with increasing load
const stressTest = {
  config: {
    target: 'https://api.example.com',
    phases: [
      { duration: 60, arrivalRate: 10 },
      { duration: 60, arrivalRate: 50 },
      { duration: 60, arrivalRate: 100 }
    ]
  }
};
```

### Spike Testing

Test API response to sudden load spikes:

```javascript
// Spike test
const spikeTest = {
  config: {
    target: 'https://api.example.com',
    phases: [
      { duration: 10, arrivalRate: 10 },
      { duration: 1, arrivalRate: 1000 }, // Spike
      { duration: 10, arrivalRate: 10 }
    ]
  }
};
```

## Tools and Frameworks

### Artillery

Artillery is a modern load testing toolkit:

```bash
npm install -g artillery
artillery quick --count 10 --num 100 https://api.example.com/users
```

See `04-professional/03-performance-testing/artillery-load-testing.mjs` for examples.

### K6

K6 is a modern load testing tool:

```javascript
import http from 'k6/http';
import { check } from 'k6';

export default function () {
  const response = http.get('https://api.example.com/users');
  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 500ms': (r) => r.timings.duration < 500,
  });
}
```

See `05-expert/04-performance-engineering/k6-load-testing.mjs` for examples.

### Autocannon

Autocannon is a fast HTTP benchmarking tool:

```javascript
const autocannon = require('autocannon');

autocannon({
  url: 'https://api.example.com',
  connections: 10,
  duration: 10
}, console.log);
```

## Performance Metrics

### Response Time

Measure API response time:

```javascript
const startTime = Date.now();
const response = await request.get("/users");
const responseTime = Date.now() - startTime;

expect(responseTime).to.be.lessThan(500); // 500ms threshold
```

### Throughput

Measure requests per second:

```javascript
const requests = 100;
const startTime = Date.now();

for (let i = 0; i < requests; i++) {
  await request.get("/users");
}

const duration = (Date.now() - startTime) / 1000; // seconds
const throughput = requests / duration;

console.log(`Throughput: ${throughput} req/s`);
```

### Error Rate

Monitor error rates under load:

```javascript
let errors = 0;
const totalRequests = 100;

for (let i = 0; i < totalRequests; i++) {
  try {
    const response = await request.get("/users");
    if (response.status >= 400) errors++;
  } catch (error) {
    errors++;
  }
}

const errorRate = (errors / totalRequests) * 100;
expect(errorRate).to.be.lessThan(1); // Less than 1% errors
```

## Best Practices

1. **Set Performance Baselines**: Establish acceptable performance metrics
2. **Test Realistic Scenarios**: Use production-like data and load patterns
3. **Monitor Resources**: Track CPU, memory, and network usage
4. **Test Incrementally**: Start with low load and gradually increase
5. **Test Different Endpoints**: Not all endpoints have the same performance characteristics
6. **Consider Caching**: Test with and without caching
7. **Monitor Degradation**: Track performance over time

## Performance Testing Examples

See the following files for complete examples:

- `04-professional/03-performance-testing/artillery-load-testing.mjs`
- `05-expert/04-performance-engineering/k6-load-testing.mjs`

## Performance Targets

Typical performance targets:

- **Response Time**: < 200ms for simple requests, < 1s for complex requests
- **Throughput**: > 1000 requests/second for high-traffic APIs
- **Error Rate**: < 0.1% under normal load
- **Availability**: > 99.9% uptime

## Tools Comparison

| Tool | Use Case | Pros | Cons |
|------|----------|------|------|
| Artillery | General load testing | Easy to use, good reporting | Limited scripting |
| K6 | Advanced load testing | Powerful scripting, good metrics | Steeper learning curve |
| Autocannon | Quick benchmarking | Very fast, simple | Limited features |

## Additional Resources

- [Artillery Documentation](https://www.artillery.io/docs)
- [K6 Documentation](https://k6.io/docs/)
- [Performance Testing Best Practices](https://www.thoughtworks.com/insights/blog/performance-testing-best-practices)


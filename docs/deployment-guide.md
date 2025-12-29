# Deployment Guide

This guide covers deployment options and best practices for the JavaScript API Automation project.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Local Deployment](#local-deployment)
- [Docker Deployment](#docker-deployment)
- [CI/CD Integration](#cicd-integration)
- [Cloud Deployment](#cloud-deployment)
- [Monitoring](#monitoring)

## Prerequisites

- Node.js >= 16.0.0
- npm >= 8.0.0
- Docker (for containerized deployment)
- Git

## Local Deployment

### Installation

```bash
# Clone repository
git clone https://github.com/your-username/javascript-api-automation.git
cd javascript-api-automation

# Install dependencies
cd super-api-tests
npm install
```

### Configuration

1. Copy environment template:
   ```bash
   cp .env.example .env
   ```

2. Configure environment variables in `.env`

3. Run tests:
   ```bash
   npm test
   ```

## Docker Deployment

### Building the Image

```bash
docker build -t api-automation .
```

### Running with Docker Compose

```bash
docker-compose up -d
```

This starts all services:
- API Automation App (Port 3000)
- Redis (Port 6379)
- Elasticsearch (Port 9200)
- Kibana (Port 5601)
- Prometheus (Port 9090)
- Grafana (Port 3001)
- PostgreSQL (Port 5432)
- MongoDB (Port 27017)

### Docker Services

See `docker-compose.yml` for complete service configuration.

## CI/CD Integration

### GitHub Actions

The project includes GitHub Actions workflow (`.github/workflows/advanced-ci-cd.yml`):

```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm install
      - run: npm test
```

### Jenkins

Jenkins pipeline configuration is in `Jenkinsfile`:

```groovy
pipeline {
    agent any
    stages {
        stage('Test') {
            steps {
                sh 'npm install'
                sh 'npm test'
            }
        }
    }
}
```

### GitLab CI

GitLab CI configuration is in `config/ci-cd/gitlab-ci.yml`.

## Cloud Deployment

### AWS Deployment

1. **EC2 Instance**:
   ```bash
   # Install Node.js
   curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
   sudo yum install -y nodejs

   # Deploy application
   git clone <repository>
   cd javascript-api-automation/super-api-tests
   npm install
   npm start
   ```

2. **ECS/Fargate**:
   - Build Docker image
   - Push to ECR
   - Deploy using ECS task definition

3. **Lambda** (Serverless):
   - Package application
   - Deploy as Lambda function
   - Configure API Gateway

### Azure Deployment

1. **Azure App Service**:
   ```bash
   az webapp create --resource-group myResourceGroup --plan myAppServicePlan --name myAppName
   az webapp deployment source config --name myAppName --resource-group myResourceGroup --repo-url <repo-url>
   ```

2. **Azure Container Instances**:
   - Build and push Docker image
   - Deploy to ACI

### GCP Deployment

1. **Cloud Run**:
   ```bash
   gcloud run deploy api-automation --source .
   ```

2. **Compute Engine**:
   - Create VM instance
   - Install Node.js
   - Deploy application

## Monitoring

### Prometheus

Prometheus is configured to collect metrics:

- Access at: `http://localhost:9090`
- Configuration: `config/monitoring/prometheus.yml`

### Grafana

Grafana provides visualization:

- Access at: `http://localhost:3001`
- Default credentials: `admin/admin123`
- Dashboards: `config/monitoring/grafana-dashboards/`

### Elasticsearch & Kibana

Log aggregation and analysis:

- Elasticsearch: `http://localhost:9200`
- Kibana: `http://localhost:5601`

## Environment-Specific Configuration

### Development

```bash
NODE_ENV=development
npm run dev
```

### Staging

```bash
NODE_ENV=staging
npm test
```

### Production

```bash
NODE_ENV=production
npm start
```

Configuration files:
- `config/environments/development.json`
- `config/environments/staging.json`
- `config/environments/production.json`

## Health Checks

The application includes health check endpoints:

```bash
curl http://localhost:3000/health
```

## Scaling

### Horizontal Scaling

- Use load balancer (Nginx, HAProxy)
- Deploy multiple instances
- Configure session storage (Redis)

### Vertical Scaling

- Increase instance resources
- Optimize application code
- Use caching strategies

## Backup and Recovery

1. **Database Backups**: Regular automated backups
2. **Configuration Backups**: Version control for configs
3. **Disaster Recovery Plan**: Document recovery procedures

## Security Considerations

1. **Secrets Management**: Use environment variables or secret managers
2. **HTTPS**: Always use HTTPS in production
3. **Firewall Rules**: Restrict access to necessary ports
4. **Regular Updates**: Keep dependencies updated
5. **Security Scanning**: Regular vulnerability scans

## Troubleshooting

### Common Issues

1. **Port Conflicts**: Check if ports are already in use
2. **Environment Variables**: Verify `.env` file is configured
3. **Dependencies**: Run `npm install` if issues occur
4. **Docker Issues**: Check Docker daemon is running

### Logs

Check application logs:

```bash
# Docker logs
docker-compose logs -f api-automation

# Application logs
tail -f logs/app.log
```

## Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [CI/CD Best Practices](https://www.atlassian.com/continuous-delivery/ci-cd)


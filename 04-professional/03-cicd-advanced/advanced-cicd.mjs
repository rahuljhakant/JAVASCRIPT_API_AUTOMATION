/**
 * PHASE 4: PROFESSIONAL LEVEL
 * Module 3: Advanced CI/CD
 * Lesson 1: Advanced CI/CD Patterns
 * 
 * Learning Objectives:
 * - Implement advanced CI/CD patterns
 * - Create multi-stage deployment pipelines
 * - Integrate with multiple CI/CD platforms
 * - Implement blue-green and canary deployments
 */

import { expect } from "chai";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

console.log("=== ADVANCED CI/CD ===");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__dirname);

// CI/CD Platform Configurations
class CICDPlatformConfig {
  static generateGitHubActions() {
    return `
name: API Tests CI/CD

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [16.x, 18.x, 20.x]
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Use Node.js \${{ matrix.node-version }}
      uses: actions/setup-node@v3
      with:
        node-version: \${{ matrix.node-version }}
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run tests
      run: npm test
      env:
        API_BASE_URL: \${{ secrets.API_BASE_URL }}
        API_TOKEN: \${{ secrets.API_TOKEN }}
    
    - name: Generate coverage report
      run: npm run coverage
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage/coverage-final.json
    
    - name: Publish test results
      uses: dorny/test-reporter@v1
      if: always()
      with:
        name: API Test Results
        path: test-results/*.xml
        reporter: java-junit
    
    - name: Archive test results
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: test-results
        path: test-results/

  deploy:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Deploy to staging
      run: |
        echo "Deploying to staging environment..."
        # Add deployment commands here
    
    - name: Run smoke tests
      run: npm run test:smoke
      env:
        API_BASE_URL: \${{ secrets.STAGING_API_URL }}
`;
  }

  static generateGitLabCI() {
    return `
stages:
  - test
  - deploy-staging
  - deploy-production

variables:
  NODE_VERSION: "18"

test:
  stage: test
  image: node:\${NODE_VERSION}
  before_script:
    - npm ci
  script:
    - npm test
    - npm run coverage
  coverage: '/Lines\\s*:\\s*\\d+.\\d+%/'
  artifacts:
    reports:
      junit: test-results/*.xml
    paths:
      - coverage/
      - test-results/
    expire_in: 1 week
  only:
    - merge_requests
    - main
    - develop

deploy-staging:
  stage: deploy-staging
  image: node:\${NODE_VERSION}
  script:
    - echo "Deploying to staging..."
    - npm run deploy:staging
  environment:
    name: staging
    url: https://staging.example.com
  only:
    - main
  when: manual

deploy-production:
  stage: deploy-production
  image: node:\${NODE_VERSION}
  script:
    - echo "Deploying to production..."
    - npm run deploy:production
  environment:
    name: production
    url: https://api.example.com
  only:
    - main
  when: manual
`;
  }

  static generateCircleCI() {
    return `
version: 2.1

orbs:
  node: circleci/node@5.0.0

workflows:
  test-and-deploy:
    jobs:
      - test:
          matrix:
            parameters:
              node-version: ["16", "18", "20"]
      - deploy-staging:
          requires:
            - test
          filters:
            branches:
              only: main
      - deploy-production:
          requires:
            - deploy-staging
          filters:
            branches:
              only: main

jobs:
  test:
    docker:
      - image: cimg/node:\${<< matrix.node-version >>}
    steps:
      - checkout
      - node/install-packages:
          pkg-manager: npm
      - run:
          name: Run tests
          command: npm test
      - run:
          name: Generate coverage
          command: npm run coverage
      - store_test_results:
          path: test-results
      - store_artifacts:
          path: coverage

  deploy-staging:
    docker:
      - image: cimg/node:18
    steps:
      - checkout
      - run:
          name: Deploy to staging
          command: npm run deploy:staging

  deploy-production:
    docker:
      - image: cimg/node:18
    steps:
      - checkout
      - run:
          name: Deploy to production
          command: npm run deploy:production
`;
  }
}

// Deployment Strategy Patterns
class DeploymentStrategy {
  static generateBlueGreen() {
    return `
# Blue-Green Deployment Strategy
# 
# 1. Deploy new version to "green" environment
# 2. Run smoke tests on green environment
# 3. Switch traffic from blue to green
# 4. Monitor for issues
# 5. Keep blue as rollback option

deploy-blue-green:
  stages:
    - deploy-green
    - test-green
    - switch-traffic
    - monitor
    - cleanup-blue

  deploy-green:
    script:
      - echo "Deploying to green environment..."
      - kubectl apply -f k8s/green-deployment.yaml
      - kubectl rollout status deployment/api-green
    
  test-green:
    script:
      - echo "Running smoke tests on green..."
      - npm run test:smoke -- --env=green
      - npm run test:api -- --env=green
  
  switch-traffic:
    script:
      - echo "Switching traffic to green..."
      - kubectl patch service api -p '{"spec":{"selector":{"version":"green"}}}'
  
  monitor:
    script:
      - echo "Monitoring green deployment..."
      - sleep 300
      - npm run test:health -- --env=green
  
  cleanup-blue:
    script:
      - echo "Cleaning up blue environment..."
      - kubectl delete deployment api-blue
`;
  }

  static generateCanary() {
    return `
# Canary Deployment Strategy
#
# 1. Deploy new version to small percentage of traffic
# 2. Monitor metrics and errors
# 3. Gradually increase traffic percentage
# 4. Full rollout or rollback based on metrics

deploy-canary:
  stages:
    - deploy-canary-10
    - monitor-canary-10
    - deploy-canary-50
    - monitor-canary-50
    - deploy-canary-100
    - monitor-canary-100

  deploy-canary-10:
    script:
      - echo "Deploying canary to 10% traffic..."
      - kubectl set weight api-canary=10 api-stable=90
  
  monitor-canary-10:
    script:
      - echo "Monitoring 10% canary..."
      - sleep 600
      - npm run test:metrics -- --env=canary
      - npm run test:api -- --env=canary
  
  deploy-canary-50:
    script:
      - echo "Increasing canary to 50%..."
      - kubectl set weight api-canary=50 api-stable=50
  
  monitor-canary-50:
    script:
      - echo "Monitoring 50% canary..."
      - sleep 600
      - npm run test:metrics -- --env=canary
  
  deploy-canary-100:
    script:
      - echo "Full rollout to 100%..."
      - kubectl set weight api-canary=100 api-stable=0
`;
  }
}

// Test Scenarios
async function testGitHubActions() {
  console.log("\n📝 Test 1: GitHub Actions Configuration");
  
  const config = CICDPlatformConfig.generateGitHubActions();
  const configPath = path.join(__dirname, "../../../.github/workflows/api-tests.yml");
  
  // Ensure .github/workflows directory exists
  const workflowsDir = path.dirname(configPath);
  if (!fs.existsSync(workflowsDir)) {
    fs.mkdirSync(workflowsDir, { recursive: true });
  }
  
  fs.writeFileSync(configPath, config);
  
  expect(fs.existsSync(configPath)).to.be.true;
  expect(config).to.include('name: API Tests CI/CD');
  expect(config).to.include('jobs:');
  
  console.log(`✅ GitHub Actions config generated: ${configPath}`);
}

async function testGitLabCI() {
  console.log("\n📝 Test 2: GitLab CI Configuration");
  
  const config = CICDPlatformConfig.generateGitLabCI();
  const configPath = path.join(__dirname, "../../../.gitlab-ci.yml");
  
  fs.writeFileSync(configPath, config);
  
  expect(fs.existsSync(configPath)).to.be.true;
  expect(config).to.include('stages:');
  
  console.log(`✅ GitLab CI config generated: ${configPath}`);
}

async function testCircleCI() {
  console.log("\n📝 Test 3: CircleCI Configuration");
  
  const config = CICDPlatformConfig.generateCircleCI();
  const configPath = path.join(__dirname, "../../../.circleci/config.yml");
  
  // Ensure .circleci directory exists
  const circleciDir = path.dirname(configPath);
  if (!fs.existsSync(circleciDir)) {
    fs.mkdirSync(circleciDir, { recursive: true });
  }
  
  fs.writeFileSync(configPath, config);
  
  expect(fs.existsSync(configPath)).to.be.true;
  expect(config).to.include('version:');
  
  console.log(`✅ CircleCI config generated: ${configPath}`);
}

async function testDeploymentStrategies() {
  console.log("\n📝 Test 4: Deployment Strategies");
  
  const blueGreen = DeploymentStrategy.generateBlueGreen();
  const canary = DeploymentStrategy.generateCanary();
  
  const blueGreenPath = path.join(__dirname, "../../../deployment-blue-green.yml");
  const canaryPath = path.join(__dirname, "../../../deployment-canary.yml");
  
  fs.writeFileSync(blueGreenPath, blueGreen);
  fs.writeFileSync(canaryPath, canary);
  
  expect(fs.existsSync(blueGreenPath)).to.be.true;
  expect(fs.existsSync(canaryPath)).to.be.true;
  
  console.log(`✅ Blue-Green deployment strategy: ${blueGreenPath}`);
  console.log(`✅ Canary deployment strategy: ${canaryPath}`);
}

// Run all tests
(async () => {
  try {
    await testGitHubActions();
    await testGitLabCI();
    await testCircleCI();
    await testDeploymentStrategies();
    
    console.log("\n✅ All advanced CI/CD tests completed!");
    console.log("\n💡 CI/CD configurations are ready to use.");
  } catch (error) {
    console.error("❌ CI/CD test failed:", error.message);
    process.exit(1);
  }
})();


/**
 * PHASE 4: PROFESSIONAL LEVEL
 * Module 2: Jenkins Integration
 * Lesson 1: Jenkins Pipeline for API Testing
 * 
 * Learning Objectives:
 * - Create Jenkins pipelines for API testing
 * - Integrate tests into CI/CD workflows
 * - Configure Jenkins jobs for automated testing
 * - Generate and publish test reports
 */

import { expect } from "chai";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

console.log("=== JENKINS INTEGRATION ===");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Jenkins Pipeline Generator
class JenkinsPipelineGenerator {
  constructor() {
    this.pipelines = [];
  }

  generateDeclarativePipeline(config) {
    const {
      name = "API Tests",
      stages = [],
      postActions = [],
      environment = {},
      tools = {}
    } = config;

    const pipeline = `
pipeline {
    agent any
    
    ${tools.nodejs ? `tools {
        nodejs '${tools.nodejs}'
    }` : ''}
    
    ${Object.keys(environment).length > 0 ? `environment {
${Object.entries(environment).map(([key, value]) => `        ${key} = '${value}'`).join('\n')}
    }` : ''}
    
    stages {
${stages.map(stage => this.generateStage(stage)).join('\n')}
    }
    
    post {
        always {
            echo 'Pipeline execution completed'
            ${postActions.includes('archive') ? `archiveArtifacts artifacts: 'test-results/**/*', allowEmptyArchive: true` : ''}
            ${postActions.includes('publish') ? `publishTestResults testResultsPattern: 'test-results/*.xml'` : ''}
        }
        success {
            echo 'All tests passed successfully!'
        }
        failure {
            echo 'Pipeline failed. Check logs for details.'
        }
    }
}
`;

    return pipeline;
  }

  generateStage(stage) {
    const { name, steps, parallel = false } = stage;

    if (parallel) {
      return `        stage('${name}') {
            parallel {
${steps.map(step => this.generateParallelStep(step)).join('\n')}
            }
        }`;
    }

    return `        stage('${name}') {
${steps.map(step => this.generateStep(step)).join('\n')}
        }`;
  }

  generateStep(step) {
    if (typeof step === 'string') {
      return `            ${step}`;
    }

    const { type, command, script } = step;

    switch (type) {
      case 'sh':
        return `            sh '''${command}'''`;
      case 'echo':
        return `            echo '${command}'`;
      case 'script':
        return `            script {
                ${script}
            }`;
      default:
        return `            ${command}`;
    }
  }

  generateParallelStep(step) {
    return `                '${step.name}': {
${step.steps.map(s => this.generateStep(s)).join('\n')}
                }`;
  }

  generateScriptedPipeline(config) {
    const { stages = [] } = config;

    const pipeline = `
node {
    stage('Checkout') {
        checkout scm
    }
    
${stages.map(stage => `
    stage('${stage.name}') {
${stage.steps.map(step => `        ${step}`).join('\n')}
    }`).join('\n')}
    
    stage('Publish Results') {
        publishTestResults testResultsPattern: 'test-results/*.xml'
        archiveArtifacts artifacts: 'test-results/**/*', allowEmptyArchive: true
    }
}
`;

    return pipeline;
  }
}

// Jenkins Job Configuration
class JenkinsJobConfig {
  constructor() {
    this.configs = [];
  }

  createBasicJob(name, pipelineScript) {
    return {
      name,
      type: 'pipeline',
      script: pipelineScript,
      description: `Automated API testing pipeline for ${name}`
    };
  }

  createMultibranchJob(name, pipelineScript) {
    return {
      name,
      type: 'multibranch-pipeline',
      script: pipelineScript,
      branchSources: ['github', 'gitlab', 'bitbucket'],
      description: `Multibranch pipeline for ${name}`
    };
  }
}

// Test Scenarios
async function testDeclarativePipeline() {
  console.log("\n📝 Test 1: Declarative Pipeline Generation");
  
  const generator = new JenkinsPipelineGenerator();
  
  const config = {
    name: "API Test Pipeline",
    tools: {
      nodejs: 'NodeJS-18'
    },
    environment: {
      NODE_ENV: 'test',
      API_BASE_URL: 'https://gorest.co.in/public-api'
    },
    stages: [
      {
        name: 'Checkout',
        steps: [
          'checkout scm'
        ]
      },
      {
        name: 'Install Dependencies',
        steps: [
          { type: 'sh', command: 'npm ci' }
        ]
      },
      {
        name: 'Run Tests',
        steps: [
          { type: 'sh', command: 'npm test' }
        ]
      },
      {
        name: 'Generate Reports',
        steps: [
          { type: 'sh', command: 'npm run report' }
        ]
      }
    ],
    postActions: ['archive', 'publish']
  };

  const pipeline = generator.generateDeclarativePipeline(config);
  
  const pipelinePath = path.join(__dirname, "../../../Jenkinsfile.declarative");
  fs.writeFileSync(pipelinePath, pipeline);
  
  expect(fs.existsSync(pipelinePath)).to.be.true;
  expect(pipeline).to.include('pipeline {');
  expect(pipeline).to.include('stages {');
  
  console.log(`✅ Declarative pipeline generated: ${pipelinePath}`);
}

async function testScriptedPipeline() {
  console.log("\n📝 Test 2: Scripted Pipeline Generation");
  
  const generator = new JenkinsPipelineGenerator();
  
  const config = {
    stages: [
      {
        name: 'Setup',
        steps: [
          'sh "npm install"'
        ]
      },
      {
        name: 'Test',
        steps: [
          'sh "npm test"'
        ]
      }
    ]
  };

  const pipeline = generator.generateScriptedPipeline(config);
  
  const pipelinePath = path.join(__dirname, "../../../Jenkinsfile.scripted");
  fs.writeFileSync(pipelinePath, pipeline);
  
  expect(fs.existsSync(pipelinePath)).to.be.true;
  expect(pipeline).to.include('node {');
  
  console.log(`✅ Scripted pipeline generated: ${pipelinePath}`);
}

async function testParallelStages() {
  console.log("\n📝 Test 3: Parallel Execution Pipeline");
  
  const generator = new JenkinsPipelineGenerator();
  
  const config = {
    name: "Parallel API Tests",
    stages: [
      {
        name: 'Parallel Tests',
        parallel: true,
        steps: [
          {
            name: 'Unit Tests',
            steps: [
              { type: 'sh', command: 'npm run test:unit' }
            ]
          },
          {
            name: 'Integration Tests',
            steps: [
              { type: 'sh', command: 'npm run test:integration' }
            ]
          },
          {
            name: 'E2E Tests',
            steps: [
              { type: 'sh', command: 'npm run test:e2e' }
            ]
          }
        ]
      }
    ],
    postActions: ['archive']
  };

  const pipeline = generator.generateDeclarativePipeline(config);
  
  const pipelinePath = path.join(__dirname, "../../../Jenkinsfile.parallel");
  fs.writeFileSync(pipelinePath, pipeline);
  
  expect(pipeline).to.include('parallel {');
  
  console.log(`✅ Parallel pipeline generated: ${pipelinePath}`);
}

async function testJobConfiguration() {
  console.log("\n📝 Test 4: Jenkins Job Configuration");
  
  const jobConfig = new JenkinsJobConfig();
  
  const generator = new JenkinsPipelineGenerator();
  const pipelineScript = generator.generateDeclarativePipeline({
    name: "API Tests",
    stages: [
      {
        name: 'Test',
        steps: [
          { type: 'sh', command: 'npm test' }
        ]
      }
    ]
  });
  
  const basicJob = jobConfig.createBasicJob('api-tests', pipelineScript);
  const multibranchJob = jobConfig.createMultibranchJob('api-tests-multibranch', pipelineScript);
  
  expect(basicJob.name).to.equal('api-tests');
  expect(basicJob.type).to.equal('pipeline');
  expect(multibranchJob.type).to.equal('multibranch-pipeline');
  
  console.log("✅ Job configurations created");
  console.log("\n📋 Jenkins Job Setup Instructions:");
  console.log("   1. Go to Jenkins Dashboard");
  console.log("   2. Click 'New Item'");
  console.log("   3. Enter job name and select 'Pipeline'");
  console.log("   4. In Pipeline section, select 'Pipeline script from SCM'");
  console.log("   5. Configure SCM (Git) and specify Jenkinsfile path");
  console.log("   6. Save and run the pipeline");
}

// Run all tests
(async () => {
  try {
    await testDeclarativePipeline();
    await testScriptedPipeline();
    await testParallelStages();
    await testJobConfiguration();
    
    console.log("\n✅ All Jenkins integration tests completed!");
    console.log("\n💡 Generated Jenkinsfiles are ready to use in Jenkins.");
  } catch (error) {
    console.error("❌ Jenkins test failed:", error.message);
    process.exit(1);
  }
})();


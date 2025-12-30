/**
 * PHASE 4: PROFESSIONAL LEVEL
 * Module 1: Docker Containerization
 * Lesson 1: Docker Basics for API Testing
 * 
 * Learning Objectives:
 * - Understand Docker concepts for API testing
 * - Run API tests in Docker containers
 * - Create Docker images for test environments
 * - Manage test data with Docker volumes
 */

import { expect } from "chai";
import { exec } from "child_process";
import { promisify } from "util";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

console.log("=== DOCKER CONTAINERIZATION ===");

const execAsync = promisify(exec);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Docker Service Manager
class DockerServiceManager {
  constructor() {
    this.containers = [];
  }

  async checkDockerInstalled() {
    try {
      const { stdout } = await execAsync("docker --version");
      console.log(`✅ Docker installed: ${stdout.trim()}`);
      return true;
    } catch (error) {
      console.error("❌ Docker is not installed or not accessible");
      return false;
    }
  }

  async checkDockerRunning() {
    try {
      await execAsync("docker ps");
      console.log("✅ Docker daemon is running");
      return true;
    } catch (error) {
      console.error("❌ Docker daemon is not running");
      return false;
    }
  }

  async buildImage(dockerfilePath, imageName, tag = "latest") {
    try {
      console.log(`🔨 Building Docker image: ${imageName}:${tag}`);
      const { stdout } = await execAsync(
        `docker build -t ${imageName}:${tag} -f ${dockerfilePath} .`
      );
      console.log(`✅ Image built successfully: ${imageName}:${tag}`);
      return true;
    } catch (error) {
      console.error(`❌ Failed to build image: ${error.message}`);
      return false;
    }
  }

  async runContainer(imageName, containerName, options = {}) {
    try {
      const {
        ports = {},
        volumes = {},
        environment = {},
        detach = true
      } = options;

      let command = `docker run`;
      
      if (detach) {
        command += " -d";
      }

      if (containerName) {
        command += ` --name ${containerName}`;
      }

      // Port mappings
      Object.entries(ports).forEach(([host, container]) => {
        command += ` -p ${host}:${container}`;
      });

      // Volume mappings
      Object.entries(volumes).forEach(([host, container]) => {
        command += ` -v ${host}:${container}`;
      });

      // Environment variables
      Object.entries(environment).forEach(([key, value]) => {
        command += ` -e ${key}=${value}`;
      });

      command += ` ${imageName}`;

      console.log(`🚀 Running container: ${containerName || imageName}`);
      const { stdout } = await execAsync(command);
      const containerId = stdout.trim();
      
      this.containers.push(containerId);
      console.log(`✅ Container started: ${containerId}`);
      
      return containerId;
    } catch (error) {
      console.error(`❌ Failed to run container: ${error.message}`);
      throw error;
    }
  }

  async stopContainer(containerNameOrId) {
    try {
      console.log(`🛑 Stopping container: ${containerNameOrId}`);
      await execAsync(`docker stop ${containerNameOrId}`);
      console.log(`✅ Container stopped: ${containerNameOrId}`);
    } catch (error) {
      console.error(`❌ Failed to stop container: ${error.message}`);
    }
  }

  async removeContainer(containerNameOrId) {
    try {
      console.log(`🗑️  Removing container: ${containerNameOrId}`);
      await execAsync(`docker rm ${containerNameOrId}`);
      console.log(`✅ Container removed: ${containerNameOrId}`);
    } catch (error) {
      console.error(`❌ Failed to remove container: ${error.message}`);
    }
  }

  async getContainerLogs(containerNameOrId) {
    try {
      const { stdout } = await execAsync(
        `docker logs ${containerNameOrId}`
      );
      return stdout;
    } catch (error) {
      console.error(`❌ Failed to get logs: ${error.message}`);
      return "";
    }
  }

  async cleanup() {
    console.log("🧹 Cleaning up containers...");
    for (const container of this.containers) {
      await this.stopContainer(container);
      await this.removeContainer(container);
    }
    this.containers = [];
  }
}

// Docker Test Environment
class DockerTestEnvironment {
  constructor() {
    this.docker = new DockerServiceManager();
  }

  async setup() {
    console.log("\n📦 Setting up Docker test environment...");
    
    const dockerInstalled = await this.docker.checkDockerInstalled();
    if (!dockerInstalled) {
      throw new Error("Docker is not installed");
    }

    const dockerRunning = await this.docker.checkDockerRunning();
    if (!dockerRunning) {
      throw new Error("Docker daemon is not running");
    }

    console.log("✅ Docker environment ready");
  }

  async createTestDockerfile() {
    const dockerfileContent = `
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy test files
COPY . .

# Set environment variables
ENV NODE_ENV=test
ENV API_BASE_URL=https://gorest.co.in/public-api

# Run tests
CMD ["npm", "test"]
`;

    const dockerfilePath = path.join(__dirname, "../../../Dockerfile.test");
    fs.writeFileSync(dockerfilePath, dockerfileContent);
    console.log(`✅ Test Dockerfile created: ${dockerfilePath}`);
    return dockerfilePath;
  }

  async createDockerComposeTest() {
    const composeContent = `
version: '3.8'

services:
  api-tests:
    build:
      context: .
      dockerfile: Dockerfile.test
    environment:
      - NODE_ENV=test
      - API_BASE_URL=https://gorest.co.in/public-api
    volumes:
      - ./test-results:/app/test-results
      - ./logs:/app/logs
    networks:
      - test-network

networks:
  test-network:
    driver: bridge
`;

    const composePath = path.join(__dirname, "../../../docker-compose.test.yml");
    fs.writeFileSync(composePath, composeContent);
    console.log(`✅ Test docker-compose created: ${composePath}`);
    return composePath;
  }

  async runTestsInContainer() {
    console.log("\n🧪 Running tests in Docker container...");
    
    // This is a demonstration - in real scenario, you would:
    // 1. Build the test image
    // 2. Run the container with test command
    // 3. Collect test results from volume
    
    console.log("ℹ️  To run tests in Docker:");
    console.log("   1. docker build -t api-tests -f Dockerfile.test .");
    console.log("   2. docker run --rm api-tests");
    console.log("   3. Or use: docker-compose -f docker-compose.test.yml up");
  }

  async teardown() {
    await this.docker.cleanup();
  }
}

// Test Scenarios
async function testDockerEnvironment() {
  console.log("\n📝 Test 1: Docker Environment Check");
  
  const env = new DockerTestEnvironment();
  await env.setup();
  
  console.log("✅ Docker environment test passed");
}

async function testDockerfileCreation() {
  console.log("\n📝 Test 2: Dockerfile Creation");
  
  const env = new DockerTestEnvironment();
  await env.setup();
  
  const dockerfilePath = await env.createTestDockerfile();
  expect(fs.existsSync(dockerfilePath)).to.be.true;
  
  const dockerfileContent = fs.readFileSync(dockerfilePath, "utf8");
  expect(dockerfileContent).to.include("FROM node");
  expect(dockerfileContent).to.include("WORKDIR /app");
  
  console.log("✅ Dockerfile creation test passed");
}

async function testDockerComposeCreation() {
  console.log("\n📝 Test 3: Docker Compose Creation");
  
  const env = new DockerTestEnvironment();
  await env.setup();
  
  const composePath = await env.createDockerComposeTest();
  expect(fs.existsSync(composePath)).to.be.true;
  
  const composeContent = fs.readFileSync(composePath, "utf8");
  expect(composeContent).to.include("version:");
  expect(composeContent).to.include("api-tests:");
  
  console.log("✅ Docker Compose creation test passed");
}

async function testDockerCommands() {
  console.log("\n📝 Test 4: Docker Command Examples");
  
  const docker = new DockerServiceManager();
  await docker.setup();
  
  console.log("\n📋 Useful Docker Commands for API Testing:");
  console.log("   • docker build -t api-tests .");
  console.log("   • docker run --rm api-tests npm test");
  console.log("   • docker-compose up --build");
  console.log("   • docker logs <container-id>");
  console.log("   • docker exec -it <container-id> sh");
  
  console.log("✅ Docker commands documented");
}

// Run all tests
(async () => {
  try {
    await testDockerEnvironment();
    await testDockerfileCreation();
    await testDockerComposeCreation();
    await testDockerCommands();
    
    console.log("\n✅ All Docker containerization tests completed!");
    console.log("\n💡 Note: These tests demonstrate Docker concepts.");
    console.log("   For actual container execution, ensure Docker is installed and running.");
  } catch (error) {
    console.error("❌ Docker test failed:", error.message);
    console.log("\n💡 This test requires Docker to be installed and running.");
    console.log("   The test demonstrates Docker concepts and file generation.");
  }
})();


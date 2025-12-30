#!/usr/bin/env node

/**
 * Setup script for JavaScript API Automation project
 * Creates necessary directories and configuration files
 */

import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, '..');

console.log('🚀 Setting up JavaScript API Automation project...\n');

// Check Node.js version
console.log('📦 Checking Node.js version...');
try {
  const nodeVersion = process.version;
  const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);
  if (majorVersion < 16) {
    console.error(`❌ Node.js version 16 or higher is required. Current version: ${nodeVersion}`);
    process.exit(1);
  }
  console.log(`✅ Node.js version: ${nodeVersion}`);
} catch (error) {
  console.error('❌ Error checking Node.js version:', error.message);
  process.exit(1);
}

// Check npm version
console.log('📦 Checking npm version...');
try {
  const npmVersion = execSync('npm -v', { encoding: 'utf-8' }).trim();
  const majorVersion = parseInt(npmVersion.split('.')[0]);
  if (majorVersion < 8) {
    console.error(`❌ npm version 8 or higher is required. Current version: ${npmVersion}`);
    process.exit(1);
  }
  console.log(`✅ npm version: ${npmVersion}`);
} catch (error) {
  console.error('❌ Error checking npm version:', error.message);
  process.exit(1);
}

// Install dependencies
console.log('\n📦 Installing dependencies...');
try {
  execSync('npm install', { stdio: 'inherit', cwd: rootDir });
  console.log('✅ Dependencies installed');
} catch (error) {
  console.error('❌ Error installing dependencies:', error.message);
  process.exit(1);
}

// Create .env file if it doesn't exist
const envPath = path.join(rootDir, '.env');
const envExamplePath = path.join(rootDir, '.env.example');

if (!fs.existsSync(envPath)) {
  console.log('\n📝 Creating .env file...');
  if (fs.existsSync(envExamplePath)) {
    fs.copyFileSync(envExamplePath, envPath);
    console.log('✅ Created .env file from .env.example');
    console.log('⚠️  Please update .env file with your actual values');
  } else {
    // Create basic .env file
    const envContent = `# API Configuration
API_BASE_URL=https://gorest.co.in/public-api/
API_TOKEN=your_api_token_here
GOREST_API_TOKEN=your_api_token_here
BEARER_TOKEN=your_api_token_here

# Testing Configuration
NODE_ENV=development
ENVIRONMENT=development
TEST_PARALLEL=true
TEST_MAX_CONCURRENCY=5

# Reporting
ALLURE_RESULTS_DIR=allure-results
ALLURE_REPORT_DIR=allure-report
`;
    fs.writeFileSync(envPath, envContent);
    console.log('✅ Created basic .env file');
    console.log('⚠️  Please update .env file with your actual API token');
  }
} else {
  console.log('✅ .env file already exists');
}

// Create necessary directories
console.log('\n📁 Creating necessary directories...');
const directories = [
  'allure-results',
  'allure-report',
  'screenshots',
  'test-results',
  'logs',
  'reports',
  'monitoring'
];

directories.forEach(dir => {
  const dirPath = path.join(rootDir, dir);
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
    console.log(`✅ Created directory: ${dir}`);
  } else {
    console.log(`✅ Directory already exists: ${dir}`);
  }
});

// Set up Git hooks if Husky is installed
const huskyPath = path.join(rootDir, 'node_modules', 'husky');
if (fs.existsSync(huskyPath)) {
  console.log('\n🔧 Setting up Git hooks...');
  try {
    execSync('npm run prepare', { stdio: 'inherit', cwd: rootDir });
    console.log('✅ Git hooks set up');
  } catch (error) {
    console.log('⚠️  Could not set up Git hooks (this is optional)');
  }
}

console.log('\n✅ Setup complete!\n');
console.log('Next steps:');
console.log('1. Update .env file with your API token and configuration');
console.log('2. Run tests: npm test');
console.log('3. Start learning with: npm run test:beginner\n');


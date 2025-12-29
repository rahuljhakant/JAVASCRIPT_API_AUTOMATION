#!/bin/bash

# Setup script for JavaScript API Automation project

set -e

echo "🚀 Setting up JavaScript API Automation project..."

# Check Node.js version
echo "📦 Checking Node.js version..."
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 16 ]; then
    echo "❌ Node.js version 16 or higher is required. Current version: $(node -v)"
    exit 1
fi
echo "✅ Node.js version: $(node -v)"

# Check npm version
echo "📦 Checking npm version..."
NPM_VERSION=$(npm -v | cut -d'.' -f1)
if [ "$NPM_VERSION" -lt 8 ]; then
    echo "❌ npm version 8 or higher is required. Current version: $(npm -v)"
    exit 1
fi
echo "✅ npm version: $(npm -v)"

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from .env.example..."
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "⚠️  Please update .env file with your actual values"
    else
        echo "⚠️  .env.example not found, creating basic .env file..."
        cat > .env << EOF
# API Configuration
API_BASE_URL=https://gorest.co.in/public-api/
API_TOKEN=your_api_token_here

# Testing Configuration
TEST_PARALLEL=true
TEST_MAX_CONCURRENCY=5
EOF
    fi
fi

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p allure-results allure-report screenshots test-results logs

# Set up Git hooks if Husky is installed
if [ -d "node_modules/.bin/husky" ] || [ -f "node_modules/husky/lib/index.js" ]; then
    echo "🔧 Setting up Git hooks..."
    npm run prepare 2>/dev/null || true
fi

echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Update .env file with your API token and configuration"
echo "2. Run tests: npm test"
echo "3. Start learning with: npm run test:beginner"


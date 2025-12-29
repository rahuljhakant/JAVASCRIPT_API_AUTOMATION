#!/bin/bash

# Deployment script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${GREEN}ℹ${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

ENVIRONMENT=${1:-staging}

if [ "$ENVIRONMENT" != "staging" ] && [ "$ENVIRONMENT" != "production" ]; then
    print_error "Invalid environment: $ENVIRONMENT"
    echo "Usage: $0 [staging|production]"
    exit 1
fi

print_info "Deploying to: $ENVIRONMENT"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Build Docker image
print_info "Building Docker image..."
docker-compose build

# Run tests before deployment
print_info "Running tests before deployment..."
npm test || {
    print_error "Tests failed. Deployment aborted."
    exit 1
}

# Deploy based on environment
case $ENVIRONMENT in
    staging)
        print_info "Deploying to staging..."
        docker-compose -f docker-compose.yml -f docker-compose.staging.yml up -d
        ;;
    production)
        print_warning "Deploying to production..."
        read -p "Are you sure you want to deploy to production? (yes/no): " confirm
        if [ "$confirm" != "yes" ]; then
            print_info "Deployment cancelled"
            exit 0
        fi
        docker-compose -f docker-compose.yml -f docker-compose.production.yml up -d
        ;;
esac

print_info "Deployment completed!"


#!/bin/bash

# Test execution wrapper script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
ENV=${ENV:-development}
LEVEL=${LEVEL:-all}
PARALLEL=${PARALLEL:-false}
COVERAGE=${COVERAGE:-false}

# Function to print colored output
print_info() {
    echo -e "${GREEN}ℹ${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
    print_info "Loaded environment variables from .env"
else
    print_warning ".env file not found, using defaults"
fi

# Set NODE_ENV
export NODE_ENV=$ENV

print_info "Running tests for environment: $ENV"
print_info "Test level: $LEVEL"

# Run tests based on level
case $LEVEL in
    beginner)
        print_info "Running beginner level tests..."
        npm run test:beginner
        ;;
    intermediate)
        print_info "Running intermediate level tests..."
        npm run test:intermediate
        ;;
    advanced)
        print_info "Running advanced level tests..."
        npm run test:advanced
        ;;
    professional)
        print_info "Running professional level tests..."
        npm run test:professional
        ;;
    expert)
        print_info "Running expert level tests..."
        npm run test:expert
        ;;
    design-patterns)
        print_info "Running design patterns tests..."
        npm run test:design-patterns
        ;;
    all)
        print_info "Running all tests..."
        if [ "$PARALLEL" = "true" ]; then
            npm run test:parallel
        else
            npm test
        fi
        ;;
    *)
        print_error "Unknown test level: $LEVEL"
        echo "Available levels: beginner, intermediate, advanced, professional, expert, design-patterns, all"
        exit 1
        ;;
esac

# Generate coverage if requested
if [ "$COVERAGE" = "true" ]; then
    print_info "Generating coverage report..."
    npm run test:coverage
fi

print_info "Tests completed!"


#!/bin/bash

# Report generation script

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${GREEN}ℹ${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

REPORT_TYPE=${1:-all}

print_info "Generating reports: $REPORT_TYPE"

case $REPORT_TYPE in
    allure)
        print_info "Generating Allure report..."
        npm run allure:generate
        print_info "Allure report generated in allure-report/"
        ;;
    coverage)
        print_info "Generating coverage report..."
        npm run test:coverage
        print_info "Coverage report generated in coverage/"
        ;;
    all)
        print_info "Generating all reports..."
        
        # Allure report
        if command -v allure &> /dev/null; then
            npm run allure:generate
            print_info "Allure report generated"
        else
            print_warning "Allure not installed, skipping Allure report"
        fi
        
        # Coverage report
        npm run test:coverage
        print_info "Coverage report generated"
        
        print_info "All reports generated!"
        ;;
    *)
        echo "Usage: $0 [allure|coverage|all]"
        exit 1
        ;;
esac


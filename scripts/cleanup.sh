#!/bin/bash

# Cleanup script

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

CLEANUP_TYPE=${1:-all}

print_info "Cleaning up: $CLEANUP_TYPE"

case $CLEANUP_TYPE in
    reports)
        print_info "Cleaning up reports..."
        rm -rf allure-results allure-report coverage test-results
        print_info "Reports cleaned"
        ;;
    screenshots)
        print_info "Cleaning up screenshots..."
        rm -rf screenshots
        print_info "Screenshots cleaned"
        ;;
    logs)
        print_info "Cleaning up logs..."
        rm -rf logs/*.log
        print_info "Logs cleaned"
        ;;
    node_modules)
        print_info "Cleaning up node_modules..."
        rm -rf node_modules super-api-tests/node_modules
        print_info "node_modules cleaned"
        ;;
    docker)
        print_info "Cleaning up Docker resources..."
        docker-compose down -v
        docker system prune -f
        print_info "Docker resources cleaned"
        ;;
    all)
        print_info "Cleaning up everything..."
        
        # Reports
        rm -rf allure-results allure-report coverage test-results
        print_info "Reports cleaned"
        
        # Screenshots
        rm -rf screenshots
        print_info "Screenshots cleaned"
        
        # Logs
        rm -rf logs/*.log
        print_info "Logs cleaned"
        
        # Docker (optional, ask for confirmation)
        read -p "Do you want to clean Docker resources? (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            docker-compose down -v
            docker system prune -f
            print_info "Docker resources cleaned"
        fi
        
        print_info "Cleanup completed!"
        ;;
    *)
        echo "Usage: $0 [reports|screenshots|logs|node_modules|docker|all]"
        exit 1
        ;;
esac


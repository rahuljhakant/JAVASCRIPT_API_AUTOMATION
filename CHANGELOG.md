# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Root package.json for workspace management
- TypeScript configuration (tsconfig.json)
- Environment variable loader utility (utils/env-loader.mjs)
- Environment configuration files for staging and production
- Prometheus configuration file
- Nginx configuration file
- Commitlint configuration
- JSDoc configuration
- CONTRIBUTING.md guidelines
- LICENSE file
- CHANGELOG.md

### Changed
- Replaced deprecated `faker` package with `@faker-js/faker`
- Updated all faker API calls to match @faker-js/faker v8 API
- Removed hardcoded API tokens from config files
- Migrated to environment variable-based configuration
- Updated test files to use environment variables

### Removed
- Deprecated `request` package (replaced with axios/node-fetch)
- Deprecated `moment` package (using native Date/Intl)
- Invalid `k6` package (k6 is standalone binary)

### Security
- Removed hardcoded API tokens from all configuration files
- Added environment variable support for sensitive data
- Created .env.example template

## [1.0.0] - 2024-12-28

### Added
- Initial project structure
- Beginner level tutorials (HTTP basics, first API calls)
- Intermediate level tutorials (CRUD operations, authentication)
- Design patterns implementation
- Advanced level tutorials (complex scenarios, performance testing)
- Professional level tutorials (Docker, Jenkins, security testing)
- Expert level tutorials (AI-powered testing, cloud-native testing)
- Comprehensive test suite
- Docker and Docker Compose configuration
- CI/CD pipeline configurations
- Documentation and learning materials

[Unreleased]: https://github.com/your-username/javascript-api-automation/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/your-username/javascript-api-automation/releases/tag/v1.0.0


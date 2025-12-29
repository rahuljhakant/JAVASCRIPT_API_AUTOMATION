# Contributing to JavaScript API Automation

Thank you for your interest in contributing to this project! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Follow the project's coding standards

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/javascript-api-automation.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Install dependencies: `npm install`
5. Make your changes
6. Test your changes: `npm test`
7. Commit your changes (see Commit Message Guidelines below)
8. Push to your fork: `git push origin feature/your-feature-name`
9. Create a Pull Request

## Development Workflow

### Branch Naming

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `test/` - Test additions or updates
- `chore/` - Maintenance tasks

### Making Changes

1. **Follow the existing code style**
   - Use ES6+ JavaScript
   - Follow the existing file structure
   - Add comments for complex logic

2. **Write tests**
   - Add tests for new features
   - Ensure all tests pass: `npm test`
   - Maintain or improve test coverage

3. **Update documentation**
   - Update README.md if needed
   - Add JSDoc comments for new functions
   - Update CHANGELOG.md with your changes

4. **Run linting**
   - Fix linting issues: `npm run lint:fix`
   - Format code: `npm run format`

## Commit Message Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `build`: Build system changes
- `ci`: CI/CD changes
- `chore`: Other changes

### Examples

```
feat(auth): add OAuth2 authentication support

Add support for OAuth2 authentication flow with token refresh
mechanism. Includes tests and documentation updates.

Closes #123
```

```
fix(crud): fix user deletion endpoint

Fix issue where user deletion was not properly cleaning up
related resources. Added cleanup tests.

Fixes #456
```

## Pull Request Process

1. **Update CHANGELOG.md**
   - Add your changes under the appropriate section
   - Follow the existing format

2. **Ensure tests pass**
   - All tests must pass
   - Code coverage should not decrease

3. **Update documentation**
   - Update README.md if needed
   - Add/update JSDoc comments

4. **Request review**
   - Assign reviewers
   - Add descriptive PR description
   - Link related issues

5. **Address feedback**
   - Respond to review comments
   - Make requested changes
   - Re-request review when ready

## Code Style

### JavaScript

- Use ES6+ features (arrow functions, destructuring, async/await)
- Use meaningful variable and function names
- Keep functions small and focused
- Add JSDoc comments for public APIs

### Testing

- Write descriptive test names
- Follow AAA pattern (Arrange, Act, Assert)
- Test both success and error cases
- Use appropriate test data

### File Structure

- Follow the existing directory structure
- Group related files together
- Use descriptive file names

## Testing Requirements

- All new code must have tests
- Tests should be clear and maintainable
- Use appropriate test data
- Test edge cases and error conditions

## Documentation Requirements

- Update README.md for user-facing changes
- Add JSDoc comments for new functions/classes
- Update CHANGELOG.md with your changes
- Add examples for complex features

## Questions?

If you have questions or need help:

- Open an issue for discussion
- Check existing documentation
- Ask in discussions

Thank you for contributing!


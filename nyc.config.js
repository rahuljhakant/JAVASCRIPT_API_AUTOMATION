module.exports = {
  all: true,
  check-coverage: true,
  lines: 80,
  functions: 80,
  branches: 80,
  statements: 80,
  exclude: [
    'coverage/**',
    'test/**',
    '**/*.test.mjs',
    '**/*.spec.mjs',
    'node_modules/**',
    '**/node_modules/**',
    '.nyc_output/**',
    'allure-results/**',
    'allure-report/**',
    'reports/**',
    'scripts/**',
    'config/**',
    'docs/**'
  ],
  include: [
    '**/*.mjs',
    '**/*.js'
  ],
  reporter: [
    'text',
    'text-summary',
    'html',
    'lcov',
    'json'
  ],
  report-dir: './coverage',
  temp-dir: './.nyc_output'
};


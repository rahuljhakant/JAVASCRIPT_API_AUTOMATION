module.exports = {
  env: {
    browser: true,
    es2021: true,
    node: true,
    mocha: true
  },
  extends: [
    'airbnb-base'
  ],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module'
  },
  rules: {
    'import/no-extraneous-dependencies': ['error', { devDependencies: true }],
    'no-console': 'off',
    'max-len': ['error', { code: 120, ignoreComments: true }],
    'no-unused-expressions': 'off',
    'chai-friendly/no-unused-expressions': 'error'
  },
  plugins: ['chai-friendly']
};

module.exports = {
  root: true,
  env: {
    browser: true,
    commonjs: true,
    node: true
  },
  extends: [
    'digitalbazaar',
    'digitalbazaar/jsdoc',
    'digitalbazaar/module'
  ],
  ignorePatterns: [
    'mock-documents/'
  ],
  rules: {
    'unicorn/prefer-node-protocol': 'error'
  }
};

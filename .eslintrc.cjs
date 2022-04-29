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
  ignorePatterns: ['dist/', 'mock-documents/']
};

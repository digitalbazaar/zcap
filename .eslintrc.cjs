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
    'unicorn/prefer-node-protocol': 'error',
    // @typedef {import(...)} re-export lines have an irreducible minimum length
    // when the type name is long; exempt them from the 80-char limit.
    'max-len': ['error', {
      code: 80,
      ignorePattern: '(\\* SPDX-License-Identifier: |\\* @typedef \\{import)',
      ignoreUrls: true
    }]
  }
};

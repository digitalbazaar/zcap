require('./typedefs');

module.exports = {
  env: {
    browser: true,
    commonjs: true,
    node: true
  },
  extends: [
    'eslint-config-digitalbazaar',
    'eslint-config-digitalbazaar/jsdoc'
  ],
  root: true
};

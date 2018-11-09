/**
 * Node.js test runner for ocapld.js.
 *
 * @author Dave Longley
 * @author David I. Lehn
 *
 * Copyright (c) 2011-2018 Digital Bazaar, Inc. All rights reserved.
 */
const assert = require('chai').assert;
const common = require('./test-common');
const jsonld = require('../node_modules/jsonld');
const jsigs = require('../node_modules/jsonld-signatures');
const ocapld = require('../lib');

const options = {
  assert: assert,
  jsigs: jsigs,
  jsonld: jsonld,
  ocapld: ocapld,
  nodejs: true
};

common(options).then(() => {
  run();
}).catch(err => {
  console.error(err);
});

process.on('unhandledRejection', (reason, p) => {
  console.error('Unhandled Rejection at:', p, 'reason:', reason);
});

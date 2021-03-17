/**
 * Node.js test runner for ocapld.js.
 *
 * Copyright (c) 2011-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const common = require('./test-common');
const expect = require('chai').expect;
const jsigs = require('../node_modules/jsonld-signatures');
const ocapld = require('../lib');

const mock = require('./mock-data');
const helpers = require('./helpers');

const options = {
  expect,
  helpers,
  jsigs,
  mock,
  ocapld,
  nodejs: true
};

common(options).then(() => {
  // '--delay' event loop hack for mocha 7.1.0+
  return Promise.resolve();
}).then(() => {
  run();
}).catch(err => {
  console.error(err);
});

process.on('unhandledRejection', (reason, p) => {
  console.error('Unhandled Rejection at:', p, 'reason:', reason);
});

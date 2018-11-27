/**
 * Node.js test runner for ocapld.js.
 *
 * @author Dave Longley
 * @author David I. Lehn
 *
 * Copyright (c) 2011-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const common = require('./test-common');
const expect = require('chai').expect;
const jsonld = require('../node_modules/jsonld');
const jsigs = require('../node_modules/jsonld-signatures');
const ocapld = require('../lib');

const options = {
  expect,
  jsigs,
  jsonld,
  ocapld,
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

/**
 * Karma test runner for ocapld.js.
 *
 * Use environment vars to control, set via karma.conf.js/webpack:
 *
 * Set dirs, manifests, or js to run:
 *   JSONLD_TESTS="r1 r2 ..."
 * Output an EARL report:
 *   EARL=filename
 * Bail with tests fail:
 *   BAIL=true
 *
 * Copyright (c) 2011-2018 Digital Bazaar, Inc. All rights reserved.
 */
// FIXME: hack to ensure delay is set first
//mocha.setup({delay: true, ui: 'bdd'});

// jsonld compatibility
//require('core-js/fn/array/includes');
require('core-js/fn/object/assign');
require('core-js/fn/promise');
// FIXME: shouldn't need this with babel transform-runtime.
require('regenerator-runtime/runtime');

const common = require('./test-common');
const expect = require('chai').expect;
const jsigs = require('jsonld-signatures');
const ocapld = require('../lib');

const mock = require('./mock-data');
const helpers = require('./helpers');

const options = {
  expect,
  helpers,
  jsigs,
  mock,
  ocapld,
  nodejs: false
};

common(options).catch(err => {
  console.error(err);
});

/**
 * Karma test runner for zcap.
 *
 * Copyright (c) 2011-2022 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import common from './test-common.js';
import jsigs from 'jsonld-signatures';
import * as zcap from '../lib/index.js';

import * as mock from './mock-data.js';
import * as helpers from './helpers.js';

const expect = chai.expect;

const options = {
  expect,
  helpers,
  jsigs,
  mock,
  zcap,
  nodejs: false
};

common(options).catch(err => {
  console.error(err);
});

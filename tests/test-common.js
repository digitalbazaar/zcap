/**
 * Test runner for ocapld.js library.
 *
 * @author Dave Longley <dlongley@digitalbazaar.com>
 * @author Manu Sporny <msporny@digitalbazaar.com>
 *
 * Copyright (c) 2014-2018 Digital Bazaar, Inc. All rights reserved.
 */
module.exports = function(options) {
  'use strict';
  const assert = options.assert;
  const jsonld = options.jsonld;
  const jsigs = options.jsigs;
  // setup
  jsigs.use('jsonld', jsonld);
  // run tests
  describe('Example', function() {
    context('common', function() {
      it('should pass', function(done) {
        done();
      });
    });
  });
  return Promise.resolve();
};

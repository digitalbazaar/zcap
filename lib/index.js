/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const jsigs = require('jsonld-signatures');

/* Core API */
exports.CapabilityInvocation = require('./CapabilityInvocation');
exports.CapabilityDelegation = require('./CapabilityDelegation');
exports.constants = require('./constants');

// enable external document loaders to extend an internal one that loads
// ZCAP context(s)
exports.extendDocumentLoader = function extendDocumentLoader(documentLoader) {
  return async function loadZcapContexts(url) {
    if(url === exports.constants.ZCAP_CONTEXT_URL) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: exports.constants.ZCAP_CONTEXT,
        tag: 'static'
      };
    }
    return documentLoader(url);
  };
};

// default doc loader; only loads ZCAP and jsigs contexts
exports.documentLoader = exports.extendDocumentLoader(
  jsigs.strictDocumentLoader);

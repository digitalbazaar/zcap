/*!
 * Copyright (c) 2018-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const jsigs = require('jsonld-signatures');

/* Core API */
const api = {};
module.exports = api;

api.CapabilityInvocation = require('./CapabilityInvocation');
api.CapabilityDelegation = require('./CapabilityDelegation');
api.Caveat = require('./Caveat');
api.ExpirationCaveat = require('./ExpirationCaveat');
api.constants = require('./constants');

// enable external document loaders to extend an internal one that loads
// ZCAP context(s)
api.extendDocumentLoader = function extendDocumentLoader(documentLoader) {
  return async function loadZcapContexts(url) {
    if(url === api.constants.ZCAP_CONTEXT_URL) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: api.constants.ZCAP_CONTEXT,
        tag: 'static'
      };
    }
    return documentLoader(url);
  };
};

// default doc loader; only loads ZCAP and jsigs contexts
api.documentLoader = api.extendDocumentLoader(jsigs.strictDocumentLoader);

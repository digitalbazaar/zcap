/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {CAPABILITY_VOCAB_URL} = require('./constants');

// Vocabulary URIs
// support both CamelCase and camelCase
const ExpireAtUri = prefixedOcapUri('ExpireAt');
const expireAtUri = prefixedOcapUri('expireAt');

module.exports = {
  ExpireAtUri,
  expireAtUri
};

function prefixedOcapUri(suffix) {
  return CAPABILITY_VOCAB_URL + suffix;
}

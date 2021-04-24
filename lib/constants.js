/*!
 * Copyright (c) 2018-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';
const {CONTEXT_URL: ZCAP_CONTEXT_URL} = require('zcap-context');
const secCtx = require('@digitalbazaar/security-context');

const {SECURITY_CONTEXT_V1_URL, SECURITY_CONTEXT_V2_URL} = secCtx;

module.exports = {
  CAPABILITY_VOCAB_URL: 'https://w3id.org/security#',
  SECURITY_CONTEXT_V1_URL,
  SECURITY_CONTEXT_V2_URL,
  ZCAP_CONTEXT_URL,
  // 6 is probably more reasonable for Kevin Bacon reasons? but picking a
  // power of 10
  MAX_CHAIN_LENGTH: 10
};

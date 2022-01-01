/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {CONTEXT: ZCAP_CONTEXT, CONTEXT_URL: ZCAP_CONTEXT_URL} =
  require('zcap-context');

module.exports = {
  CAPABILITY_VOCAB_URL: 'https://w3id.org/security#',
  ZCAP_CONTEXT_URL,
  ZCAP_CONTEXT,
  ZCAP_ROOT_PREFIX: 'urn:zcap:root:',
  // 6 is probably more reasonable for Kevin Bacon reasons? but picking a
  // power of 10
  MAX_CHAIN_LENGTH: 10
};

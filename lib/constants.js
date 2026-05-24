/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
export {
  CONTEXT as ZCAP_CONTEXT,
  CONTEXT_URL as ZCAP_CONTEXT_URL
} from '@digitalbazaar/zcap-context';

/** @type {string} The base URL for the zcap security vocabulary. */
export const CAPABILITY_VOCAB_URL = 'https://w3id.org/security#';

/** @type {string} URI prefix for root capability IDs (`urn:zcap:root:`). */
export const ZCAP_ROOT_PREFIX = 'urn:zcap:root:';

/**
 * Default maximum capability delegation chain length (inclusive of the tail).
 *
 * @type {number}
 */
// 6 is probably more reasonable for Kevin Bacon reasons? but picking a
// power of 10
export const MAX_CHAIN_LENGTH = 10;

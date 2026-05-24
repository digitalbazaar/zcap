/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import jsigs from 'jsonld-signatures';

/* Core API */
export {CapabilityInvocation} from './CapabilityInvocation.js';
export {CapabilityDelegation} from './CapabilityDelegation.js';
export {createRootCapability} from './utils.js';
import * as constants from './constants.js';
export {constants};

/**
 * @typedef {import('./utils.js').RootZcap} RootZcap
 * @typedef {import('./utils.js').DelegatedZcap} DelegatedZcap
 * @typedef {import('./utils.js').Zcap} Zcap
 * @typedef {import('./utils.js').CapabilityDelegationProof} CapabilityDelegationProof
 * @typedef {import('./utils.js').InspectCapabilityChain} InspectCapabilityChain
 * @typedef {import('./utils.js').InspectResult} InspectResult
 * @typedef {import('./utils.js').CapabilityChainDetails} CapabilityChainDetails
 * @typedef {import('./utils.js').CapabilityMeta} CapabilityMeta
 * @typedef {import('./utils.js').VerifyResult} VerifyResult
 * @typedef {import('./utils.js').VerifyProofResult} VerifyProofResult
 * @typedef {import('./utils.js').VerifyProofPurposeResult} VerifyProofPurposeResult
 */

/**
 * Wraps an existing document loader so that it also serves the zcap JSON-LD
 * context. The wrapped loader is called for all other URLs.
 *
 * @param {Function} documentLoader - An existing JSON-LD document loader to
 *   extend.
 *
 * @returns {Function} A new document loader that handles the zcap context URL
 *   and delegates all other URLs to the wrapped loader.
 */
export function extendDocumentLoader(documentLoader) {
  return async function loadZcapContexts(url) {
    if(url === constants.ZCAP_CONTEXT_URL) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: constants.ZCAP_CONTEXT,
        tag: 'static'
      };
    }
    return documentLoader(url);
  };
}

/**
 * A default JSON-LD document loader that serves only the zcap and
 * jsonld-signatures contexts. Suitable for use when no other contexts are
 * needed. Extend it with {@link extendDocumentLoader} if additional contexts
 * are required.
 *
 * @type {Function}
 */
export const documentLoader = extendDocumentLoader(
  jsigs.strictDocumentLoader);

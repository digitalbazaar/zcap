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

// enable external document loaders to extend an internal one that loads
// ZCAP context(s)
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

// default doc loader; only loads ZCAP and jsigs contexts
export const documentLoader = extendDocumentLoader(
  jsigs.strictDocumentLoader);

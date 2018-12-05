/**
 * Copyright (c) 2018 Digital Bazaar, Inc.
 *
 * @author Christopher Lemmer Webber
 * @author Ganesh Annan <gannan@digitalbazaar.com>
 *
 */
'use strict';

const constants = require('./constants');
const defaultCaveatRegistry = require('./caveatRegistry');

const api = {};
module.exports = api;

/**
 * Retrieves the delegator from a capability.
 *
 * @param {Object} capability - the fully expanded JSON-LD document for the
 *                              object capability
 */
api.getDelegator = capability => {
  const {delegator, id} = capability;
  if(!(delegator || id)) {
    throw new Error('Invoker not found for capability');
  }

  return delegator || id;
};

/**
 * Retrieves the invoker from a capability.
 *
 * @param {Object} capability - the fully expanded JSON-LD document for the
 *                              object capability
 */
api.getInvoker = capability => {
  const {id, invoker} = capability;
  if(!(invoker || id)) {
    throw new Error('Invoker not found for capability');
  }

  return invoker || id;
};

/**
 * Plucks the single element of an array that contains a single item.
 *
 * @param {Array} array - an array with one item.
 */
api.getOne = array => {
  if(!Array.isArray(array) || array.length != 1) {
    throw new Error('Expected an array of size 1');
  }
  return array[0];
};

/**
 * Retrieves the target from a capability.
 *
 * @param {Object} capability - the fully expanded JSON-LD document for the
 *                              object capability
 */
api.getTarget = capability => {
  return capability.invocationTarget ?
    capability.invocationTarget : capability.id;
};

/**
 * Verifies the caveats for a given object capability.
 *
 * @param {Object} capability - the fully expanded JSON-LD document for the
 *                              object capability
 * @param {Object} jsigs - a configured instance of jsonld-signatures
 * @param {Object} purposeParameters  - a set of options for validating the
 *                                        proof purpose.
 */
api.verifyCapability = async ({capability, jsigs, purposeParameters}) => {
  // Capability does not point to a parent capability and it was capable of
  // delegating a capability
  if(!('parentCapability' in capability)
    && (capability.proof || {}).proofPurpose !== 'capabilityInvocation') {
    const {expectedTarget} = purposeParameters;
    if(!expectedTarget) {
      return {
        verified: false,
        error: new Error('Expected target not found for capability invocation.')
      };
    }
    // target is the root capability itself,
    // unless an invocation target is specified
    const target = api.getTarget(capability);
    // It's the toplevel capability, which means it's valid if the target
    // matches the expected target
    const verified = target === expectedTarget;
    return {
      verified
    };
  }
  // Otherwise, we have to check the signature
  return jsigs.verify(capability, {
    purpose: 'capabilityDelegation',
    purposeParameters
  });
};

/**
 * Verifies the caveats for a given object capability.
 *
 * @param {Object} capability - the fully expanded JSON-LD document for the
 *                              object capability
 * @param {Object} purposeParameters  - a set of options for validating the
 *                                        proof purposeParameters.
 */
api.verifyCaveats = async ({capability, purposeParameters}) => {
  const caveats = capability.caveat || [];
  const caveatRegistry = purposeParameters.caveatRegistry ||
    defaultCaveatRegistry;

  for(const caveat of caveats) {
    const {type: caveatType} = caveat;
    const caveatChecker = caveatRegistry[caveatType];
    if(!caveatChecker) {
      throw new Error(
        'Caveat checker not found for caveat type: ' + caveatType);
    }
    const success = await caveatChecker({
      caveat, capability, purposeParameters});
    if(!success) {
      return false;
    }
  }

  return true;
};

/**
 * Verifies the invoker is the creator of the key or controlls the key
 *
 * @param {Object} creator - the fully expanded JSON-LD document for the
 *                              object capability
 * @param {Object} invoker  - a set of options for validating the
 *                                        proof purposeParameters.
 */
api.verifyInvoker = async ({creator, invoker, jsonld, documentLoader}) => {
  return _genericVerify({
    comparer: invoker,
    purpose: 'capabilityInvocation',
    creator,
    jsonld,
    documentLoader
  });
};

/**
 * Verifies the delegator is the creator of the key or controlls the key
 *
 * @param {Object} creator - the fully expanded JSON-LD document for the
 *                              object capability
 * @param {Object} delegator  - a set of options for validating the
 *                                        proof purposeParameters.
 */
api.verifyDelegator = async ({creator, delegator, jsonld, documentLoader}) => {
  return _genericVerify({
    comparer: delegator,
    purpose: 'capabilityDelegation',
    creator,
    jsonld,
    documentLoader
  });
};

async function _genericVerify(
  {comparer, purpose, creator, jsonld, documentLoader}) {
  // comparer as a key
  if(comparer === creator) {
    return true;
  }
  // comparer as a controller of keys
  // retrieve the keys associated with proof purpose
  const frame = {
    '@context': constants.SECURITY_CONTEXT_V2_URL,
    id: comparer,
    [purpose]: {
      '@embed': '@always',
      publicKey: { // TODO: Simplify frame, remove the publicKey
        '@embed': '@never',
        id: creator
      }
    }
  };
  const opts = {documentLoader, compactToRelative: false};
  const framed = await jsonld.frame(comparer, frame, opts);
  const [result] = framed['@graph'];
  const [key] = jsonld.getValues(result, purpose);
  return key.publicKey === creator;
}

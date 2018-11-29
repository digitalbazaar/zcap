/**
 * Copyright (c) 2018 Digital Bazaar, Inc.
 *
 * @author Christopher Lemmer Webber
 * @author Ganesh Annan <gannan@digitalbazaar.com>
 *
 */
'use strict';

const jsigs = require('jsonld-signatures');
const defaultCaveatRegistry = require('./caveatRegistry');
const vocab = require('./vocab');

const api = {};
module.exports = api;


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
 * Verifies the caveats for a given object capability.
 *
 * @param {Object} capability - the fully expanded JSON-LD document for the
 *                              object capability
 * @param {Object} jsigs - a configured instance of jsonld-signatures
 * @param {Object} purposeParameters  - a set of options for validating the
 *                                        proof purpose.
 */
api.verifyCapability = async ({capability, purposeParameters}) => {
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
    // target is the root capability unless an invocation target is specified
    const target = capability.invocationTarget ?
      capability.invocationTarget : capability.id;
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
    if(!(caveatType in caveatRegistry)) {
      throw new Error(
        'Caveat handler not found for caveat type: ' + caveatType);
    }
    const caveatChecker = caveatRegistry[caveatType];
    const success = await caveatChecker({
      caveat, capability, purposeParameters});
    if(!success) {
      return false;
    }
  }

  return true;
};

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
  const {delegator, id, invoker} = capability;
  // if neither a delegator or id is found on the capability then the capability
  // can not be delegated
  if(!(delegator || id)) {
    throw new Error('Delegator not found for capability');
  }
  // if there's an invoker present and not a delegator, then this capability
  // was intentionally meant to not be delegated
  if(!delegator && invoker) {
    return undefined;
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
  const {delegator, id, invoker} = capability;
  // if neither an invoker or id is found on the capability then the capability
  // can not be invoked
  if(!(invoker || id)) {
    throw new Error('Invoker not found for capability');
  }
  // if there's a delegator present and not an invoker, then this capability
  // was intentionally meant to not be invoked
  if(!invoker && delegator) {
    return undefined;
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
 * @param {Boolean} validateTarget - enables the target === expectedTarget check
 *
 */
api.verifyCapability = async (
  {capability, jsigs, purposeParameters, validateTarget = true}) => {
  // Ensure we have not visited the capability already, if so we have
  // encountered a cycle
  const _visited = getVisited(purposeParameters);
  if(_visited.has(capability.id)) {
    return {
      verified: false,
      error: new Error(
        'Cycle encountered, the capability has been previously processed: ' +
        capability.id
      )
    };
  }
  // Capability does not point to a parent capability and it was capable of
  // delegating a capability
  if(!('parentCapability' in capability)
    && ('capabilityDelegation' in capability || 'delegator' in capability)) {
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
    // Check if we need to validate target, if true then check the target and
    // the expected target. It's the toplevel(root) capability, which means it's
    // valid if the target matches the expected target.If false then we're done,
    // the capability chain is valid.
    const verified = !validateTarget || target === expectedTarget;
    return {
      verified
    };
  }
  // Otherwise, we have to check the signature
  _visited.add(capability.id);
  return jsigs.verify(capability, {
    purpose: 'capabilityDelegation',
    purposeParameters: {...purposeParameters, _visited}
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
  const {caveat} = capability;
  let caveats;
  if(!caveat) {
    caveats = [];
  } else if(caveat && !Array.isArray(caveat)) {
    caveats = [caveat]
  } else {
    caveats = caveat;
  }
  const caveatRegistry = {
    ...purposeParameters.caveatRegistry,
    ...defaultCaveatRegistry
  };
  // console.log({caveats, defaultCaveatRegistry});
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
 * @param {String} creator - the creator of the key.
 * @param {String} invoker  - the key creator or owner.
 * @param {Object} jsonld - a configured instance of jsonld.
 * @param {Object} documentLoader - a configured jsonld documentLoader.
 *
 *
 */
api.verifyInvoker = async ({creator, invoker, jsonld, documentLoader}) => {
  return genericVerify({
    id: invoker,
    purpose: 'capabilityInvocation',
    creator,
    jsonld,
    documentLoader
  });
};

/**
 * Verifies the delegator is the creator of the key or controlls the key
 *
 * @param {String} creator - the creator of the key.
 * @param {String} delegator  - the key creator or owner.
 * @param {Object} jsonld - a configured instance of jsonld.
 * @param {Object} documentLoader - a configured jsonld documentLoader.
 *
 */
api.verifyDelegator = async ({creator, delegator, documentLoader, jsonld}) => {
  return genericVerify({
    id: delegator,
    purpose: 'capabilityDelegation',
    creator,
    jsonld,
    documentLoader
  });
};

/**
 * Verifies the id is the creator of the key or controlls the key
 *
 * @param {String} creator - the creator of the key.
 * @param {String} id  - the id of the creator or owner.
 * @param {Object} jsonld - a configured instance of jsonld.
 * @param {Object} documentLoader - a configured jsonld documentLoader.
 * @param {String} purpose - 'capabilityInvocation' or 'capabilityDelegation'.
 *
 */
async function genericVerify(
  {id, creator, documentLoader, jsonld, purpose}) {
  // id is a key
  if(id === creator) {
    return true;
  }
  // id is the controller of keys
  // retrieve the keys associated with proof purpose
  const frame = {
    '@context': constants.SECURITY_CONTEXT_V2_URL,
    id,
    [purpose]: {
      '@embed': '@always',
      publicKey: { // TODO: Simplify frame, remove the publicKey
        '@embed': '@never',
        id: creator
      }
    }
  };
  const opts = {documentLoader, compactToRelative: false};
  const framed = await jsonld.frame(id, frame, opts);
  const [result] = framed['@graph'];
  const [key] = jsonld.getValues(result, purpose);
  return key.publicKey === creator;
}

/**
 * Retrieves the _visited Set used for cycle checks
 * @param  {Set} _visited - The current set used to check for cycles
 *
 */
function getVisited({_visited = undefined}) {
  if(_visited && _visited instanceof Set) {
    return new Set(_visited);
  }
  return new Set();
}

/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const jsigs = require('jsonld-signatures');
const jsonld = require('jsonld');

const api = {};
module.exports = api;

/**
 * Retrieves the delegator from a capability.
 *
 * @param {Object} capability - the JSON-LD document for the object capability
 *          compacted to the security context.
 */
api.getDelegator = capability => {
  const {delegator, id, invoker} = capability;
  // if neither a delegator or id is found on the capability then the capability
  // can not be delegated
  if(!(delegator || id)) {
    throw new Error('Delegator not found for capability.');
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
 * @param {Object} capability - the JSON-LD document for the object capability
 *          compacted to the security context.
 */
api.getInvoker = capability => {
  const {delegator, id, invoker} = capability;
  // if neither an invoker or id is found on the capability then the capability
  // can not be invoked
  if(!(invoker || id)) {
    throw new Error('Invoker not found for capability.');
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
 * @param {Object} capability - the JSON-LD document for the object capability
 *          compacted to the security context.
 */
api.getTarget = capability => {
  return capability.invocationTarget ?
    capability.invocationTarget : capability.id;
};

/**
 * Fetches a JSON-LD document from a URL and, if necessary, compacts it to
 * the security v2 context.
 *
 * @param {String} url - the URL to fetch.
 * @param {function} documentLoader - a configured jsonld documentLoader.
 * @param {object} expansionMap - a configured jsonld expansionMap.
 *
 * @return {Object} the retrieved JSON-LD document.
 */
api.fetchInSecurityContext = async ({url, documentLoader, expansionMap}) => {
  if(url && typeof url === 'object' &&
    url['@context'] === constants.SECURITY_CONTEXT_V2_URL) {
    return url;
  }
  return jsonld.compact(
    url, constants.SECURITY_CONTEXT_V2_URL,
    {documentLoader, expansionMap, compactToRelative: false});
};

/**
 * Retrieves the delegation proof(s) for a capability that is associated with
 * its parent capability. A capability that has no parent or no associated
 * delegation proofs will cause this function to return an empty array.
 *
 * @param {Object} capability - the JSON-LD document for the object capability
 *          compacted to the security context.
 *
 * @return {Object} any `capabilityDelegation` proof objects attached to the
 *           given capability.
 */
api.getDelegationProofs = ({capability}) => {
  // capability is root, it has no relevant delegation proofs
  if(!capability.parentCapability) {
    return [];
  }

  return jsonld.getValues(capability, 'proof').filter(p => {
    if(!(p && p.proofPurpose === 'capabilityDelegation' &&
      Array.isArray(p.capabilityChain) && p.capabilityChain.length > 0)) {
      return false;
    }
    const last = p.capabilityChain[p.capabilityChain.length - 1];
    return last === capability.parentCapability;
  });
};

/**
 * Gets the `capabilityChain` associated with the given capability and
 * proof.
 *
 * @param {Object} capability - the JSON-LD document for the object capability
 *          compacted to the security context.
 * @param {Object} proof - the capability delegation proof to use.
 *
 * @return {Object} any `capabilityDelegation` proof objects attached to the
 *           given capability.
 */
api.getCapabilityChain = ({capability, proof}) => {
  if(!capability.parentCapability) {
    // root capability has no chain
    return [];
  }

  const proofs = proof ?
    [proof] : api.getDelegationProofs({capability});
  if(proofs.length === 0) {
    throw new Error(
      'Cannot get capability chain; capability is invalid; it is not the ' +
      'root capability yet it does not have a delegation proof.');
  }

  const {capabilityChain} = proofs[0];
  if(!capabilityChain) {
    throw new Error(
      'Cannot get capability chain; capability is invalid; it does not have ' +
      'a "capabilityChain" in its delegation proof.');
  }

  return capabilityChain.slice();
};

/**
 * Creates a `capabilityChain` for delegating the given capability.
 *
 * @param {Object} capability - the JSON-LD document for the object capability
 *          compacted to the security context.
 * @param {function} documentLoader - a configured jsonld documentLoader.
 * @param {Object} expansionMap - a configured jsonld expansionMap.
 *
 * @return {Object} any `capabilityDelegation` proof objects attached to the
 *           given capability.
 */
api.computeCapabilityChain = async ({
  capability, documentLoader, expansionMap}) => {
  // fetch parent capability
  const {parentCapability} = capability;
  if(!parentCapability) {
    throw new Error(
      'Cannot compute capability chain; capability has no "parentCapability".');
  }

  // FIXME: must validate parent capability?
  const parent = await api.fetchInSecurityContext(
    {url: parentCapability, documentLoader, expansionMap});
  if(!parent.parentCapability) {
    // parent is root capability
    return [parentCapability];
  }

  const proofs = api.getDelegationProofs({capability: parent});
  if(proofs.length === 0) {
    throw new Error(
      'Cannot compute capability chain; parent capability is invalid; it is ' +
      'not the root capability yet it does not have a delegation proof.');
  }
  if(proofs.length > 1) {
    throw new Error(
      'Cannot compute capability chain; parent capability is invalid; it ' +
      'has more than one capability delegation proof.');
  }

  const {capabilityChain} = proofs[0];
  if(!capabilityChain) {
    throw new Error(
      'Cannot compute capability chain; parent capability is invalid; it ' +
      'does not have a "capabilityChain" in its delegation proof.');
  }

  // if last ocap was embedded, change it to a reference
  const newChain = capabilityChain.slice(0, capabilityChain.length - 1);
  const last = capabilityChain[capabilityChain.length - 1];
  if(typeof last === 'string') {
    newChain.push(last);
  } else {
    newChain.push(last.id);
  }
  newChain.push(parentCapability);

  // ensure new chain uses absolute URLs
  for(const url of newChain) {
    if(!url.includes(':')) {
      throw new Error(
        'Cannot compute capability chain; parent capability uses relative ' +
        'URL(s) in its capability chain.');
    }
  }

  return newChain;
};

/**
 * Validates a capability chain list, ensuring, for instance, it contains only
 * IDs except possibly last entry (which can be a full embedded capability),
 * that all IDs are all absolute URLs, and that it contains no cycles.
 *
 * @param {Object} capability - the capability the chain list is for.
 * @param {Array} capabilityChain - the capability chain list to validate.
 *
 * @return {Object} {valid, error}.
 */
api.validateCapabilityChain = ({capability, capabilityChain}) => {
  if(capabilityChain.length > constants.MAX_CHAIN_LENGTH) {
    return {
      valid: false,
      error: new Error(
        'The capabability chain exceeds the maximum allowed length.')
    };
  }

  // validate entries in the chain
  const uniqueSet = new Set();
  const last = capabilityChain[capabilityChain.length - 1];
  for(const entry of capabilityChain) {
    let id = entry;
    if(typeof entry !== 'string') {
      if(entry !== last) {
        return {
          valid: false,
          error: new TypeError(
            'Capability chain list is invalid; only the last entry in the ' +
            'list may be embedded.')
        };
      }
      if(!(entry && typeof entry === 'object' &&
        typeof entry.id === 'string')) {
        return {
          valid: false,
          error: new TypeError(
            'Capability chain list is invalid; an embedded capability must ' +
            'be an object with an "id" property that is a string.')
        };
      }
      id = entry.id;
    }
    if(!id.includes(':')) {
      return {
        valid: false,
        error: new Error(
          'Capability chain list is invalid; it contains a capability ID ' +
          'that is not an absolute URL.')
      };
    }
    uniqueSet.add(id);
  }

  // ensure there is no cycle in the chain (including `capability` itself; so
  // compare against `capabilityChain.length + 1`)
  uniqueSet.add(capability.id);
  if(uniqueSet.size !== (capabilityChain.length + 1)) {
    return {
      valid: false,
      error: new Error('The capabability chain contains a cycle.')
    };
  }

  return {valid: true};
};

/**
 * Verifies the capability chain, if any, attached to the given capability.
 *
 * Verifying the given capability chain means ensuring that the tail capability
 * (the one given) has been properly delegated and that the head (or root) of
 * the chain matches the expected target.
 *
 * @param {Object} capability - the JSON-LD document for the object capability,
 *          compacted to the security v2 context.
 * @param {Object} proof - the capability delegation proof to use if the
 *          capability's chain is being verified without invoking the
 *          capability.
 * @param {Object} purposeParameters  - a set of options for validating the
 *          proof purpose.
 * @param {function} documentLoader - a configured jsonld documentLoader.
 * @param {Object} expansionMap - a configured jsonld expansionMap.
 *
 * @return {Object} {verified, error, verifiedParentCapability}.
 */
api.verifyCapabilityChain = async ({
  capability, proof, purposeParameters, documentLoader, expansionMap}) => {
  // FIXME: must also check `allowedAction` and `capabilityAction`

  /* Verification process is:
    1. Fetch capability if only its ID was passed.
    2. Get the capability delegation chain for the capability.
    3. Validate the capability delegation chain.
    4. Verify the root capability:
      4.1. Check the expected target, if one was specified.
      4.2. Ensure that the caveats are met on the root capability.
    5. If the capability is not the root and no `proof` was passed, then
       we must verify its capability delegation proof ourselves, so add
       it to the chain.
    6. For each capability `cap` in the chain, verify the capability delegation
       proof on `cap`. This will validate everything else for `cap` including
       that caveats are met.

    Note: We start verifying a capability from its root of trust (the
    beginning or head of the capability chain) as this approach limits an
    attacker's ability to waste our time and effort traversing from the tail
    to the head.
  */

  try {
    // 1. Fetch capability if only its ID was passed.
    capability = await api.fetchInSecurityContext(
      {url: capability, documentLoader, expansionMap});

    // 2. Get the capability delegation chain for the capability.
    const capabilityChain = api.getCapabilityChain({capability, proof});

    // 3. Validate the capability delegation chain.
    let {valid, error} = api.validateCapabilityChain(
      {capability, capabilityChain});
    if(!valid) {
      throw error;
    }

    // 4. Verify root capability:
    const isRoot = capabilityChain.length === 0;
    let root = isRoot ? capability : capabilityChain.shift();
    root = await api.fetchInSecurityContext(
      {url: root, documentLoader, expansionMap});
    // 4.1. Check the expected target, if one was specified.
    const {expectedTarget} = purposeParameters;
    if(expectedTarget !== undefined) {
      const target = api.getTarget(root);
      if(target !== expectedTarget) {
        throw new Error(
          `Expected target (${expectedTarget}) does not match ` +
          `root capability target (${target}).`);
      }
    }
    // 4.2. Ensure that the caveats are met on the root capability.
    ({valid, error} = await api.checkCaveats({
      capability: root, purposeParameters, documentLoader, expansionMap}));
    if(!valid) {
      throw error;
    }

    let verifiedParentCapability = root;

    // if capability is root, we're done, exit early
    if(isRoot) {
      return {verified: true, verifiedParentCapability};
    }

    // 5. If the capability is not the root and no `proof` was passed, then
    //   we must verify its capability delegation proof ourselves, so add
    //   it to the chain.
    if(!proof) {
      capabilityChain.push(capability);
    }

    // 6. For each capability `cap` in the chain, verify the capability
    //   delegation proof on `cap`. This will validate everything else for
    //   `cap` including that caveats are met.
    const {suite, caveat, CapabilityDelegation} = purposeParameters;
    for(let cap of capabilityChain) {
      cap = await api.fetchInSecurityContext(
        {url: cap, documentLoader, expansionMap});
      const result = await jsigs.verify(cap, {
        suite,
        purpose: new CapabilityDelegation({
          expectedTarget,
          verifiedParentCapability,
          caveat
        }),
        documentLoader,
        expansionMap,
        compactProof: false
      });
      if(!result.verified) {
        // FIXME: which error to return?
        const error = result.error || (result.keyResults[0] || {}).error ||
          new Error('Capability delegation proof not verified.');
        return {verified: false, error};
      }
      verifiedParentCapability = cap;
    }

    return {verified: true, verifiedParentCapability};
  } catch(error) {
    return {verified: false, error};
  }
};

/**
 * Checks if the given capability is valid by seeing if its caveats have been
 * met.
 *
 * @param {Object} capability - the JSON-LD document for the object capability
 *          compacted to the security context.
 * @param {Object} purposeParameters  - a set of options for validating the
 *          proof purposeParameters.
 * @param {function} documentLoader - a configured jsonld documentLoader.
 * @param {Object} expansionMap - a configured jsonld expansionMap.
 *
 * @return {Object} {valid, error}.
 */
api.checkCaveats = async ({
  capability, purposeParameters, documentLoader, expansionMap}) => {
  try {
    // FIXME: revisit how to implement revocation, likely through a caveat
    // class even if it is a "special" one in how the data is modeled
    // check built-in revocation caveat
    /*const {revocationChecker: checkIfRevoked = noopRevocationChecker} =
      purposeParameters;

    // FIXME: seems like the return value should be {revoked, reason}
    const revoked = await checkIfRevoked({
      capability, purposeParameters, documentLoader});
    if(revoked) {
      throw new Error('Capability has been revoked.');
    }*/

    // check custom caveats
    const caveatRegistry = {};
    const {caveat: caveatHandlers = []} = purposeParameters;
    for(const handler of caveatHandlers) {
      caveatRegistry[handler.type] = handler;
    }
    const caveats = jsonld.getValues(capability, 'caveat');
    try {
      await Promise.all(caveats.map(async caveat => {
        const {type} = caveat;
        const handler = caveatRegistry[type];
        if(!handler) {
          throw new Error(
            `Caveat handler not found for caveat type "${type}".`);
        }
        const result = await handler.validate(
          caveat, {capability, documentLoader, expansionMap});
        if(!result.valid) {
          throw new Error(
            `Caveat of type ${type} not met: ${result.error.message}`);
        }
      }));
    } catch(error) {
      return {valid: false, error};
    }
    return {valid: true};
  } catch(error) {
    return {valid: false, error};
  }
};

// FIXME: remove
/**
 * The default do-nothing check for if things are revoked
 */
/*async function noopRevocationChecker() {
  return false;
}
*/

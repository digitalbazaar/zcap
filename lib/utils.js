/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const defaultCaveatRegistry = require('./caveatRegistry');

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
 * @param {Object} jsonld - a configured instance of jsonld.
 * @param {Object} documentLoader - a configured jsonld documentLoader.
 *
 * @return {Object} the retrieved JSON-LD document.
 */
api.fetchInSecurityContext = async ({url, jsonld, documentLoader}) => {
  if(url && typeof url === 'object' &&
    url['@context'] === constants.SECURITY_CONTEXT_V2_URL) {
    return url;
  }
  return jsonld.compact(
    url, constants.SECURITY_CONTEXT_V2_URL,
    {documentLoader, compactToRelative: false});
};

/**
 * Retrieves the delegation proof(s) for a capability that is associated with
 * its parent capability. A capability that has no parent or no associated
 * delegation proofs will cause this function to return an empty array.
 *
 * @param {Object} capability - the JSON-LD document for the object capability
 *          compacted to the security context.
 * @param {Object} jsonld - a configured instance of jsonld.
 *
 * @return {Object} any `capabilityDelegation` proof objects attached to the
 *           given capability.
 */
api.getDelegationProofs = ({capability, jsonld}) => {
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
 * @param {Object} jsonld - a configured instance of jsonld.
 *
 * @return {Object} any `capabilityDelegation` proof objects attached to the
 *           given capability.
 */
api.getCapabilityChain = ({capability, proof, jsonld}) => {
  if(!capability.parentCapability) {
    // root capability has no chain
    return [];
  }

  const proofs = proof ?
    [proof] : api.getDelegationProofs({capability, jsonld});
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
 * @param {Object} jsonld - a configured instance of jsonld.
 * @param {Object} documentLoader - a configured jsonld documentLoader.
 *
 * @return {Object} any `capabilityDelegation` proof objects attached to the
 *           given capability.
 */
api.computeCapabilityChain = async ({capability, jsonld, documentLoader}) => {
  // fetch parent capability
  const {parentCapability} = capability;
  if(!parentCapability) {
    throw new Error(
      'Cannot compute capability chain; capability has no "parentCapability".');
  }

  // FIXME: must validate parent capability?
  const parent = await api.fetchInSecurityContext(
    {url: parentCapability, jsonld, documentLoader});
  if(!parent.parentCapability) {
    // parent is root capability
    return [parentCapability];
  }

  const proofs = api.getDelegationProofs({capability: parent, jsonld});
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
 * @param {Object} jsigs - a configured instance of jsonld-signatures.
 * @param {Object} jsonld - a configured instance of jsonld.
 * @param {Object} documentLoader - a configured jsonld documentLoader.
 *
 * @return {Object} {verified, error, verifiedParentCapability}.
 */
api.verifyCapabilityChain = async ({
  capability, proof, purposeParameters, jsigs, jsonld, documentLoader}) => {
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
      {url: capability, jsonld, documentLoader});

    // 2. Get the capability delegation chain for the capability.
    const capabilityChain = api.getCapabilityChain({capability, proof, jsonld});

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
      {url: root, jsonld, documentLoader});
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
      capability: root,
      purposeParameters,
      jsigs,
      jsonld,
      documentLoader
    }));
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
    for(let cap of capabilityChain) {
      cap = await api.fetchInSecurityContext(
        {url: cap, jsonld, documentLoader});
      const result = await jsigs.verify(cap, {
        purpose: 'capabilityDelegation',
        purposeParameters: {
          ...purposeParameters,
          verifiedParentCapability
        }
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
 * @param {Object} jsigs - a configured instance of jsonld-signatures.
 * @param {Object} jsonld - a configured instance of jsonld.
 * @param {Object} documentLoader - a configured jsonld documentLoader.
 *
 * @return {Object} {valid, error}.
 */
api.checkCaveats = async (
  {capability, purposeParameters, jsigs, jsonld, documentLoader}) => {
  try {
    // check built-in revocation caveat
    const {revocationChecker: checkIfRevoked = noopRevocationChecker} =
      purposeParameters;

    // FIXME: seems like the return value should be {revoked, reason}
    const revoked = await checkIfRevoked({
      capability, purposeParameters, jsigs, jsonld, documentLoader});
    if(revoked) {
      throw new Error('Capability has been revoked.');
    }

    // check custom caveats
    const {caveat} = capability;
    let caveats;
    if(!caveat) {
      caveats = [];
    } else if(caveat && !Array.isArray(caveat)) {
      caveats = [caveat];
    } else {
      caveats = caveat;
    }
    const caveatRegistry = {
      ...purposeParameters.caveatRegistry,
      ...defaultCaveatRegistry
    };
    for(const caveat of caveats) {
      const {type} = caveat;
      const caveatType = await expandCaveatType({type, jsonld, documentLoader});
      const caveatChecker = caveatRegistry[caveatType];
      if(!caveatChecker) {
        throw new Error(
          'Caveat checker not found for caveat type: ' + caveatType);
      }
      // FIXME: should return `valid: Boolean, error`
      const success = await caveatChecker(
        {caveat, capability, purposeParameters});
      if(!success) {
        throw new Error('Caveat not met: ' + caveatType);
      }
    }
    return {valid: true};
  } catch(error) {
    return {valid: false, error};
  }
};

/**
 * Validates that the invoker is the creator of the key or controls the key.
 *
 * @param {String} creator - the creator of the key.
 * @param {String} invoker - the required key creator or controller.
 * @param {Object} jsonld - a configured instance of jsonld.
 * @param {Object} documentLoader - a configured jsonld documentLoader.
 *
 * @return {Object} {valid, error}.
 */
api.validateInvoker = async ({creator, invoker, jsonld, documentLoader}) => {
  return genericValidateParty({
    id: invoker,
    purpose: 'capabilityInvocation',
    creator,
    jsonld,
    documentLoader
  });
};

/**
 * Validates that the delegator is the creator of the key or controls the key.
 *
 * @param {String} creator - the creator of the key.
 * @param {String} delegator - the required key creator or owner.
 * @param {Object} jsonld - a configured instance of jsonld.
 * @param {Object} documentLoader - a configured jsonld documentLoader.
 *
 * @return {Object} {valid, error}.
 */
api.validateDelegator = async (
  {creator, delegator, documentLoader, jsonld}) => {
  return genericValidateParty({
    id: delegator,
    purpose: 'capabilityDelegation',
    creator,
    jsonld,
    documentLoader
  });
};

/**
 * Validates that the id is the creator of the key or controls the key.
 *
 * @param {String} creator - the creator of the key.
 * @param {String} id - the id of the creator or owner.
 * @param {Object} jsonld - a configured instance of jsonld.
 * @param {Object} documentLoader - a configured jsonld documentLoader.
 * @param {String} purpose - 'capabilityInvocation' or 'capabilityDelegation'.
 *
 * * @return {Object} {valid, error}.
 */
async function genericValidateParty(
  {id, creator, documentLoader, jsonld, purpose}) {
  try {
    if(!id) {
      const type = purpose.substr('capability'.length);
      throw new Error(`${type} is not permitted.`);
    }

    // id is a key
    if(id === creator) {
      return {valid: true};
    }

    // id is the controller of keys
    // retrieve the keys associated with proof purpose
    const frame = {
      '@context': constants.SECURITY_CONTEXT_V2_URL,
      id,
      [purpose]: {
        '@embed': '@always',
        publicKey: {
          // TODO: Simplify frame, remove the publicKey once verification
          // suites are implemented
          '@embed': '@never',
          id: creator
        }
      }
    };
    const opts = {documentLoader, compactToRelative: false};
    const framed = await jsonld.frame(id, frame, opts);
    const [result] = framed['@graph'];
    const [key] = jsonld.getValues(result, purpose);
    const party = purpose === 'capabilityInvocation' ? 'invoker' : 'delegator';
    if(!key.publicKey === creator) {
      throw new Error(
        `The required ${party} does not control the key used to ` +
        'create the proof.');
    }
    return {valid: true};
  } catch(error) {
    return {valid: false, error};
  }
}

/**
 * The default do-nothing check for if things are revoked
 */
async function noopRevocationChecker() {
  return false;
}

async function expandCaveatType({type, jsonld, documentLoader}) {
  const expanded = await jsonld.expand({
    '@context': constants.SECURITY_CONTEXT_V2_URL,
    type
  }, {documentLoader});
  return expanded[0]['@type'][0];
}

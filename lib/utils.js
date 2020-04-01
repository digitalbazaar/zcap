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
 * Retrieves the authorized delegators from a capability.
 *
 * @param {Object} capability - the JSON-LD document for the object capability
 *          compacted to the security context.
 *
 * @return {Array} the delegators for the capability (empty for none).
 */
api.getDelegators = capability => {
  const {controller, delegator, id, invoker} = capability;
  // if neither a delegator, controller, nor id is found on the capability then
  // the capability can not be delegated
  if(!(delegator || controller || id)) {
    throw new Error('Delegator not found for capability.');
  }
  // if there's an invoker present and not a delegator, then this capability
  // was intentionally meant to not be delegated
  if(invoker && !delegator) {
    return [];
  }
  const result = delegator || controller || id;
  return Array.isArray(result) ? result : [result];
};

/**
 * Retrieves the authorized invokers from a capability.
 *
 * @param {Object} capability - the JSON-LD document for the object capability
 *          compacted to the security context.
 *
 * @return {Array} the invokers for the capability (empty for none).
 */
api.getInvokers = capability => {
  const {controller, delegator, id, invoker} = capability;
  // if neither an invoker, controller, nor id is found on the capability then
  // the capability can not be invoked
  if(!(invoker || controller || id)) {
    throw new Error('Invoker not found for capability.');
  }
  // if there's a delegator present and not an invoker, then this capability
  // was intentionally meant to not be invoked
  if(delegator && !invoker) {
    return [];
  }
  const result = invoker || controller || id;
  return Array.isArray(result) ? result : [result];
};

/**
 * Returns true if the given verification method is a delegator or is
 * controlled by a delegator of the given capability.
 *
 * @param {Object} capability - the JSON-LD document for the object capability
 *          compacted to the security context.
 * @param {Object} verificationMethod - the verification method to check.
 *
 * @return {boolean} `true` if the delegator matches, `false` if not.
 */
api.isDelegator = ({capability, verificationMethod}) => {
  const delegators = api.getDelegators(capability);
  const controller = verificationMethod.controller || verificationMethod.owner;
  return (delegators.length > 0 &&
    (delegators.includes(verificationMethod.id) ||
    (controller && delegators.includes(controller))));
};

/**
* Returns true if the given verification method is a invoker or is
* controlled by an invoker of the given capability.
 *
 * @param {Object} capability - the JSON-LD document for the object capability
 *          compacted to the security context.
 * @param {Object} verificationMethod - the verification method to check.
 *
 * @return {boolean} `true` if the invoker matches, `false` if not.
 */
api.isInvoker = ({capability, verificationMethod}) => {
  const invokers = api.getInvokers(capability);
  const controller = verificationMethod.controller || verificationMethod.owner;
  return (invokers.length > 0 &&
    (invokers.includes(verificationMethod.id) ||
    (controller && invokers.includes(controller))));
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
  let {invocationTarget} = capability;
  if(invocationTarget && typeof invocationTarget === 'object') {
    invocationTarget = invocationTarget.id;
  } else if(typeof invocationTarget !== 'string') {
    invocationTarget = capability.id;
  }
  return invocationTarget;
};

/**
 * Fetches a JSON-LD document from a URL and, if necessary, compacts it to
 * the security v2 context.
 *
 * @param {String} url - the URL to fetch.
 * @param {boolean} [isRoot=false] - true if the given url is for a root
 *   capability, in which case it must be dereferenced via a document loader
 *   to ensure it is valid; this is because root capabilities need not
 *   include delegation proofs that vouch for their authenticity.
 * @param {function} documentLoader - a configured jsonld documentLoader.
 * @param {object} expansionMap - a configured jsonld expansionMap.
 *
 * @return {Object} the retrieved JSON-LD document.
 */
api.fetchInSecurityContext = async ({
  url, isRoot, documentLoader, expansionMap
}) => {
  if(url && typeof url === 'object' &&
    url['@context'] === constants.SECURITY_CONTEXT_V2_URL) {
    if(!isRoot) {
      return url;
    }
    // since URL is for a root capability, we must dereference it
    url = url.id;
  }
  return jsonld.compact(url, constants.SECURITY_CONTEXT_V2_URL, {
    documentLoader, expansionMap, compactToRelative: false
  });
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

    if(typeof last === 'string') {
      return last === capability.parentCapability;
    }
    return last.id === capability.parentCapability;
  });
};

/**
 * Gets the `capabilityChain` associated with the given capability.
 *
 * @param {Object} capability - the JSON-LD document for the object capability
 *          compacted to the security context.
 *
 * @return {Object} any `capabilityDelegation` proof objects attached to the
 *           given capability.
 */
api.getCapabilityChain = ({capability}) => {
  if(!capability.parentCapability) {
    // root capability has no chain
    return [];
  }

  const proofs = api.getDelegationProofs({capability});
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
 * @param [maxChainLength=10] - The maximum length of the capability delegation
 *   chain.
 *
 * @return {Object} {valid, error}.
 */
api.validateCapabilityChain = ({
  capability, capabilityChain, maxChainLength = constants.MAX_CHAIN_LENGTH
}) => {
  // add one to the chain length because `capabilityChain` does not include
  // the given capability itself
  if(capabilityChain.length + 1 > maxChainLength) {
    return {
      valid: false,
      error: new Error(
        'The capabability chain exceeds the maximum allowed length ' +
        `of ${maxChainLength}.`)
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
 * A capability to inspect. The capability is compacted into the security
 * context. Only the required fields are shown here, a capability will contain
 * additional properties.
 * @typedef {Object} Capability
 * @property {string} id - The ID of the capability.
 * @property {string} invoker - The invoker of the capability.
 * @property {string} [delegator] - The delegator of the capability. The last
 *   capability in the chain will not have a delegator.
 */

/**
 * The capability to inspect.
 * @typedef {Object} CapabilityChainDetails
 * @property {Capability[]} capabilityChain - The capabilities in the chain.
 * @property {Object[]} capabilityChainMeta - The results returned from
 *   jsonld-signatures verify for each capability in the chain.
 */

/**
 * The result of a capability chain inspection.
 * @typedef {Object} InspectChainResult
 * @property {boolean} valid - Is the chain valid.
 * @property {Error} [error] - When valid is false, a descriptive Error.
 */

/**
 * Verifies the capability chain, if any, attached to the given capability.
 *
 * Verifying the given capability chain means ensuring that the tail capability
 * (the one given) has been properly delegated and that the head (or root) of
 * the chain matches the expected target.
 *
 * @param {Object} capability - the JSON-LD document for the object capability,
 *   compacted to the security v2 context.
 * @param {boolean} [excludeGivenCapability=false] - `true` to exclude
 *   verifying the capability delegation proof for the given `capability`,
 *   `false` to verify it.
 * @param {Object} purposeParameters  - a set of options for validating the
 *   proof purpose.
 * @param {function} documentLoader - a configured jsonld documentLoader.
 * @param {function}
 *   [inspectCapabilityChain(CapabilityChainDetails):InspectResult] -
 *   An async function that can be used to check for revocations related to
 *   any of the capabilities. The expected return value is a Promise. See
 *   the documentation for CapabilityChainDetails and InspectChainResult above.
 * @param {Object} expansionMap - a configured jsonld expansionMap.
 * @param [currentDate = new Date()] {Date} - The date used for comparison
 *   when determining if a capability has expired.
 * @param [maxChainLength=10] - The maximum length of the capability delegation
 *   chain.
 * @param [allowTargetAttenuation=false] {boolean} - Allow the
 *   invocationTarget of a delegation chain to be increasingly restrictive
 *   based on a hierarchical RESTful URL structure.
 *
 * @return {Object} {verified, error, verifiedParentCapability}.
 */
api.verifyCapabilityChain = async ({
  capability, inspectCapabilityChain, excludeGivenCapability = false,
  purposeParameters, documentLoader, expansionMap, currentDate = new Date(),
  maxChainLength, allowTargetAttenuation = false
}) => {
  /* Verification process is:
    1. Fetch capability if only its ID was passed.
    1.1. Ensure `capabilityAction` is allowed.
    2. Get the capability delegation chain for the capability.
    3. Validate the capability delegation chain.
    4. Verify the root capability:
      4.1. Check the expected target, if one was specified.
      4.2. Ensure that the caveats are met on the root capability.
      4.3. Ensure root capability is expected and has no invocation target.
    5. If `excludeGivenCapability` is not true, then we need to verify the
       capability delegation proof on `capability`, so add it to the chain to
       get processed below.
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

    // 1.1. Ensure `capabilityAction`, if given, is allowed; if the capability
    // restricts the actions via `allowedAction` then it must be in the set.
    const allowedAction = jsonld.getValues(capability, 'allowedAction');
    const {capabilityAction, expectedAction} = purposeParameters;
    if(allowedAction.length > 0 && capabilityAction !== undefined &&
      !allowedAction.includes(capabilityAction)) {
      throw new Error(
        `Capability action "${capabilityAction}" is not allowed by the ` +
        'capability; allowed actions are: ' +
        allowedAction.map(x => `"${x}"`).join(', '));
    }
    if(expectedAction && capabilityAction !== expectedAction) {
      throw new Error(
        `Capability action "${capabilityAction}" does not match the expected ` +
        `capability action of "${expectedAction}".`);
    }

    // 2. Get the capability delegation chain for the capability.
    const capabilityChain = api.getCapabilityChain({capability});

    // 3. Validate the capability delegation chain.
    let {valid, error} = api.validateCapabilityChain(
      {capability, capabilityChain, maxChainLength});
    if(!valid) {
      throw error;
    }

    // 4. Verify root capability (note: it must *always* be dereferenced since
    // it does not need to have a delegation proof to vouch for its authenticity
    // ... dereferencing it prevents adversaries from submitting an invalid
    // root capability that is accepted):
    const isRoot = capabilityChain.length === 0;
    let root = isRoot ? capability : capabilityChain.shift();
    root = await api.fetchInSecurityContext(
      {url: root, isRoot, documentLoader, expansionMap});

    // 4.1. Check the expected target, if one was specified.
    const {expectedTarget, expectedRootCapability} = purposeParameters;
    if(expectedTarget !== undefined) {
      const target = api.getTarget(root);
      if(!((Array.isArray(expectedTarget) && expectedTarget.includes(target)) ||
        (typeof expectedTarget === 'string' && target === expectedTarget))) {
        throw new Error(
          `Expected target (${expectedTarget}) does not match ` +
          `root capability target (${target}).`);
      }
    }
    // 4.2. Ensure that the caveats are met on the root capability.
    valid = false;
    error = null;
    ({valid, error} = await api.checkCaveats({
      capability: root, purposeParameters, documentLoader, expansionMap}));
    if(!valid) {
      throw error;
    }

    let rootExpirationDate;
    if(root.expires !== undefined) {
      rootExpirationDate = Date.parse(root.expires);
      if(isNaN(rootExpirationDate)) {
        throw new Error(
          'The "expires" field in the root capability is invalid.');
      }
      if(currentDate.getTime() > rootExpirationDate) {
        throw new Error('The root capability has expired.');
      }
    }

    // 4.3. Ensure root capability is expected and has no invocation target.

    // run root capability checks (note that these will only be run once
    // because the `verifiedParentCapability` parameter stops recursion
    // from happening below)

    // ensure that the invocation target matches the root capability or,
    // if `expectedRootCapability` is present, that it matches that
    if(expectedRootCapability !== undefined) {
      if(!((Array.isArray(expectedRootCapability) &&
        expectedRootCapability.includes(root.id)) ||
        (typeof expectedRootCapability === 'string' &&
          root.id === expectedRootCapability))) {
        throw new Error(
          `Expected root capability (${expectedRootCapability}) does not ` +
          `match actual root capability (${root.id}).`);
      }
    } else if(api.getTarget(root) !== root.id) {
      throw new Error(
        'The root capability must not specify a different ' +
        'invocation target.');
    }

    // root capability now verified
    let verifiedParentCapability = root;

    // if verifying a delegation proof and we're at the root, exit early
    if(isRoot) {
      return {verified: true, verifiedParentCapability};
    }

    // create a document loader that will use properly embedded capabilities
    const dlMap = new Map();
    let next = capabilityChain;
    while(next.length > 0) {
      // the only capability that may be embedded (if the zcap is valid) is
      // the last one in the chain, if it is embedded, add it to `dlMap` and
      // recurse into its chain and loop to collect all embedded zcaps
      let cap = next[next.length - 1];
      if(typeof cap !== 'object') {
        break;
      }
      if(!cap['@context']) {
        // the capabilities in the chain are already in the security context
        // if no context has been specified
        cap['@context'] = constants.SECURITY_CONTEXT_V2_URL;
      }
      // Transforms the `capability` into the security context (the native
      // context this code uses) so we can process it cleanly and then
      // verifies the capability delegation proof on `capability`. This allows
      // capabilities to be expressed using custom contexts.
      cap = await api.fetchInSecurityContext(
        {url: cap, documentLoader, expansionMap});
      dlMap.set(cap.id, cap);
      next = api.getCapabilityChain({capability: cap});
    }
    const dl = async (...args) => {
      const [url] = args;
      const document = dlMap.get(url);
      if(document) {
        return {
          contextUrl: null,
          documentUrl: url,
          document
        };
      }
      return documentLoader.apply(documentLoader, args);
    };

    // 5. If `excludeGivenCapability` is not true, then we need to verify the
    //  capability delegation proof on `capability`, so add it to the chain to
    //  get processed below. If an `inspectCapabilityChain` handler has been
    //  provided, the verify results are required on all capabilities.
    let pushedGivenCapability = false;
    if(inspectCapabilityChain || !excludeGivenCapability) {
      capabilityChain.push(capability);
      pushedGivenCapability = true;
    }

    // 6. For each capability `cap` in the chain, verify the capability
    //   delegation proof on `cap`. This will validate everything else for
    //   `cap` including that caveats are met.
    const {suite, caveat, CapabilityDelegation} = purposeParameters;
    // note that `verifiedParentCapability` will prevent repetitive checking
    // of the same segments of the chain (once a parent is verified, its chain
    // is not checked again when checking its children)
    const dereferencedCapabilities = [];
    const capabilityChainMeta = [];

    // eslint-disable-next-line prefer-const
    for(let [i, cap] of capabilityChain.entries()) {
      // Transforms the `capability` into the security context (the native
      // context this code uses) so we can process it cleanly and then
      // verifies the capability delegation proof on `capability`. This allows
      // capabilities to be expressed using custom contexts.
      cap = await api.fetchInSecurityContext(
        {url: cap, documentLoader: dl, expansionMap});
      const verifyResult = await jsigs.verify(cap, {
        suite,
        purpose: new CapabilityDelegation({
          allowTargetAttenuation,
          expectedTarget,
          expectedRootCapability,
          capabilityAction,
          verifiedParentCapability,
          caveat
        }),
        documentLoader: dl,
        expansionMap,
        compactProof: false
      });
      if(!verifyResult.verified) {
        // FIXME: which error to return?
        const error = verifyResult.error || (verifyResult.keyResults[0] ||
          {}).error || new Error('Capability delegation proof not verified.');
        throw error;
      }
      capabilityChainMeta.push({verifyResult});
      dereferencedCapabilities.push(cap);
      if(i !== capabilityChain.length - 1 || !pushedGivenCapability) {
        verifiedParentCapability = cap;
      }
    }

    // ensure that the delegation chain does not expand the `allowedAction` of
    // the original delgation
    const fullCapabilityChain = pushedGivenCapability ?
      dereferencedCapabilities : [...dereferencedCapabilities, capability];
    let parentAllowedAction;
    let parentExpirationDate = rootExpirationDate;
    for(const c of fullCapabilityChain) {
      const {allowedAction} = c;
      let valid = false;
      // if the parent's allowedAction is undefined, then any more restrictive
      // action is allowed in the child
      if(!parentAllowedAction) {
        valid = true;
      } else if(Array.isArray(parentAllowedAction)) {
        if(Array.isArray(allowedAction)) {
          valid = allowedAction.every(a => parentAllowedAction.includes(a));
        } else {
          valid = parentAllowedAction.includes(allowedAction);
        }
      } else {
        valid = (parentAllowedAction === allowedAction);
      }

      // if the capability is already invalid, no need proceed further
      if(!valid) {
        throw new Error('The `allowedAction` in a delegated capability ' +
          'must be equivalent or more restrictive than its parent.');
      }

      // verify expiration dates
      // if the parent does not specify an expiration date, then any more
      // restrictive expiration date is acceptable
      let currentCapabilityExpirationDate;
      if(c.expires !== undefined) {
        currentCapabilityExpirationDate = Date.parse(c.expires);
        if(isNaN(currentCapabilityExpirationDate)) {
          throw new Error(
            'The "expires" field in a delegated capability is invalid.');
        }
      }

      if(parentExpirationDate !== undefined ||
        currentCapabilityExpirationDate !== undefined) {
        // handle case where `expires` is set in the parent, but the child
        // does not have `exires` or when the child has an expiration date
        // greater than the parent.
        if(currentCapabilityExpirationDate === undefined ||
          currentCapabilityExpirationDate > parentExpirationDate) {
          throw new Error('The `expires` property in a delegated ' +
            'capability must be equivalent or more restrictive than its ' +
            'parent.');
        }
        if(currentDate.getTime() > currentCapabilityExpirationDate) {
          throw new Error('A capability in the delegation chain has expired.');
        }
      }

      parentAllowedAction = c.allowedAction;
      parentExpirationDate = currentCapabilityExpirationDate;
    }

    if(inspectCapabilityChain) {
      const {valid, error} = await inspectCapabilityChain({
        capabilityChain: dereferencedCapabilities,
        capabilityChainMeta,
      });
      if(!valid) {
        throw error;
      }
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

/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {
  MAX_CHAIN_LENGTH, ZCAP_CONTEXT_URL, ZCAP_ROOT_PREFIX
} from './constants.js';

/**
 * Creates a root capability from a root controller and a root invocation
 * target.
 *
 * @param {object} options - The options.
 * @param {string|Array} options.controller - The root controller.
 * @param {string} options.invocationTarget - The root invocation target.
 *
 * @returns {object} The root capability.
 */
export function createRootCapability({controller, invocationTarget}) {
  return {
    '@context': ZCAP_CONTEXT_URL,
    id: `${ZCAP_ROOT_PREFIX}${encodeURIComponent(invocationTarget)}`,
    controller,
    invocationTarget
  };
}

/**
 * Retrieves the controller(s) from a capability.
 *
 * @param {object} options - The options.
 * @param {object} options.capability - The authorization capability (zcap).
 *
 * @returns {Array} The controller(s) for the capability.
 */
export function getControllers({capability}) {
  const {controller} = capability;
  if(!controller) {
    throw new Error('Capability controller not found.');
  }
  return Array.isArray(controller) ? controller : [controller];
}

/**
 * Returns true if the given verification method is a controller (or is
 * controlled by a controller) of the given capability.
 *
 * @param {object} options - The options.
 * @param {object} options.capability - The authorization capability (zcap).
 * @param {object} options.verificationMethod - The verification method to
 *   check.
 *
 * @returns {boolean} `true` if the controller matches, `false` if not.
 */
export function isController({capability, verificationMethod}) {
  const controllers = getControllers({capability});
  return controllers.includes(verificationMethod.controller) ||
    controllers.includes(verificationMethod.id);
}

/**
 * Retrieves the allowed actions from a capability.
 *
 * @param {object} options - The options.
 * @param {object} options.capability - The authorization capability (zcap).
 *
 * @returns {Array} Allowed actions.
 */
export function getAllowedActions({capability}) {
  const {allowedAction} = capability;
  if(!allowedAction) {
    return [];
  }
  if(Array.isArray(allowedAction)) {
    return allowedAction;
  }
  return [allowedAction];
}

/**
 * Retrieves the target from a capability.
 *
 * @param {object} options - The options.
 * @param {object} options.capability - The authorization capability (zcap).
 *
 * @returns {string} - Capability target.
 */
export function getTarget({capability}) {
  // zcaps MUST have an `invocationTarget` that is a string
  return capability.invocationTarget;
}

/**
 * Retrieves the delegation proof(s) for a capability that is associated with
 * its parent capability. A capability that has no parent or no associated
 * delegation proofs will cause this function to return an empty array.
 *
 * @param {object} options - The options.
 * @param {object} options.capability - The authorization capability.
 *
 * @returns {object} Any `capabilityDelegation` proof objects attached to the
 *   given capability.
 */
export function getDelegationProofs({capability}) {
  // capability is root or capability has no `proof`, then it has no relevant
  // delegation proofs
  if(!capability.parentCapability || !capability.proof) {
    return [];
  }
  let {proof} = capability;
  if(!Array.isArray(proof)) {
    proof = [proof];
  }
  return proof.filter(p => p && p.proofPurpose === 'capabilityDelegation');
}

/**
 * Gets the `capabilityChain` associated with the given capability.
 *
 * @param {object} options - The options.
 * @param {object} options.capability - The authorization capability.
 *
 * @returns {object} Any `capabilityDelegation` proof objects attached to the
 *   given capability.
 */
export function getCapabilityChain({capability}) {
  if(!capability.parentCapability) {
    // root capability has no chain
    return [];
  }

  const proofs = getDelegationProofs({capability});
  if(proofs.length !== 1) {
    throw new Error(
      'Cannot get capability chain; capability is invalid; it is not the ' +
      'root capability yet it does not have exactly one delegation proof.');
  }

  const {capabilityChain} = proofs[0];
  if(!(capabilityChain && Array.isArray(capabilityChain))) {
    throw new Error(
      'Cannot get capability chain; capability is invalid; it does not have ' +
      'a "capabilityChain" array in its delegation proof.');
  }

  return capabilityChain.slice();
}

/**
 * Determines if the given `invocationTarget` is valid given a
 * `baseInvocationTarget`.
 *
 * To check for a proper delegation, `invocationTarget` must be the child
 * capability's `invocationTarget` and `baseInvocationTarget` must be the
 * parent capability's `invocationTarget`.
 *
 * To check for a proper invocation, `invocationTarget` must be the value from
 * the invocation proof and `baseInvocationTarget` must be the invoked
 * capability's `invocationTarget`.
 *
 * @param {object} options - The options.
 * @param {string} options.invocationTarget - The invocation target to check.
 * @param {string} options.baseInvocationTarget - The base invocation target.
 * @param {boolean} options.allowTargetAttenuation - `true` to allow target
 *   attenuation.
 *
 * @returns {boolean} `true` if the target is valid, `false` if not.
 */
export function isValidTarget({
  invocationTarget, baseInvocationTarget, allowTargetAttenuation
}) {
  // direct match, valid
  if(baseInvocationTarget === invocationTarget) {
    return true;
  }
  if(allowTargetAttenuation) {
    /* Note: When `allowTargetAttenuation=true`, a zcap can be invoked with
    a more narrow target and delegated zcap can have a different invocation
    target from its parent. Here we must ensure that the invocation target
    has a proper prefix relative to the base one we're comparing against.

    If the `baseInvocationTarget` already has a query (has `?`) then the
    suffix that follows it must start with `&`. Otherwise, it may start
    with either `/` or `?`. */
    const prefixes = [];
    if(baseInvocationTarget.includes('?')) {
      // query already present in base invocation target, so only accept new
      // variables in the query
      prefixes.push(`${baseInvocationTarget}&`);
    } else {
      // accept path-based attenuation or new query-based attenuation
      prefixes.push(`${baseInvocationTarget}/`);
      prefixes.push(`${baseInvocationTarget}?`);
    }
    if(prefixes.some(prefix => invocationTarget.startsWith(prefix))) {
      return true;
    }
  }
  // not a match
  return false;
}

/**
 * Creates a capability chain for delegating a capability from the
 * given `parentCapability`.
 *
 * @param {object} options - The options.
 * @param {object} options.parentCapability - The parent capability from
 *   which to compute the capability chain.
 * @param {boolean} options._skipLocalValidationForTesting - Private.
 *
 * @returns {Array} The computed capability chain for the capability to be
 *   included in a capability delegation proof.
 */
export function computeCapabilityChain({
  parentCapability, _skipLocalValidationForTesting
}) {
  // if parent capability is root (string or no parent of its own)
  const type = typeof parentCapability;
  if(type === 'string') {
    return [parentCapability];
  }
  if(!parentCapability.parentCapability) {
    // capability must be a root zcap
    checkCapability({capability: parentCapability, expectRoot: true});
    return [parentCapability.id];
  }

  // capability must be a delegated zcap, check it and get its chain
  checkCapability({capability: parentCapability, expectRoot: false});
  const proofs = getDelegationProofs({capability: parentCapability});
  if(proofs.length !== 1) {
    throw new Error(
      'Cannot compute capability chain; parent capability is invalid; it is ' +
      'not the root capability yet it does not have exactly one delegation ' +
      'proof.');
  }

  const {capabilityChain} = proofs[0];
  if(!(capabilityChain && Array.isArray(capabilityChain))) {
    throw new Error(
      'Cannot compute capability chain; parent capability is invalid; it ' +
      'does not have a "capabilityChain" array in its delegation proof.');
  }

  // validate parent capability chain to help prevent bad delegations
  if(!_skipLocalValidationForTesting) {
    // ensure that all `capabilityChain` entries except the last are strings
    const lastRequiredType = capabilityChain.length > 1 ?
      'object' : 'string';
    const lastIndex = capabilityChain.length - 1;
    for(const [i, entry] of capabilityChain.entries()) {
      const entryType = typeof entry;
      if(!((i === lastIndex && entryType === lastRequiredType) ||
        i !== lastIndex && entryType === 'string')) {
        throw new TypeError(
          'Cannot compute capability chain; parent capability chain is ' +
          'invalid; it must consist of strings of capability IDs except ' +
          'the last capability if it is delegated, in which case it must ' +
          'be an object with an "id" property that is a string.');
      }
    }
  }

  // if last zcap is embedded, change it to a reference
  const newChain = capabilityChain.slice(0, capabilityChain.length - 1);
  const last = capabilityChain[capabilityChain.length - 1];
  if(typeof last === 'string') {
    newChain.push(last);
  } else {
    newChain.push(last.id);
  }
  newChain.push(parentCapability);

  // ensure new chain uses absolute URLs
  for(const entry of newChain) {
    if((typeof entry === 'string' && !entry.includes(':')) ||
      typeof entry === 'object' && !entry.id.includes(':')) {
      throw new Error(
        'Cannot compute capability chain; parent capability chain is ' +
        'invalid because uses relative URL(s) in its capability chain.');
    }
  }

  return newChain;
}

/**
 * Dereferences the capability chain associated with the given capability,
 * ensuring it passes a number of validation checks.
 *
 * A delegated zcap's chain has a reference to a root zcap. A verifier must
 * provide a hook (`getRootCapability`) to dereference this root zcap since
 * the root zcap has no delegation proof and must therefore be trusted by
 * the verifier. If the root zcap can't be dereferenced by the trusted hook,
 * then an authorization error must be thrown by that hook.
 *
 * This function will dereference the root zcap and then dereference all of
 * the embedded delegated zcaps from the chain, combining them into a single
 * array containing full zcaps ordered from root => tail.
 *
 * The dereferenced chain (result of this function) should then compare the
 * root zcap's ID against a list of expected root capabilities, throwing
 * an error if none of them match. Otherwise, the dereferenced chain should
 * then be processed to ensure that all delegation rules have been followed.
 * If checking an invocation, it should also be ensured that a combination of
 * an expected target and a root zcap is permitted (note it is conceivable that
 * a verifier may accept more than one combination, e.g., a target of `x` could
 * work with both root zcap `a` and `b`).
 *
 * @param {object} options - The options.
 * @param {string|object} options.capability - The authorization capability
 *   (zcap) to get the chain for.
 * @param {Function} options.getRootCapability - A function for dereferencing
 *   the root capability (the root zcap must be deref'd in a trusted way by the
 *   verifier, it must not be untrusted input).
 * @param {number} [options.maxChainLength=10] - The maximum length of the
 *   capability delegation chain (this is inclusive of `capability` itself).
 *
 * @returns {Promise<object>} {dereferencedChain}.
 */
export async function dereferenceCapabilityChain({
  capability, getRootCapability, maxChainLength = MAX_CHAIN_LENGTH
}) {
  // capability MUST be a string if it is root; root zcaps MUST always be
  // dereferenced via a trusted mechanism provided by the verifier as they
  // do not have delegation proofs
  if(typeof capability === 'string') {
    const id = capability;
    const {rootCapability} = await getRootCapability({id});
    checkCapability({capability: rootCapability, expectRoot: true});
    if(rootCapability.id !== id) {
      throw new Error(
        `Dereferenced root capability ID "${rootCapability.id}" does not ` +
        `match reference ID "${id}".`);
    }
    capability = rootCapability;
  } else {
    // ensure capability itself is valid
    checkCapability({capability, expectRoot: false});
  }

  // get a mapping of IDs to full zcaps as the chain is validated
  const dereferencedChainMap = new Map();

  // get the underef'd capability chain for the capability
  const capabilityChain = getCapabilityChain({capability});

  // ensure capability chain length (add 1 to be inclusive of `capability`)
  // does not exceed max chain length; only check this once at the start
  // as it produces the most sensible error -- it is true that an embedded
  // zcap could go over the limit but this will be caught via a congruency
  // check on the length instead
  if((capabilityChain.length + 1) > maxChainLength) {
    throw new Error(
      'The capability chain exceeds the maximum allowed length ' +
      `of ${maxChainLength}.`);
  }

  // subtract one from the max chain length to start to account for
  // `capability` which is not present in `capabilityChain`
  let firstPass = true;
  let requiredLength = capabilityChain.length;
  let currentCapability = capability;
  let currentCapabilityChain = capabilityChain;
  while(currentCapabilityChain.length > 0) {
    if(currentCapabilityChain.length !== requiredLength) {
      throw new Error('The capability chain length is incongruent.');
    }

    // if `next.length > 1`, then its last entry is a delegated
    // capability and it MUST be fully embedded as an object; all other
    // entries MUST be strings
    const lastRequiredType = currentCapabilityChain.length > 1 ?
      'object' : 'string';

    // validate entries and dereference delegated zcaps
    const lastIndex = currentCapabilityChain.length - 1;
    for(const [i, entry] of currentCapabilityChain.entries()) {
      const entryType = typeof entry;
      const entryIsString = entryType === 'string';
      const requiredType = i === lastIndex ? lastRequiredType : 'string';

      // ensure entry is the required type and, if it is an object, its `id`
      // is a string
      if(!(entryType === requiredType &&
        (entryIsString || typeof entry.id === 'string'))) {
        throw new TypeError(
          'Capability chain is invalid; it must consist of strings ' +
          'of capability IDs except the last capability if it is ' +
          'delegated, in which case it must be an object with an "id" ' +
          'property that is a string.');
      }

      // ensure capability ID expresses an absolute URI (i.e., it has `:`)
      const id = entryIsString ? entry : entry.id;
      if(!id.includes(':')) {
        throw new Error(
          'Capability chain is invalid; it contains a capability ID ' +
          'that is not an absolute URI.');
      }

      // ensure last entry in chain matches parent capability
      if(i === lastIndex && currentCapability.parentCapability &&
        currentCapability.parentCapability !== id) {
        throw new Error(
          'Capability chain is invalid; the last entry does not ' +
          'match the parent capability.');
      }

      if(!entryIsString) {
        // check zcap data model
        checkCapability({capability: entry, expectRoot: i === 0});
      }

      // ensure no cycles in the capability chain
      if(firstPass) {
        // on the first pass, the zcap must not have been seen yet
        if(id === capability.id || dereferencedChainMap.has(id)) {
          throw new Error('The capability chain contains a cycle.');
        }
        // add zcap to the map whether it is only a reference (an ID) or
        // a fully embedded zcap; this will be used to ensure no additional
        // zcaps are added to the chain
        dereferencedChainMap.set(id, entry);
      } else {
        // on non-first pass, every ID should already be in the zcap map
        // and they should all be strings, not objects
        const existing = dereferencedChainMap.get(id);
        if(!existing) {
          // the chain is inconsistent across delegated zcaps
          throw new Error('The capability chain is inconsistent.');
        }
        if(id === capability.id || typeof existing === 'object') {
          // the zcap has been deferenced before, there's a cycle
          throw new Error('The capability chain contains a cycle.');
        }

        // only update the zcaps map using a fully embedded zcap
        if(!entryIsString) {
          dereferencedChainMap.set(id, entry);
        }
      }
    }

    // if the chain has more than the root zcap, loop to process the
    // next chain from the last delegated zcap
    if(currentCapabilityChain.length > 1) {
      // next chain must be 1 shorter than the current one
      requiredLength--;
      currentCapability = currentCapabilityChain[
        currentCapabilityChain.length - 1];
      currentCapabilityChain = getCapabilityChain(
        {capability: currentCapability});
    } else {
      // no more chains to check
      break;
    }

    firstPass = false;
  }

  // dereference root zcap via provided trusted `getRootCapability` function
  if(capabilityChain.length > 0) {
    const [id] = capabilityChain;
    const {rootCapability} = await getRootCapability({id});
    checkCapability({capability: rootCapability, expectRoot: true});
    if(rootCapability.id !== id) {
      throw new Error(
        `Dereferenced root capability ID "${rootCapability.id}" does not ` +
        `match reference ID "${id}" from capability chain.`);
    }
    dereferencedChainMap.set(id, rootCapability);
  }

  // include `capability` in dereferenced map
  dereferencedChainMap.set(capability.id, capability);
  const dereferencedChain = [...dereferencedChainMap.values()];

  return {dereferencedChain};
}

export function checkProofContext({proof}) {
  // zcap context can appear anywhere in the array as it *is* protected
  const {'@context': ctx} = proof;
  if(!((Array.isArray(ctx) && ctx.includes(ZCAP_CONTEXT_URL)) ||
    ctx === ZCAP_CONTEXT_URL)) {
    throw new Error(
      `Missing required capability proof context ("${ZCAP_CONTEXT_URL}").`);
  }
}

export function hasValidAllowedAction({allowedAction, parentAllowedAction}) {
  // if the parent's `allowedAction` is `undefined`, then any more restrictive
  // action is allowed in the child
  if(!parentAllowedAction) {
    return true;
  }

  if(Array.isArray(parentAllowedAction)) {
    // parent's `allowedAction` must include every one from child's
    if(Array.isArray(allowedAction)) {
      return allowedAction.every(a => parentAllowedAction.includes(a));
    }
    return parentAllowedAction.includes(allowedAction);
  }

  // require exact match
  return (parentAllowedAction === allowedAction);
}

export function checkCapability({capability, expectRoot}) {
  const {
    '@context': context,
    id, parentCapability, invocationTarget, allowedAction, expires
  } = capability;

  const isRoot = parentCapability === undefined;
  if(isRoot) {
    if(context !== ZCAP_CONTEXT_URL) {
      throw new Error(
        'Root capability must have an "@context" value of ' +
        `"${ZCAP_CONTEXT_URL}".`);
    }
    if(capability.expires !== undefined) {
      throw new Error(
        'Root capability must not have an "expires" field.');
    }
  } else {
    if(!((Array.isArray(context) && context[0] === ZCAP_CONTEXT_URL))) {
      throw new Error(
        'Delegated capability must have an "@context" array ' +
        `with "${ZCAP_CONTEXT_URL}" in its first position.`);
    }
    if(!(typeof parentCapability === 'string' &&
      parentCapability.includes(':'))) {
      throw new Error(
        'Delegated capability must have a "parentCapability" with a string ' +
        'value that expresses an absolute URI.');
    }
    const [proof] = getDelegationProofs({capability});
    if(!proof) {
      throw new Error('Delegated capability must have a "proof".');
    }
    if(isNaN(Date.parse(proof.created))) {
      throw new Error(
        'Delegated capability must have a valid proof "created" date.');
    }
    if(isNaN(Date.parse(expires))) {
      throw new Error('Delegated capability must have a valid expires date.');
    }
  }

  if(!(typeof id === 'string' && id.includes(':'))) {
    throw new Error(
      'Capability must have an "id" with a string value that expresses an ' +
      'absolute URI.');
  }
  if(!(typeof invocationTarget === 'string' &&
    invocationTarget.includes(':'))) {
    throw new Error(
      'Capability must have an "invocationTarget" with a string value that ' +
      'expresses an absolute URI.');
  }
  if(allowedAction !== undefined && !(
    typeof allowedAction === 'string' ||
    (Array.isArray(allowedAction) && allowedAction.length > 0))) {
    throw new Error(
      'If present on a capability, "allowedAction" must be a string or a ' +
      'non-empty array.');
  }

  if(isRoot !== expectRoot) {
    if(expectRoot) {
      throw new Error(
        `Expected capability "${capability.id}" to be root ` +
        'but it is delegated.');
    }
    throw new Error(
      `Expected capability "${capability.id}" to be delegated but it is root.`);
  }
}

export function compareTime({t1, t2, maxClockSkew}) {
  // `maxClockSkew` is in seconds, so transform to milliseconds
  if(Math.abs(t1 - t2) < (maxClockSkew * 1000)) {
    // times are equal within the max clock skew
    return 0;
  }
  return t1 < t2 ? -1 : 1;
}

// documentation typedefs

/**
 * A inspection function result.
 *
 * @typedef {object} InspectResult
 */

/**
 * A capability chain inspection function.
 *
 * @typedef {Function} InspectCapabilityChain
 * @param {CapabilityChainDetails}
 * @returns {InspectResult}
 */

/**
 * A capability to inspect. The capability is compacted into the security
 * context. Only the required fields are shown here, a capability will contain
 * additional properties.
 *
 * @typedef {object} Capability
 * @property {string} id - The ID of the capability.
 * @property {string} controller - The controller of the capability.
 */

/**
 * The capability to inspect.
 *
 * @typedef {object} CapabilityChainDetails
 * @property {Capability[]} capabilityChain - The capabilities in the chain.
 * @property {CapabilityMeta[]} capabilityChainMeta - The results returned
 *   from jsonld-signatures verify for each capability in the chain. Each
 *   object contains `{verifyResult}` where each `verifyResult` is an
 *   `InspectChainResult`.
 */

/**
 * The meta data resulting from the verification of a delegated capability.
 *
 * @typedef {object} CapabilityMeta
 * @property {VerifyResult} verifyResult - The capability verify result, which
 *   is `null` for the root capability.
 */

/**
 * The result of running jsonld-signature's verify method.
 *
 * @typedef {object} VerifyResult
 * @property {boolean} verified - `true` if all the checked proofs were
 *   successfully verified.
 * @property {VerifyProofResult[]} results - The verify results for each
 *   delegation proof.
 */

/**
 * The result of verifying a capability delegation proof.
 *
 * @typedef {object} VerifyProofResult
 * @property {VerifyProofPurposeResult} proofPurposeResult - The result from
 *   verifying the capability delegation proof purpose.
 */

/**
 * The result of verifying a capability delegation proof purpose.
 *
 * @typedef {object} VerifyProofPurposeResult
 * @property {string} delegator - The party that created the capability
 *   delegation proof, i.e., the party that delegated the capability.
 */

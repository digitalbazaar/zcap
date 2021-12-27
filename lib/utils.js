/*!
 * Copyright (c) 2018-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const jsigs = require('jsonld-signatures');
const {MAX_CHAIN_LENGTH, ZCAP_CONTEXT_URL} = require('./constants');

// FIXME: use `exports.foo` directly for improved destructuring w/ ESM import
const api = {};
module.exports = api;

/**
 * Retrieves the controller(s) from a capability.
 *
 * @param {object} capability - The authorization capability (zcap).
 *
 * @return {Array} The controller(s) for the capability.
 */
api.getControllers = ({capability}) => {
  const {controller} = capability;
  if(!controller) {
    throw new Error('Capability controller not found.');
  }
  return Array.isArray(controller) ? controller : [controller];
};

/**
 * Returns true if the given verification method is a controller (or is
 * controlled by a controller) of the given capability.
 *
 * @param {object} capability - The authorization capability (zcap).
 * @param {object} verificationMethod - The verification method to check.
 *
 * @return {boolean} `true` if the controller matches, `false` if not.
 */
api.isController = ({capability, verificationMethod}) => {
  const controllers = api.getControllers({capability});
  return controllers.includes(verificationMethod.controller) ||
    controllers.includes(verificationMethod.id);
};

/**
 * Retrieves the allowed actions from a capability.
 *
 * @param {object} capability - The authorization capability (zcap).
 */
api.getAllowedActions = ({capability}) => {
  const {allowedAction} = capability;
  if(!allowedAction) {
    return [];
  }
  if(Array.isArray(allowedAction)) {
    return allowedAction;
  }
  return [allowedAction];
};

/**
 * Retrieves the target from a capability.
 *
 * @param {object} capability - The authorization capability (zcap).
 */
api.getTarget = ({capability}) => {
  // zcaps MUST have an `invocationTarget` that is an object with `id` or
  // a string with the ID value
  return capability.invocationTarget.id || capability.invocationTarget;
};

/**
 * Retrieves the delegation proof(s) for a capability that is associated with
 * its parent capability. A capability that has no parent or no associated
 * delegation proofs will cause this function to return an empty array.
 *
 * @param {object} capability - The authorization capability.
 *
 * @return {object} any `capabilityDelegation` proof objects attached to the
 *           given capability.
 */
api.getDelegationProofs = ({capability}) => {
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
};

/**
 * Gets the `capabilityChain` associated with the given capability.
 *
 * @param {object} capability - The authorization capability.
 *
 * @returns {object} Any `capabilityDelegation` proof objects attached to the
 *   given capability.
 */
api.getCapabilityChain = ({capability}) => {
  if(!capability.parentCapability) {
    // root capability has no chain
    return [];
  }

  const proofs = api.getDelegationProofs({capability});
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
};

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
 * @param {string} invocationTarget - The invocation target to check.
 * @param {string} baseInvocationTarget - The base invocation target.
 * @param {boolean} allowTargetAttenuation - `true` to allow target
 *   attenuation.
 *
 * @returns {boolean} `true` if the target is valid, `false` if not.
 */
api.isValidTarget = ({
  invocationTarget, baseInvocationTarget, allowTargetAttenuation
}) => {
  // direct match, valid
  if(baseInvocationTarget === invocationTarget) {
    return true;
  }
  if(allowTargetAttenuation) {
    /* Note: When `allowTargetAttenuation=true`, a zcap can be invoked with
    a more narrow target and delegated zcap can have a different invocation
    target from its parent. Here we must ensure that the invocation target
    has a proper prefix relative to the base one we're comparing against. */
    // target is only acceptable if it is a path-prefix
    const prefix = `${baseInvocationTarget}/`;
    if(invocationTarget.startsWith(prefix)) {
      return true;
    }
  }
  // not a match
  return false;
};

/**
 * Creates a capability chain for delegating the a capability from the
 * given `parentCapability`.
 *
 * @param {object} capability - The authorization capability (zcap).
 * @param {object} parentCapability - The parent capability from which to
 *   compute the capability chain.
 *
 * @return {array} The computed capability chain for the capability to be
 *   included in a capability delegation proof.
 */
api.computeCapabilityChain = ({parentCapability}) => {
  // FIXME: must validate parent capability?

  // if parent capability is root (string or no parent of its own)
  const type = typeof parentCapability;
  if(type === 'string') {
    return [parentCapability];
  }
  if(!parentCapability.parentCapability) {
    return [parentCapability.id];
  }

  // parent capability is delegated, get its chain
  const proofs = api.getDelegationProofs({capability: parentCapability});
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

  // if last zcap was embedded, change it to a reference
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
};

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
 * @param {string|object} capability - The authorization capability (zcap) to
 *   get the chain for.
 * @param {function} getRootCapability - A function for dereferencing the
 *   root capability (the root zcap must be deref'd in a trusted way by the
 *   verifier, it must not be untrusted input).
 * @param [maxChainLength=10] - The maximum length of the capability delegation
 *   chain (this is inclusive of `capability` itself).
 *
 * @return {Promise<object>} {dereferencedChain}.
 */
api.dereferenceCapabilityChain = async ({
  capability, getRootCapability, maxChainLength = MAX_CHAIN_LENGTH
}) => {
  // FIXME: ensure that the logic of this function ensures that if it returns
  // without throwing that the chain that is returned will only have objects
  // and no strings in it

  // capability MUST be a string if it is root; root zcaps MUST always be
  // dereferenced via a trusted mechanism provided by the verifier as they
  // do not have delegation proofs
  if(typeof capability === 'string') {
    const id = capability;
    const {rootCapability} = await getRootCapability({id});
    _validateCapability({capability: rootCapability, expectRoot: true});
    if(rootCapability.id !== id) {
      throw new Error(
        `Dereferenced root capability ID "${rootCapability.id}" does not ` +
        `match reference ID "${id}".`);
    }
    capability = rootCapability;
  } else {
    // FIXME: determine when this should happen
    // ensure capability itself is valid
    _validateCapability({capability, expectRoot: false});
  }

  // get a mapping of IDs to full zcaps as the chain is validated
  const dereferencedChainMap = new Map();

  // get the underef'd capability chain for the capability
  const capabilityChain = api.getCapabilityChain({capability});

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
          'of capability IDs except if the last capability is delegated, ' +
          'in which case it must be an object with an "id" property that ' +
          'is a string.');
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
        // validate zcap
        _validateCapability({capability: entry, expectRoot: i === 0});
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
      currentCapabilityChain = api.getCapabilityChain(
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
    _validateCapability({capability: rootCapability, expectRoot: true});
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
};

/**
 * A capability chain inspection function.
 * @typedef {function} InspectCapabilityChain
 * @param {CapabilityChainDetails}
 * @returns {InspectResult}
 */

/**
 * A capability to inspect. The capability is compacted into the security
 * context. Only the required fields are shown here, a capability will contain
 * additional properties.
 * @typedef {object} Capability
 * @property {string} id - The ID of the capability.
 * @property {string} controller - The controller of the capability.
 */

/**
 * The capability to inspect.
 * @typedef {object} CapabilityChainDetails
 * @property {Capability[]} capabilityChain - The capabilities in the chain.
 * @property {InspectChainResult[]} capabilityChainMeta - The results returned
 *   from jsonld-signatures verify for each capability in the chain. Each
 *   object contains `{verifyResult}` where each `verifyResult` is an
 *   `InspectChainResult`.
 */

/**
 * The result of a capability chain inspection.
 * @typedef {object} InspectChainResult
 * @property {VerifyResult} verifyResult - The capability verify result.
 */

/**
 * The result of running jsonld-signature's verify method.
 * @typedef {object} VerifyResult
 * @property {boolean} verified - `true` if all the checked proofs were
 *   successfully verified.
 * @property {VerifyProofResult[]} results - The verify results for each
 *   delegation proof.
 */

/**
 * The result of verifying a capability delegation proof.
 * @typedef {object} VerifyProofResult
 * @property {VerifyProofPurposeResult} proofPurposeResult - The result from
 *   verifying the capability delegation proof purpose.
 */

/**
 * The result of verifying a capability delegation proof purpose.
 * @typedef {object} VerifyProofPurposeResult
 * @property {string} delegator - The party that created the capability
 *   delegation proof, i.e., the party that delegated the capability.
 */

/**
 * Verifies the given dereferenced capability chain. This involves ensuring
 * that the root zcap in the chain is as expected (for the endpoint where an
 * invocation or a simple chain chain is occurring) and that every other zcap
 * in the chain (including any invoked one), has been properly delegated.
 *
 * @param {class} CapabilityDelegation - The CapabilityDelegation class; this
 *   must be passed to avoid circular references in this module.
 * @param {boolean} [allowTargetAttenuation=false] - Allow the
 *   `invocationTarget` of a delegation chain to be increasingly restrictive
 *   based on a hierarchical RESTful URL structure.
 * @param {InspectChainResult[]} [capabilityChainMeta] - An optional array of
 *   results for inspecting the capability chain; this is passed when the
 *   capability delegation proof for the last capability in the dereferenced
 *   chain has already been verified, signaling that it should be not
 *   reverified within this function; all other verification results will be
 *   added to this array for passing to an optional capability inspection
 *   function.
 * @param {Date} [currentDate = new Date()] - The date used for comparison.
 *   when determining if a capability has expired.
 * @param {array} dereferencedChain - The dereferenced capability chain for
 *   `capability`, starting at the root capability and ending at `capability`.
 * @param {function} documentLoader - A configured jsonld documentLoader.
 * @param {object} expansionMap - A configured jsonld expansionMap.
 * @param {string|array} expectedRootCapability - The expected root
 *   capability for the delegation chain (this can be a single root
 *   capability ID expressed as a string or, if there is more than one
 *   acceptable root capability, several root capability IDs in an array.
 * @param {boolean} [requireChainDateMonotonicity=false] - Require the
 *   created dates on delegation proofs to be monotonically increasing
 *   forward in time.
 * @param {number} [maxDelegationTtl=Infinity] - The maximum time to live
 *   for a delegated zcap (as measured by the time difference between
 *   `expires`, which MUST be present if `maxDelegationTtl !== Infinity`, and
 *   `created` on the delegation proof.
 * @param {object|array} [suite] - The jsonld-signature suite(s) to use to
 *   verify the capability chain.
 *
 * @return {object} {verified, error, verifiedParentCapability}.
 */
api.verifyCapabilityChain = async ({
  CapabilityDelegation,
  allowTargetAttenuation = false,
  capabilityChainMeta = [],
  currentDate = new Date(),
  dereferencedChain,
  documentLoader,
  expansionMap,
  expectedRootCapability,
  maxDelegationTtl = Infinity,
  requireChainDateMonotonicity = false,
  suite
}) => {
  /* Note: We start verifying a capability from its root of trust (the
  beginning or head of the capability chain) as this approach limits an
  attacker's ability to waste our time and effort traversing from the tail
  to the head. To prevent recursively repeating checks, we pass a
  `verifiedParentCapability` each time we start verifying another capability
  delegation proof in the capability chain.

  Verification process is:

  1. Verify the root capability ID matches an expected one.
  2. For each capability `zcap` in the chain, verify the capability delegation
    proof on `zcap` (if `capabilityChainMeta` has no precomputed result) and
    that all of the delegation rules have been followed. */

  /* Note: `verifiedParentCapability` will prevent repetitive checking of
  the same segments of the chain (once a parent is verified, its chain is
  not checked again when checking its children). */
  let verifiedParentCapability = null;

  try {
    // 1. Verify the root capability ID matches an expected one.
    const [root] = dereferencedChain;
    if(!((Array.isArray(expectedRootCapability) &&
      expectedRootCapability.includes(root.id)) ||
      (typeof expectedRootCapability === 'string' &&
        root.id === expectedRootCapability))) {
      throw new Error(
        `Expected root capability (${expectedRootCapability}) does not ` +
        `match actual root capability (${root.id}).`);
    }

    // if the chain only has the root, exit early
    if(dereferencedChain.length === 1) {
      return {
        verified: true,
        verifiedParentCapability,
        capabilityChainMeta
      };
    }

    // 2. For each capability `zcap` in the chain, verify the capability
    //   delegation proof on `zcap` and that the delegation rules have been
    //   followed.
    let parentAllowedAction;
    let parentDelegationDate;
    let parentExpirationDate;
    let {invocationTarget: parentInvocationTarget} = root;

    // track whether `capabilityChainMeta` needs its first result shifted to
    // the end (if a result was present, it is for the last zcap, so move it
    // to the end when we're done checking zcaps below)
    const mustShift = capabilityChainMeta.length > 0;

    // get all delegated capabilities (no root zcap since it has no delegation
    // proof to check)
    const delegatedCapabilities = dereferencedChain.slice(1);
    for(let i = 0; i < delegatedCapabilities.length; ++i) {
      const zcap = delegatedCapabilities[i];
      verifiedParentCapability = delegatedCapabilities[i - 1] || root;

      // verify proof on zcap if no result has been computed yet (one
      // verify result will be present in `capabilityChainMeta` per
      // delegated capability)
      if(capabilityChainMeta.length < delegatedCapabilities.length) {
        const verifyResult = await jsigs.verify(zcap, {
          suite,
          purpose: new CapabilityDelegation({
            allowTargetAttenuation,
            expectedRootCapability,
            verifiedParentCapability,
            maxDelegationTtl,
            requireChainDateMonotonicity
          }),
          documentLoader,
          expansionMap
        });
        if(!verifyResult.verified) {
          throw verifyResult.error;
        }
        // delegation proof verified; save meta data for later inspection
        capabilityChainMeta.push({verifyResult});
      }

      // ensure `allowedAction` is valid (compared against parent)
      const {allowedAction} = zcap;
      if(!_hasValidAllowedAction({allowedAction, parentAllowedAction})) {
        throw new Error(
          'The "allowedAction" in a delegated capability ' +
          'must be equivalent or more restrictive than its parent.');
      }

      // ensure `invocationTarget` delegation is acceptable
      const invocationTarget = api.getTarget({capability: zcap});
      if(!api.isValidTarget({
        invocationTarget,
        baseInvocationTarget: parentInvocationTarget,
        allowTargetAttenuation
      })) {
        if(allowTargetAttenuation) {
          throw new Error(
            `The "invocationTarget" in a delegated capability must be ` +
            'equivalent or more restrictive than its parent.');
        } else {
          throw new Error(
            'The "invocationTarget" in a delegated capability ' +
            'must be equivalent to its parent.');
        }
      }

      // verify expiration dates
      // if the parent does not specify an expiration date, then any more
      // restrictive expiration date is acceptable
      let currentCapabilityExpirationDate;
      if(zcap.expires !== undefined) {
        // expires date has been previously validated, so just parse it
        currentCapabilityExpirationDate = Date.parse(zcap.expires);
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

      // get delegated date if necessary
      let currentCapabilityDelegationDate;
      const getDelegatedDate = requireChainDateMonotonicity ||
        maxDelegationTtl < Infinity;
      if(getDelegatedDate) {
        const proofs = api.getDelegationProofs({capability: zcap});
        // get earliest date from delegation proofs
        for(const p of proofs) {
          const created = Date.parse(p.created);
          if(currentCapabilityDelegationDate === undefined) {
            currentCapabilityDelegationDate = created;
          } else if(currentCapabilityDelegationDate < created) {
            currentCapabilityDelegationDate = created;
          }
        }
      }

      // FIXME: remove optionality here and always run this check
      if(requireChainDateMonotonicity) {
        // verify parent capability was not delegated after child
        if(parentDelegationDate !== undefined &&
          parentDelegationDate > currentCapabilityDelegationDate) {
          throw new Error(
            'A capability in the delegation chain was delegated before ' +
            'its parent.');
        }
      }

      // FIXME: disallow infinity as an option and set a reasonable default
      if(maxDelegationTtl < Infinity) {
        /* Note: Here we ensure zcap has a time-to-live (TTL) that is
        sufficiently short. This is to prevent the use of zcaps that, when
        revoked, will have to be stored for long periods of time. We have to
        ensure:

        1. The zcap has an expiration date.
        2. The zcap's delegation date is not in the future (this also ensures
          that the zcap's expiration date is not before its delegation date as
          it would have triggered an expiration error in a previous check).
        3. The zcap's current TTL is <= `maxDelegationTtl`
        4. The zcap's TTL was never > `maxDelegationTtl`. */
        if(zcap.expires === undefined) {
          throw new Error(
            'A delegated capability in the delegation chain does not have ' +
            'an expiration date.');
        }
        if(currentCapabilityDelegationDate > currentDate) {
          throw new Error(
            'A delegated capability in the delegation chain was delegated ' +
            'in the future.');
        }
        const currentTtl = currentCapabilityExpirationDate - currentDate;
        const maxTtl = currentCapabilityExpirationDate -
          currentCapabilityDelegationDate;
        if(currentTtl > maxDelegationTtl || maxTtl > maxDelegationTtl) {
          throw new Error(
            'A delegated capability in the delegation chain has a time to ' +
            'live that is too long.');
        }
      }

      parentAllowedAction = allowedAction;
      parentExpirationDate = currentCapabilityExpirationDate;
      parentDelegationDate = currentCapabilityDelegationDate;
      parentInvocationTarget = invocationTarget;
    }

    // shift zcap verify result for last zcap to the end of meta array if
    // necessary
    if(mustShift) {
      capabilityChainMeta.push(capabilityChainMeta.shift());
    }

    return {verified: true, verifiedParentCapability, capabilityChainMeta};
  } catch(error) {
    return {verified: false, error};
  }
};

api.checkProofContext = ({proof}) => {
  // zcap context can appear anywhere in the array as it *is* protected
  const {'@context': ctx} = proof;
  if(!((Array.isArray(ctx) && ctx.includes(ZCAP_CONTEXT_URL)) ||
    ctx === ZCAP_CONTEXT_URL)) {
    throw new Error(
      `Missing required capability proof context ("${ZCAP_CONTEXT_URL}").`);
  }
};

function _validateCapability({capability, expectRoot}) {
  const {
    '@context': context,
    id, parentCapability, invocationTarget, proof, allowedAction, expires
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
    if(!proof) {
      throw new Error('Delegated capability must have a "proof".');
    }
    // FIXME: require `expires` on delegated zcaps
    if(/*!expires || */ expires !== undefined && isNaN(Date.parse(expires))) {
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

function _hasValidAllowedAction({allowedAction, parentAllowedAction}) {
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

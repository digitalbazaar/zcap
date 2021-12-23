/*!
 * Copyright (c) 2018-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const jsigs = require('jsonld-signatures');
const jsonld = require('jsonld');
const {
  MAX_CHAIN_LENGTH, ZCAP_CONTEXT_URL, ZCAP_ROOT_PREFIX
} = require('./constants');

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
 * Retrieves the target from a capability.
 *
 * @param {object} capability - The authorization capability (zcap).
 */
api.getTarget = ({capability}) => {
  let {invocationTarget} = capability;
  if(invocationTarget && typeof invocationTarget === 'object') {
    invocationTarget = invocationTarget.id;
  } else if(typeof invocationTarget !== 'string') {
    invocationTarget = capability.id;
  }
  return invocationTarget;
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
  // capability is root, it has no relevant delegation proofs
  if(!capability.parentCapability) {
    return [];
  }
  return jsonld.getValues(capability, 'proof').filter(p => {
    return (p && p.proofPurpose === 'capabilityDelegation');
  });
};

/**
 * Gets the `capabilityChain` associated with the given capability.
 *
 * @param {object} capability - The authorization capability.
 *
 * @return {object} any `capabilityDelegation` proof objects attached to the
 *           given capability.
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
  for(const url of newChain) {
    if(!url.includes(':')) {
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
 * @property {Object[]} capabilityChainMeta - The results returned from
 *   jsonld-signatures verify for each capability in the chain.
 */

/**
 * The result of a capability chain inspection.
 * @typedef {object} InspectChainResult
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
 * @param {object} capability - The authorization capability (zcap) that the
 *   chain is for.
 * @param {array} dereferencedChain - The dereferenced capability chain for
 *   `capability`, starting at the root capability and ending at `capability`.
 * @param {object} [partialVerifyResult] - A partial result of verifying the
 *   capability delegation proof on `capability`; this must be passed when the
 *   capability's delegation proof has been partially verified and its
 *   purpose is presently being validated.
 * @param {function} [validateAgainstParent] - A function that must be passed
 *   the verified parent of the capability; this must be passed when the
 *   capability's delegation proof has been partially verified and its purpose
 *   is presently being validated.
 * @param {object} purposeParameters  - a set of options for validating the
 *   proof purpose.
 * @param {function} documentLoader - a configured jsonld documentLoader.
 * @param {function}
 *   [inspectCapabilityChain(CapabilityChainDetails):InspectResult] -
 *   An async function that can be used to check for revocations related to
 *   any of the capabilities. The expected return value is a Promise. See
 *   the documentation for CapabilityChainDetails and InspectChainResult above.
 * @param {object} expansionMap - a configured jsonld expansionMap.
 * @param [currentDate = new Date()] {Date} - The date used for comparison.
 *   when determining if a capability has expired.
 * @param [allowTargetAttenuation=false] {boolean} - Allow the
 *   invocationTarget of a delegation chain to be increasingly restrictive
 *   based on a hierarchical RESTful URL structure.
 * @param [requireChainDateMonotonicity=false] {boolean} - Require the
 *   created dates on delegation proofs to be monotonically increasing
 *   forward in time.
 * @param [maxDelegationTtl=Infinity] {number} - The maximum time to live
 *   for a delegated zcap (as measured by the time difference between
 *   `expires`, which MUST be present if `maxDelegationTtl !== Infinity`, and
 *   `created` on the delegation proof.
 *
 * @return {object} {verified, error, verifiedParentCapability}.
 */
api.verifyCapabilityChain = async ({
  capability, dereferencedChain, proofVerifyResult, validateAgainstParent,
  inspectCapabilityChain, purposeParameters,
  documentLoader, expansionMap, currentDate = new Date(),
  allowTargetAttenuation = false,
  requireChainDateMonotonicity = false, maxDelegationTtl = Infinity
}) => {
  /*  Note: We start verifying a capability from its root of trust (the
    beginning or head of the capability chain) as this approach limits an
    attacker's ability to waste our time and effort traversing from the tail
    to the head. To prevent recursively repeating checks, we pass a
    `verifiedParentCapability` in the `purposeParameters` each time we
    start verifying another capability in the capability chain.

    Verification process is:

    1. Ensure `capabilityAction` is allowed.
    2. Verify the root capability:
      2.1. Check the expected target, if one was specified.
      2.2. Ensure root capability is expected and has an invocation target.
    3. For each capability `cap` in the chain, verify the capability delegation
      proof on `cap` (using `proofVerifyResult` for `capability` if it was
      passed indicating it was already verified). This will validate everything
      else for `cap`.
  */

  // FIXME: ensure `expectedTarget` is checked for invocation checks, but it is
  // not required for delegation checks
  const {expectedTarget} = purposeParameters;
  let {expectedRootCapability} = purposeParameters;
  if(expectedRootCapability === undefined && expectedTarget !== undefined) {
    expectedRootCapability =
      `${ZCAP_ROOT_PREFIX}${encodeURIComponent(expectedTarget)}`;
  }

  try {
    // FIXME: require a `capabilityAction` to be specified
    // 1. Ensure `capabilityAction`, if given, is allowed; if the capability
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

    const isRoot = dereferencedChain.length === 1;
    const [root] = dereferencedChain;

    // FIXME: expected target may be different on root -- instead of requiring
    // `expectedTarget` to match the root, it should only have to match the
    // zcap invoked and then target attentuation rules should be applied to
    // ensure that the invoked zcap is permitted to have whatever target it
    // has

    // 2.1. Check the expected target.
    const target = api.getTarget({capability: root});
    // FIXME: determine if this check should happen here at all...
    if(expectedTarget !== undefined) {
      if(!((Array.isArray(expectedTarget) && expectedTarget.includes(target)) ||
        (typeof expectedTarget === 'string' && target === expectedTarget))) {
        throw new Error(
          `Expected target (${expectedTarget}) does not match ` +
          `root capability target (${target}).`);
      }
    }

    // 2.2. Ensure root capability is expected and has an invocation target.

    // run root capability checks (note that these will only be run once
    // because the `verifiedParentCapability` parameter stops recursion
    // from happening below)

    // FIXME: determine if `expectedCapability` is required for delegation
    // proof only checks...

    // ensure that the invocation target matches the root capability and
    // the root capability is as expected
    if(expectedRootCapability !== undefined) {
      if(!((Array.isArray(expectedRootCapability) &&
        expectedRootCapability.includes(root.id)) ||
        (typeof expectedRootCapability === 'string' &&
          root.id === expectedRootCapability))) {
        throw new Error(
          `Expected root capability (${expectedRootCapability}) does not ` +
          `match actual root capability (${root.id}).`);
      }
    }

    // root capability now verified
    let verifiedParentCapability = root;

    // if verifying a delegation proof and we're at the root, exit early
    if(isRoot) {
      return {verified: true, verifiedParentCapability};
    }

    // 3. For each capability `cap` in the chain, verify the capability
    //   delegation proof on `cap`. This will validate everything else for
    //   `cap`.
    // note that `verifiedParentCapability` will prevent repetitive checking
    // of the same segments of the chain (once a parent is verified, its chain
    // is not checked again when checking its children)
    const {suite, CapabilityDelegation} = purposeParameters;
    // get all delegated capabilities (no root zcap since it has no delegation
    // proof to check)
    const delegatedCapabilities = dereferencedChain.slice(1);
    const capabilityChainMeta = [];
    const lastIndex = delegatedCapabilities.length - 1;
    for(let i = 0; i < delegatedCapabilities.length; ++i) {
      const cap = delegatedCapabilities[i];
      let verifyResult;
      if(i === lastIndex && proofVerifyResult) {
        // finish validating purpose
        let purposeResult;
        try {
          purposeResult = await validateAgainstParent(
            {verifiedParentCapability});
        } catch(error) {
          purposeResult = {valid: false, error};
        }
        // build verify result
        verifyResult = {
          verified: purposeResult.valid,
          results: [{...proofVerifyResult, purposeResult}]
        };
        if(purposeResult.error) {
          verifyResult.error = purposeResult.error;
        }
      } else {
        verifyResult = await jsigs.verify(cap, {
          suite,
          purpose: new CapabilityDelegation({
            allowTargetAttenuation,
            expectedTarget,
            expectedRootCapability,
            capabilityAction,
            verifiedParentCapability
          }),
          documentLoader,
          expansionMap
        });
        if(!verifyResult.verified) {
          throw verifyResult.error;
        }
        if(i !== lastIndex) {
          verifiedParentCapability = cap;
        }
      }
      capabilityChainMeta.push({verifyResult});
    }

    // FIXME: combine lower loop with upper loop now that all zcaps are
    // always deref'd

    // ensure that the delegation chain does not expand the `allowedAction` of
    // the original delegation
    let parentAllowedAction;
    let parentDelegationDate;
    let parentExpirationDate;
    for(const c of delegatedCapabilities) {
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

      // get delegated date if necessary
      let currentCapabilityDelegationDate;
      const getDelegatedDate = requireChainDateMonotonicity ||
        maxDelegationTtl < Infinity;
      if(getDelegatedDate) {
        const proofs = api.getDelegationProofs({capability: c});
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

      if(requireChainDateMonotonicity) {
        // verify parent capability was not delegated after child
        if(parentDelegationDate !== undefined &&
          parentDelegationDate > currentCapabilityDelegationDate) {
          throw new Error(
            'A capability in the delegation chain was delegated before ' +
            'its parent.');
        }
      }

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
        if(c.expires === undefined) {
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

      parentAllowedAction = c.allowedAction;
      parentExpirationDate = currentCapabilityExpirationDate;
      parentDelegationDate = currentCapabilityDelegationDate;
    }

    if(inspectCapabilityChain) {
      const {valid, error} = await inspectCapabilityChain({
        // FIXME: why not include root zcap too?
        capabilityChain: delegatedCapabilities,
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
    '@context': context, id, parentCapability, invocationTarget, proof
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

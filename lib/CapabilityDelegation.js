/*!
 * Copyright (c) 2018-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const jsigs = require('jsonld-signatures');
const utils = require('./utils');
const {ControllerProofPurpose} = jsigs.purposes;

module.exports = class CapabilityDelegation extends ControllerProofPurpose {
  /**
   * @param {array} [capabilityChain] - An array of capabilities with the first
   *   entry representing the root capability and the last representing the
   *   parent of the capability to be delegated (only used when creating
   *   a proof, not validating one).
   * @param {string|Date|number} [date] - The expected date for
   *   the creation of the proof.
   * @param {object} [parentCapability] - An alternative to passing
   *   `capabilityChain` when creating a proof; passing `parentCapability` will
   *   enable the capability chain to be auto-computed.
   * @param {boolean} [allowTargetAttenuation=false] - Allow the
   *   invocationTarget of a delegation chain to be increasingly restrictive
   *   based on a hierarchical RESTful URL structure.
   * @param {string|array} [expectedRootCapability] - The expected root
   *   capability for the delegation chain (this can be a single root
   *   capability ID expressed as a string or, if there is more than one
   *   acceptable root capability, several root capability IDs in an array.
   * @param {object} [controller] - The description of the controller, if it
   *   is not to be dereferenced via a `documentLoader`.
   * @param {Date} [currentDate = new Date()] - The date used for comparison
   *   when determining if a capability has expired.
   * @param {InspectCapabilityChain} [inspectCapabilityChain] - An async
   *   function that can be used to check for revocations related to any of
   *   verified capabilities.
   * @param {number} [maxChainLength=10] - The maximum length of the capability
   *   delegation chain.
   * @param {number} [maxDelegationTtl=Infinity] - The maximum time to live
   *   for a delegated zcap (as measured by the time difference between
   *   `expires`, which MUST be present if `maxDelegationTtl !== Infinity`, and
   *   `created` on the delegation proof.
   * @param {number} [maxTimestampDelta] - a maximum number of seconds that
   *   the date on the signature can deviate from, defaults to `Infinity`.
   * @param {boolean} [requireChainDateMonotonicity=false] - Require the
   *   created dates on delegation proofs to be monotonically increasing
   *   forward in time.
   * @param {object|array} suite - the jsonld-signature suites to use to
   *   verify the capability chain.
   * @param {object} [verifiedParentCapability] - The previously verified
   *   parent capability, if any.
   */
  constructor({
    // proof creation params
    capabilityChain, date, parentCapability,
    // proof verification params
    allowTargetAttenuation = false,
    controller, currentDate,
    expectedRootCapability, inspectCapabilityChain,
    maxChainLength, maxDelegationTtl = Infinity, maxTimestampDelta = Infinity,
    requireChainDateMonotonicity = false,
    suite, verifiedParentCapability,
    _skipLocalValidationForTesting = false
  } = {}) {
    super({term: 'capabilityDelegation', controller, date, maxTimestampDelta});

    // parameters used to create a proof
    const hasCreateProofParams = capabilityChain || date || parentCapability;
    // params used to verify a proof
    const hasVerifyProofParams = controller ||
      currentDate || expectedRootCapability ||
      inspectCapabilityChain || suite || verifiedParentCapability;

    if(hasCreateProofParams && hasVerifyProofParams) {
      // cannot provide both create and verify params
      throw new Error(
        'Parameters for both creating and verifying a proof must not be ' +
        'provided together.');
    }

    // default to proof creation to cover case where neither create nor
    // verify params were provided
    if(!hasVerifyProofParams) {
      if(capabilityChain && !Array.isArray(capabilityChain)) {
        throw new TypeError('"capabilityChain" must be an array.');
      }
      if(parentCapability && !(typeof parentCapability === 'string' ||
        typeof parentCapability === 'object')) {
        throw new TypeError('"parentCapability" must be a string or object.');
      }
      if(!(capabilityChain || parentCapability)) {
        throw new Error(
          'Either "capabilityChain" or "parentCapability" is required ' +
          'to create a capability delegation proof.');
      }

      // FIXME: this can be removed if `parentCapability` is the only way
      // to specify a capability chain -- try to remove this optionality
      if(capabilityChain && !_skipLocalValidationForTesting) {
        // ensure that all capabilityChain entries except the last are strings
        const lastRequiredType = capabilityChain.length > 1 ?
          'object' : 'string';
        const lastIndex = capabilityChain.length - 1;
        for(const [i, entry] of capabilityChain.entries()) {
          const entryType = typeof entry;
          if(!((i === lastIndex && entryType === lastRequiredType) ||
            i !== lastIndex && entryType === 'string')) {
            throw new TypeError(
              'Capability chain is invalid; it must consist of strings ' +
              'of capability IDs except if the last capability is ' +
              'delegated, in which case it must be an object with an "id" ' +
              'property that is a string.');
          }
        }
      }

      this.capabilityChain = capabilityChain;
      this.parentCapability = parentCapability;
    } else {
      if(currentDate !== undefined && !(currentDate instanceof Date)) {
        throw new TypeError('"currentDate" must be a Date object.');
      }
      // FIXME: require `expectedRootCapability` but provide a helper to
      // auto-generate it? -- it may also be the case that when verifying
      // delegation chains only, the expected root isn't known ahead of time
      // ... in which case we may need to allow the check to be skipped?
      /*if(expectedRootCapability === undefined) {
        expectedRootCapability =
          `${ZCAP_ROOT_PREFIX}${encodeURIComponent(expectedTarget)}`;
      }*/
      if(!(typeof expectedRootCapability === 'string' ||
        Array.isArray(expectedRootCapability))) {
        throw new TypeError(
          '"expectedRootCapability" must be a string or array.');
      }

      // expected root capability values must be absolute URIs
      const expectedRootCapabilities = Array.isArray(expectedRootCapability) ?
        expectedRootCapability : [expectedRootCapability];
      for(const erc of expectedRootCapabilities) {
        if(!(typeof erc === 'string' && erc.includes(':'))) {
          throw new Error(
            '"expectedRootCapability" values must be absolute URI strings.');
        }
      }

      this.allowTargetAttenuation = allowTargetAttenuation;
      this.currentDate = currentDate || new Date();
      this.expectedRootCapability = expectedRootCapability;
      this.inspectCapabilityChain = inspectCapabilityChain;
      this.maxChainLength = maxChainLength;
      this.maxDelegationTtl = maxDelegationTtl;
      // FIXME: remove this option; always require chain date monotonicity
      this.requireChainDateMonotonicity = requireChainDateMonotonicity;
      this.suite = suite;
      this.verifiedParentCapability = verifiedParentCapability;
    }
  }

  async validate(
    proof, {document, verificationMethod, documentLoader, expansionMap}) {
    // ensure proof has expected context (even though this is called in
    // `match`, it is possible to call `validate` separately without calling
    // `match`, so check here too)
    utils.checkProofContext({proof});

    try {
      const {
        allowTargetAttenuation,
        currentDate,
        expectedRootCapability,
        inspectCapabilityChain,
        maxChainLength,
        maxDelegationTtl,
        requireChainDateMonotonicity,
        suite
      } = this;

      // FIXME: continue splitting validation/verification code into better
      // primitives until the below complex code path is no longer needed

      /* Note: In order to reduce time wasted by attackers that submit long
      zcap chains that are valid beyond the root (but not at the root because
      the attacker hasn't actually be delegated authority), we start chain
      verification at the root and move forward. This means that each parent
      zcap must be verified before a child is. This also means that we can't
      simplify recursively unwind the chain in reverse -- so the code is a bit
      more complex.

      This means that the verification process is:

      1. Verify the tail proof (which has already occurred before this function
        (`validate`) is called.
      2. Verify the chain from root => tail by calling `verifyCapabilityChain`
        just once -- when validating the tail. To ensure we don't call it more
        than once, we use `verifiedParentCapability` as a guard; if the parent
        capability has been verified, we don't call it, presuming that we are
        presently inside of a call to `verifyCapabilityChain` initiated by
        validating the tail as mentioned.
      3. Create a function (`validateAgainstParent`) for running all
        parent-dependent validation checks that can be called (for the tail)
        from within `verifyCapabilityChain` once its parent has been verified.
        This prevents other hooks such as `inspectCapabilityChain` from running
        unless the whole chain is verified. This function will cache the result
        of those checks so that it can be called again once the chain has been
        verified to return the proper result from this function (`validate`).
        In the event that the current code is running on a zcap other than the
        tail, it will run just once below since it `verifyCapabilityChain` will
        not be called. */

      // `validateResult` to be cached and reference to super's `validate` so
      // it can be called from `validateAgainstParent` below
      let validateResult;
      const superValidate = super.validate.bind(this);

      // see if the parent capability has already been verified
      let {verifiedParentCapability} = this;
      if(!verifiedParentCapability) {
        // parent capability not yet verified, so verify delegation chain
        // and only then build verify result for `capability`
        const verifyResult = {};
        const capabilityChainMeta = [{verifyResult}];

        // `proof` must be reattached to the capability because it contains
        // a `capabilityChain` property that must be validated.
        const capabilityWithProof = {...document, proof};

        const {dereferencedChain} = await utils.dereferenceCapabilityChain({
          capability: capabilityWithProof,
          // FIXME: allow custom `getRootCapability`
          async getRootCapability({id}) {
            const {document} = await documentLoader(id);
            return {rootCapability: document};
          },
          maxChainLength
        });

        /* Note: Here we produce a partial verification result for the proof
        that has already been verified (modulo the purpose validation is that
        presently running in this function). By passing this, it provides the
        verification result information needed by `verifyCapabilityChain` to
        avoid having to re-verify `capability` internally. It will still need
        to complete purpose validation, but it will do this by calling
        `validateAgainstParent` once the parent of capability has been
        verified. Also note that `validate` is only called on a proof purpose
        if the proof was verified so we can set that `true` here. */
        const partialVerifyResult = {proof, verified: true, verificationMethod};

        // FIXME: this is complicated because `verifyCapabilityChain` calls
        // `inspectCapabilityChain` which needs the verify results -- if this
        // can be decoupled, we can call it separately

        const result = await utils.verifyCapabilityChain({
          CapabilityDelegation,
          allowTargetAttenuation,
          capabilityChainMeta,
          currentDate,
          dereferencedChain,
          documentLoader,
          expansionMap,
          expectedRootCapability,
          maxDelegationTtl,
          requireChainDateMonotonicity,
          suite
        });
        if(!result.verified) {
          throw result.error;
        }
        ({verifiedParentCapability} = result);

        // FIXME: can this be called before `verifyCapabilityChain`? if we had
        // a separate primitive that got the fully dereferenced chain it seems
        // it could be -- if that can be split out from `verifyCapabilityChain`
        // and then require the dereferenced chain to be passed into it, then
        // that could work?
        const purposeResult = await validateAgainstParent(
          {verifiedParentCapability});

        // FIXME: try to move code from inside `verifyCapabilityChain` out
        // here, then call `inspectCapabilityChain`

        // build verify result
        verifyResult.verified = purposeResult.valid;
        verifyResult.results = [{...partialVerifyResult, purposeResult}];

        // run `inspectCapabilityChain` hook
        if(inspectCapabilityChain) {
          const {valid, error} = await inspectCapabilityChain({
            // FIXME: why not include root zcap too?
            capabilityChain: dereferencedChain.slice(1),
            capabilityChainMeta
          });
          if(!valid) {
            throw error;
          }
        }

        return purposeResult;
      }

      return await validateAgainstParent({verifiedParentCapability});

      async function validateAgainstParent() {
        // if `validateAgainstParent` was already called within
        // `verifyCapabilityChain`, its return value will have been cached
        // and we just return it here
        if(validateResult) {
          return validateResult;
        }

        // ensure proof created by authorized delegator...
        // parent zcap controller must match the delegating verification method
        // (or its controller)
        if(!utils.isController(
          {capability: verifiedParentCapability, verificationMethod})) {
          throw new Error(
            'The capability controller does not match the verification ' +
            'method (or its controller) used to delegate.');
        }

        // check verification method controller
        validateResult = await superValidate(proof, {
          documentLoader, verificationMethod, expansionMap});
        if(!validateResult.valid) {
          throw validateResult.error;
        }

        // the controller of the proof is the delegator of the capability
        validateResult.delegator = validateResult.controller;
        delete validateResult.controller;

        // `validateResult` includes meta data about the proof controller
        return validateResult;
      }
    } catch(error) {
      return {valid: false, error};
    }
  }

  async update(proof/*, {document, documentLoader, expansionMap}*/) {
    // FIXME: can we remove the optionality and always compute the chain
    // instead?
    let {capabilityChain} = this;

    // no capability chain given, attempt to compute from parent
    if(!capabilityChain) {
      const {parentCapability} = this;
      // FIXME: determine if capability needs to be validated at this point
      capabilityChain = utils.computeCapabilityChain({parentCapability});
    }

    proof.proofPurpose = 'capabilityDelegation';
    proof.capabilityChain = capabilityChain;
    return proof;
  }

  async match(proof, {document, documentLoader, expansionMap}) {
    try {
      // check the `proof` context before using its terms
      utils.checkProofContext({proof});
    } catch(e) {
      // context does not match, so proof does not match
      return false;
    }

    return super.match(proof, {document, documentLoader, expansionMap});
  }
};

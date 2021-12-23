/*!
 * Copyright (c) 2018-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const jsigs = require('jsonld-signatures');
const utils = require('./utils');
const {ControllerProofPurpose} = jsigs.purposes;

module.exports = class CapabilityDelegation extends ControllerProofPurpose {
  /**
   * @param [capabilityChain] {array} - An array of capabilities with the first
   *   entry representing the root capability and the last representing the
   *   parent of the capability to be delegated (only used when creating
   *   a proof, not validating one).
   * @param [parentCapability] {object} An alternative to passing
   *   `capabilityChain` when creating a proof; passing `parentCapability` will
   *   enable the capability chain to be auto-computed.
   * @param [verifiedParentCapability] the previously verified parent
   *   capability, if any.
   * @param [expectedTarget] {string} the target we expect a capability to
   *   apply to (URI).
   * @param [expectedRootCapability] {string} the expected root capability
   *   for the `expectedTarget`, should it be different; in cases where an
   *   object can express its authority it will be the root capability and
   *   the `expectedTarget` should match this object's ID, however, when
   *   an object cannot express its own authority another object can act
   *   as its authority if the verifier specifies it via this property.
   * @param [capability] {string or object} the capability that is to be
   *   added/referenced in a created proof.
   * @param [capabilityAction] {string} the capability action that is
   *   to be added to a proof or is expected when validating a proof.
   * @param {Object or Array} suite - the jsonld-signature suites to use to
   *   verify the capability chain.
   * @param [controller] {object} the description of the controller, if it
   *   is not to be dereferenced via a `documentLoader`.
   * @param [date] {string or Date or integer} the expected date for
   *   the creation of the proof.
   * @param [maxTimestampDelta] {integer} a maximum number of seconds that
   *   the date on the signature can deviate from, defaults to `Infinity`.
   * @param {function} [inspectCapabilityChain] - See documentation for
   *   `utils.verifyCapabilityChain`.
   * @param [currentDate = new Date()] {Date} - The date used for comparison
   *   when determining if a capability has expired.
   * @param [maxChainLength=10] - The maximum length of the capability
   *   delegation chain.
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
   */
  constructor({
    capabilityChain, parentCapability, verifiedParentCapability,
    expectedTarget, expectedRootCapability, inspectCapabilityChain,
    capability, capabilityAction, suite, currentDate, maxChainLength,
    controller, date, maxTimestampDelta = Infinity,
    allowTargetAttenuation = false, requireChainDateMonotonicity = false,
    maxDelegationTtl = Infinity, _skipLocalValidationForTesting = false
  } = {}) {
    super({term: 'capabilityDelegation', controller, date, maxTimestampDelta});

    if(capabilityChain && !_skipLocalValidationForTesting) {
      if(!Array.isArray(capabilityChain)) {
        throw new TypeError('"capabilityChain" must be an array.');
      }
      // ensure that all capabilityChain entries except the last are strings
      const lastRequiredType = capabilityChain.length > 1 ? 'object' : 'string';
      const lastIndex = capabilityChain.length - 1;
      for(const [i, entry] of capabilityChain.entries()) {
        const entryType = typeof entry;
        if(!((i === lastIndex && entryType === lastRequiredType) ||
          i !== lastIndex && entryType === 'string')) {
          throw new TypeError(
            'Capability chain is invalid; it must consist of strings ' +
            'of capability IDs except if the last capability is delegated, ' +
            'in which case it must be an object with an "id" property that ' +
            'is a string.');
        }
      }
    }

    this.capabilityChain = capabilityChain;
    this.parentCapability = parentCapability;
    this.verifiedParentCapability = verifiedParentCapability;
    this.expectedTarget = expectedTarget;
    this.expectedRootCapability = expectedRootCapability;
    this.capability = capability;
    this.capabilityAction = capabilityAction;
    this.inspectCapabilityChain = inspectCapabilityChain;
    this.maxChainLength = maxChainLength;
    this.allowTargetAttenuation = allowTargetAttenuation;
    this.requireChainDateMonotonicity = requireChainDateMonotonicity;
    this.maxDelegationTtl = maxDelegationTtl;
    this.suite = suite;

    if(currentDate !== undefined && !(currentDate instanceof Date)) {
      throw new TypeError('"currentDate" must be a Date object.');
    }
    this.currentDate = currentDate || new Date();
  }

  async validate(
    proof, {document, verificationMethod, documentLoader, expansionMap}) {
    try {
      const {
        allowTargetAttenuation,
        capability,
        capabilityAction,
        capabilityChain,
        expectedRootCapability,
        expectedTarget,
        currentDate,
        inspectCapabilityChain,
        maxChainLength,
        maxDelegationTtl,
        requireChainDateMonotonicity,
        suite
      } = this;

      const purposeParameters = {
        capabilityChain, expectedTarget, expectedRootCapability, capability,
        capabilityAction, CapabilityDelegation, suite
      };

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

        const result = await utils.verifyCapabilityChain({
          allowTargetAttenuation,
          capability: capabilityWithProof,
          dereferencedChain,
          partialVerifyResult,
          validateAgainstParent,
          currentDate,
          documentLoader,
          expansionMap,
          inspectCapabilityChain,
          purposeParameters,
          requireChainDateMonotonicity,
          maxDelegationTtl
        });
        if(!result.verified) {
          throw result.error;
        }
        ({verifiedParentCapability} = result);
      }

      // FIXME: can this be called before `verifyCapabilityChain`? if we had
      // a separate primitive that got the fully dereferenced chain it seems
      // it could be -- if that can be split out from `verifyCapabilityChain`
      // and then require the dereferenced chain to be passed into it, then
      // that could work?
      return await validateAgainstParent({verifiedParentCapability});

      async function validateAgainstParent() {
        // if `validateAgainstParent` was already called within
        // `verifyCapabilityChain`, its return value will have been cached
        // and we just return it here
        if(validateResult) {
          return validateResult;
        }

        // ensure parent capability matches
        if(document.parentCapability !== verifiedParentCapability.id) {
          throw new Error('"parentCapability" does not match.');
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

        // make sure invocationTarget is valid
        const target = utils.getTarget({capability: document});
        const parentTarget = utils.getTarget({
          capability: verifiedParentCapability
        });

        if(allowTargetAttenuation) {
          if(!(parentTarget === target ||
            target.startsWith(`${parentTarget}/`))) {
            throw new Error('The "invocationTarget" in a delegated ' +
              'capability must be equivalent or more restrictive than ' +
              'its parent.');
          }
        } else if(parentTarget !== target) {
          throw new Error('The "invocationTarget" in a delegated capability ' +
            'must be equivalent to its parent.');
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
    let {capabilityChain} = this;
    // FIXME: can we remove the optionality and always compute the chain
    // instead?
    if(capabilityChain && !Array.isArray(capabilityChain)) {
      throw new TypeError('"capabilityChain" must be an array.');
    }

    // no capability chain given, attempt to compute from parent
    if(!capabilityChain) {
      const {parentCapability} = this;
      if(!parentCapability) {
        throw new Error(
          'Cannot compute capability chain; no "parentCapability" passed.');
      }
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

/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const CapabilityDelegation = require('./CapabilityDelegation');
const CapabilityProofPurpose = require('./CapabilityProofPurpose');
const utils = require('./utils');

module.exports = class CapabilityInvocation extends CapabilityProofPurpose {
  /**
   * @param {string|object} [capability] - The capability that is to be
   *   added/referenced in a created proof (a root zcap MUST be passed as
   *   a string and a delegated zcap as an object).
   * @param {string} [capabilityAction] - The capability action that is
   *   to be added to a proof.
   * @param {string} [invocationTarget] - The invocation target to use; this
   *   is required and can be used to attenuate the capability's invocation
   *   target if the verifier supports target attentuation.
   * @param {boolean} [allowTargetAttenuation=false] - Allow the
   *   invocationTarget of a delegation chain to be increasingly restrictive
   *   based on a hierarchical RESTful URL structure.
   * @param {object} [controller] - The description of the controller, if it
   *   is not to be dereferenced via a `documentLoader`.
   * @param {string|Date|number} [date] - Used during proof verification as the
   *   expected date for the creation of the proof (within a maximum timestamp
   *   delta) and for checking to see if a capability has expired; if not
   *   passed the current date will be used.
   * @param {string} [expectedAction] - the capability action that is expected
   *   when validating a proof.
   * @param {string|array} [expectedRootCapability] - The expected root
   *   capability for the delegation chain (this can be a single root
   *   capability ID expressed as a string or, if there is more than one
   *   acceptable root capability, several root capability IDs in an array.
   * @param {string} [expectedTarget] - The target we expect a capability to
   *   apply to (URI).
   * @param {InspectCapabilityChain} [inspectCapabilityChain] - An async
   *   function that can be used to check for revocations related to any of
   *   verified capabilities.
   * @param {number} [maxChainLength=10] - The maximum length of the capability
   *   delegation chain.
   * @param {number} [maxClockSkew=300] - A maximum number of seconds that
   *   clocks may be skewed when comparing dates, e.g., to ensure monotonicity
   *   in "created" dates in the capability delegation chain.
   * @param {number} [maxDelegationTtl=Infinity] - The maximum milliseconds to
   *   live for a delegated zcap as measured by the time difference between
   *   `expires` and `created` on the delegation proof.
   * @param {number} [maxTimestampDelta=Infinity] - A maximum number of seconds
   *   that "created" date on the capability invocation proof can deviate from
   *   `date`, defaults to `Infinity`.
   * @param {object|array} suite - The jsonld-signature suite(s) to use to
   *   verify the capability chain.
   */
  constructor({
    // proof creation params
    capability, capabilityAction, invocationTarget,
    // proof verification params
    allowTargetAttenuation, controller, date,
    expectedAction, expectedRootCapability, expectedTarget,
    inspectCapabilityChain,
    maxChainLength,
    maxClockSkew,
    maxDelegationTtl,
    maxTimestampDelta,
    suite
  } = {}) {
    // parameters used to create a proof
    const hasCreateProofParams = capability || capabilityAction ||
      invocationTarget;
    // params used to verify a proof
    const hasVerifyProofParams = controller || date ||
      expectedAction || expectedRootCapability || expectedTarget ||
      inspectCapabilityChain || suite;

    if(hasCreateProofParams && hasVerifyProofParams) {
      // cannot provide both create and verify params
      throw new Error(
        'Parameters for both creating and verifying a proof must not be ' +
        'provided together.');
    }

    super({
      allowTargetAttenuation,
      controller, date,
      expectedRootCapability, inspectCapabilityChain,
      maxChainLength, maxClockSkew, maxDelegationTtl, maxTimestampDelta,
      suite,
      term: 'capabilityInvocation'
    });

    // validate `CapabilityInvocation` specific params, the base class will
    // have already handled validating common ones...

    // use negative conditional to cover case where neither create nor
    // verify params were provided and default to proof creation case to
    // avoid creating bad proofs
    if(!hasVerifyProofParams) {
      if(typeof capability === 'object') {
        // root capabilities MUST be passed as strings
        if(!(capability && capability.parentCapability)) {
          throw new Error(
            '"capability" must be a string if it is a root capability.');
        }
      } else if(typeof capability !== 'string') {
        throw new TypeError('"capability" must be a string or object.');
      }
      if(typeof capabilityAction !== 'string') {
        throw new TypeError('"capabilityAction" must be a string.');
      }
      if(typeof invocationTarget !== 'string') {
        throw new TypeError('"invocationTarget" must be a string.');
      }

      this.capability = capability;
      this.capabilityAction = capabilityAction;
      this.invocationTarget = invocationTarget;
    } else {
      if(typeof expectedAction !== 'string') {
        throw new TypeError('"expectedAction" must be a string.');
      }
      if(!(typeof expectedTarget === 'string' ||
        Array.isArray(expectedTarget))) {
        throw new TypeError('"expectedTarget" must be a string or array.');
      }
      // expected target values must be absolute URIs
      const expectedTargets = Array.isArray(expectedTarget) ?
        expectedTarget : [expectedTarget];
      for(const et of expectedTargets) {
        if(!(typeof et === 'string' && et.includes(':'))) {
          throw new Error(
            '"expectedTargets" values must be absolute URI strings.');
        }
      }

      this.expectedTarget = expectedTarget;
      this.expectedAction = expectedAction;
    }
  }

  async update(proof) {
    const {capability, capabilityAction, invocationTarget} = this;
    proof.proofPurpose = this.term;
    proof.capability = capability;
    proof.invocationTarget = invocationTarget;
    proof.capabilityAction = capabilityAction;
    return proof;
  }

  async match(proof, {document, documentLoader, expansionMap}) {
    const {expectedAction, expectedTarget} = this;

    try {
      // check the `proof` context before using its terms
      utils.checkProofContext({proof});
    } catch(e) {
      // context does not match, so proof does not match
      return false;
    }

    if(!proof.capability) {
      // capability not in the proof, not a match
      return false;
    }

    // ensure basic purpose and expected action match the proof
    if(!(await super.match(proof, {document, documentLoader, expansionMap}) &&
      (expectedAction === proof.capabilityAction))) {
      return false;
    }

    // ensure the proof's declared invocation target matches an expected one
    if(Array.isArray(expectedTarget)) {
      return expectedTarget.includes(proof.invocationTarget);
    }
    return expectedTarget === proof.invocationTarget;
  }

  _getCapabilityDelegationClass() {
    return CapabilityDelegation;
  }

  _getTailCapability({proof}) {
    return {capability: proof.capability};
  }

  async _runChecksBeforeChainVerification({dereferencedChain, proof}) {
    const {
      allowTargetAttenuation,
      expectedAction,
      expectedTarget
    } = this;

    /* 1. Ensure that `capabilityAction` is an allowed action and that
    it matches `expectedAction`. Note that if it doesn't match and `match`
    was called to gate calling `validate`, then this code will not execute.
    However, if `validate` is called directly, this check MUST run here.

    If the capability restricts the actions via `allowedAction` then
    `capabilityAction` must be in its set. */
    const capability = dereferencedChain[dereferencedChain.length - 1];
    const {capabilityAction} = proof;
    const allowedActions = utils.getAllowedActions({capability});
    if(allowedActions.length > 0 &&
      !allowedActions.includes(capabilityAction)) {
      throw new Error(
        `Capability action "${capabilityAction}" is not allowed by the ` +
        'capability; allowed actions are: ' +
        allowedActions.map(x => `"${x}"`).join(', '));
    }
    if(capabilityAction !== expectedAction) {
      throw new Error(
        `Capability action "${capabilityAction}" does not match the ` +
        `expected action of "${expectedAction}".`);
    }

    /* 2. Ensure `expectedTarget` is as expected. The invocation target
    will also be checked to ensure it hasn't changed from previous zcaps
    in the chain (unless attenuation is permitted) later. */

    /* 3. Verify the invocation target in the proof is as expected. The
    `invocationTarget` specified in the capability invocation proof must
    match exactly (or follow acceptable target attenuation rules) the
    `invocationTarget` specified in the invoked capability. */
    const capabilityTarget = utils.getTarget({capability});
    const {invocationTarget} = proof;
    if(!utils.isValidTarget({
      invocationTarget,
      baseInvocationTarget: capabilityTarget,
      allowTargetAttenuation
    })) {
      throw new Error(
        `Invocation target (${invocationTarget}) does not match ` +
        `capability target (${capabilityTarget}).`);
    }

    /* 4. Verify the invocation target is an expected target. Prior to this
    step we ensured that the invocation target used matched th capability
    that was invoked, but this check ensures that the invocation target used
    matches the endpoint (the `expectedTarget`) where the capability was
    actually invoked. */
    if(!((Array.isArray(expectedTarget) &&
      expectedTarget.includes(invocationTarget)) ||
      (typeof expectedTarget === 'string' &&
      invocationTarget === expectedTarget))) {
      throw new Error(
        `Expected target (${expectedTarget}) does not match ` +
        `invocation target (${invocationTarget}).`);
    }

    /* 5. If capability is delegated (not root), then ensure the capability
    invocation proof `created` date is not before the capability delegation
    proof creation date. */
    if(capability.parentCapability) {
      const invoked = Date.parse(proof.created);
      const [delegationProof] = utils.getDelegationProofs({capability});
      // FIXME: apply `clockSkew`
      const delegated = Date.parse(delegationProof.created);
      if(invoked < delegated) {
        throw new Error(
          'A delegated capability must not be invoked before the "created" ' +
          'date in its delegation proof.');
      }
    }

    // return no capability delegation verify results yet; the tail's
    // capability delegation proof must be verified via
    // `_verifyCapabilityChain`
    return {capabilityChainMeta: []};
  }

  async _runChecksAfterChainVerification({
    dereferencedChain, proof, validateOptions
  }) {
    /* Verify the controller of the capability. The zcap controller must
    match the invoking verification method (or its controller). */
    const capability = dereferencedChain[dereferencedChain.length - 1];
    const {verificationMethod} = validateOptions;
    if(!utils.isController({capability, verificationMethod})) {
      throw new Error(
        'The capability controller does not match the verification method ' +
        '(or its controller) used to invoke.');
    }

    // run base level validation checks
    const result = await this._runBaseProofValidation({proof, validateOptions});
    if(!result.valid) {
      throw result.error;
    }

    // the controller of the verification method from the proof is the
    // invoker of the capability
    result.invoker = result.controller;

    return result;
  }
};

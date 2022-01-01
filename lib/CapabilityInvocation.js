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
   * @param {string|Date|number} [date] - The expected date for the creation of
   *   the proof.
   * @param {boolean} [allowTargetAttenuation=false] - Allow the
   *   invocationTarget of a delegation chain to be increasingly restrictive
   *   based on a hierarchical RESTful URL structure.
   * @param {object} [controller] - The description of the controller, if it
   *   is not to be dereferenced via a `documentLoader`.
   * @param {Date} [currentDate = new Date()] - The date used for comparison
   *   when determining if a capability has expired.
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
   * @param {number} [maxDelegationTtl=Infinity] - The maximum time to live
   *   for a delegated zcap (as measured by the time difference between
   *   `expires`, which MUST be present if `maxDelegationTtl !== Infinity`, and
   *   `created` on the delegation proof.
   * @param {number} [maxTimestampDelta] - A maximum number of seconds that
   *   the date on the signature can deviate from, defaults to `Infinity`.
   * @param {boolean} [requireChainDateMonotonicity=false] - Require the
   *   created dates on delegation proofs to be monotonically increasing
   *   forward in time.
   * @param {object|array} suite - The jsonld-signature suite(s) to use to
   *   verify the capability chain.
   */
  constructor({
    // proof creation params
    capability, capabilityAction, date, invocationTarget,
    // proof verification params
    allowTargetAttenuation = false, controller, currentDate,
    expectedAction, expectedRootCapability, expectedTarget,
    inspectCapabilityChain,
    maxChainLength,
    maxDelegationTtl = Infinity,
    maxTimestampDelta = Infinity,
    requireChainDateMonotonicity = false,
    suite
  } = {}) {
    // parameters used to create a proof
    const hasCreateProofParams = capability || capabilityAction ||
      date || invocationTarget;
    // params used to verify a proof
    const hasVerifyProofParams = controller || currentDate ||
      expectedAction || expectedRootCapability || expectedTarget ||
      inspectCapabilityChain || suite;

    if(hasCreateProofParams && hasVerifyProofParams) {
      // cannot provide both create and verify params
      throw new Error(
        'Parameters for both creating and verifying a proof must not be ' +
        'provided together.');
    }

    super({
      date,
      allowTargetAttenuation, controller, currentDate,
      expectedRootCapability,
      inspectCapabilityChain,
      maxChainLength,
      maxDelegationTtl,
      maxTimestampDelta,
      requireChainDateMonotonicity,
      suite, term: 'capabilityInvocation'
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

  // FIXME: let parent do all the work

  // async validate(proof, {verificationMethod, documentLoader, expansionMap}) {
  //   try {
  //     // ensure proof has expected context (even though this is called in
  //     // `match`, it is possible to call `validate` separately without calling
  //     // `match`, so check here too)
  //     utils.checkProofContext({proof});

  //     const {
  //       allowTargetAttenuation,
  //       currentDate,
  //       expectedAction,
  //       expectedRootCapability,
  //       expectedTarget,
  //       inspectCapabilityChain,
  //       maxChainLength,
  //       maxDelegationTtl,
  //       requireChainDateMonotonicity,
  //       suite
  //     } = this;

  //     /* 1. Dereference the capability chain. This involves finding all
  //     embedded delegated zcaps, using a verifier-trusted hook to dereference
  //     the root zcap, and putting the full zcaps in order (root => tail) in an
  //     array. The `tail` is the zcap that was invoked. */
  //     let {capability} = proof;
  //     const {dereferencedChain} = await utils.dereferenceCapabilityChain({
  //       capability,
  //       // FIXME: allow custom `getRootCapability`
  //       async getRootCapability({id}) {
  //         const {document} = await documentLoader(id);
  //         return {rootCapability: document};
  //       },
  //       maxChainLength
  //     });
  //     // update root capability to dereferenced root zcap
  //     if(typeof capability === 'string') {
  //       ([capability] = dereferencedChain);
  //     }

  //     /* 2. Ensure that `capabilityAction` is an allowed action and that
  //     it matches `expectedAction`. Note that if it doesn't match and `match`
  //     was called to gate calling `validate`, then this code will not execute.
  //     However, if `validate` is called directly, this check MUST run here.

  //     If the capability restricts the actions via `allowedAction` then
  //     `capabilityAction` must be in its set. */
  //     const {capabilityAction} = proof;
  //     const allowedActions = utils.getAllowedActions({capability});
  //     if(allowedActions.length > 0 &&
  //       !allowedActions.includes(capabilityAction)) {
  //       throw new Error(
  //         `Capability action "${capabilityAction}" is not allowed by the ` +
  //         'capability; allowed actions are: ' +
  //         allowedActions.map(x => `"${x}"`).join(', '));
  //     }
  //     if(capabilityAction !== expectedAction) {
  //       throw new Error(
  //         `Capability action "${capabilityAction}" does not match the ` +
  //         `expected action of "${expectedAction}".`);
  //     }

  //     /* 3. Ensure `expectedTarget` is as expected. The invocation target
  //     will also be checked to ensure it hasn't changed from previous zcaps
  //     in the chain (unless attenuation is permitted) later. */

  //     /* 4. Verify the invocation target in the proof is as expected. The
  //     `invocationTarget` specified in the capability invocation proof must
  //     match exactly (or follow acceptable target attenuation rules) the
  //     `invocationTarget` specified in the invoked capability. */
  //     const capabilityTarget = utils.getTarget({capability});
  //     // FIXME: this must be simplified to require `invocationTarget` in the
  //     // proof instead of defaulting it to the value in the capability
  //     const {invocationTarget = capabilityTarget} = proof;
  //     if(!utils.isValidTarget({
  //       invocationTarget,
  //       baseInvocationTarget: capabilityTarget,
  //       allowTargetAttenuation
  //     })) {
  //       throw new Error(
  //         `Invocation target (${invocationTarget}) does not match ` +
  //         `capability target (${capabilityTarget}).`);
  //     }

  //     /* 5. Verify the invocation target is an expected target. Prior to this
  //     step we ensured that the invocation target used matched th capability
  //     that was invoked, but this check ensures that the invocation target used
  //     matches the endpoint (the `expectedTarget`) where the capability was
  //     actually invoked. */
  //     if(!((Array.isArray(expectedTarget) &&
  //       expectedTarget.includes(invocationTarget)) ||
  //       (typeof expectedTarget === 'string' &&
  //       invocationTarget === expectedTarget))) {
  //       throw new Error(
  //         `Expected target (${expectedTarget}) does not match ` +
  //         `invocation target (${invocationTarget}).`);
  //     }

  //     /* 6. Verify the capability delegation chain. This will make sure that
  //     the root zcap in the chain is as expected (for the endpoint where the
  //     invocation occurred) and that every other zcap in the chain (including
  //     the invoked one), has been properly delegated. */
  //     const {
  //       verified, error, capabilityChainMeta
  //     } = await utils.verifyCapabilityChain({
  //       CapabilityDelegation,
  //       allowTargetAttenuation,
  //       currentDate,
  //       dereferencedChain,
  //       documentLoader,
  //       expectedRootCapability,
  //       expansionMap,
  //       inspectCapabilityChain,
  //       maxDelegationTtl,
  //       requireChainDateMonotonicity,
  //       suite
  //     });
  //     if(!verified) {
  //       throw error;
  //     }

  //     /* 7. Verify the controller of the capability. The zcap controller must
  //     match the invoking verification method (or its controller). */
  //     if(!utils.isController({capability, verificationMethod})) {
  //       throw new Error(
  //         'The capability controller does not match the verification method ' +
  //         '(or its controller) used to invoke.');
  //     }

  //     const validateResult = await super.validate(proof, {
  //       documentLoader, verificationMethod, expansionMap});

  //     if(!validateResult.valid) {
  //       throw validateResult.error;
  //     }

  //     // the controller of the verification method from the proof is the
  //     // invoker of the capability
  //     validateResult.invoker = validateResult.controller;

  //     // run `inspectCapabilityChain` hook
  //     if(inspectCapabilityChain) {
  //       const {valid, error} = await inspectCapabilityChain({
  //         // FIXME: why not include root zcap too?
  //         capabilityChain: dereferencedChain.slice(1),
  //         capabilityChainMeta
  //       });
  //       if(!valid) {
  //         throw error;
  //       }
  //     }

  //     // check verification method controller
  //     return validateResult;
  //   } catch(error) {
  //     return {valid: false, error};
  //   }
  // }

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
    // FIXME: this must be simplified to require `invocationTarget` in the
    // proof instead of defaulting it to the value in the capability
    const {invocationTarget = capabilityTarget} = proof;
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

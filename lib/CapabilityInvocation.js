/*!
 * Copyright (c) 2018-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const jsigs = require('jsonld-signatures');
const utils = require('./utils');
const CapabilityDelegation = require('./CapabilityDelegation');
const {ControllerProofPurpose} = jsigs.purposes;

// TODO: consider making a common base class for this class and
// `CapabilityDelegation` instead of using `utils`

module.exports = class CapabilityInvocation extends ControllerProofPurpose {
  /**
   * @param [capability] {string|object} the capability that is to be
   *   added/referenced in a created proof (a root zcap MUST be passed as
   *   a string and a delegated zcap as an object).
   * @param [capabilityAction] {string} the capability action that is
   *   to be added to a proof.
   * @param [invocationTarget] {string} the invocation target to use; this
   *   is required and can be used to attenuate the capability's invocation
   *   target if the verifier supports target attentuation.
   * @param [date] {string|Date|number} the expected date for
   *   the creation of the proof.
   * @param [allowTargetAttenuation=false] {boolean} - Allow the
   *   invocationTarget of a delegation chain to be increasingly restrictive
   *   based on a hierarchical RESTful URL structure.
   * @param [controller] {object} the description of the controller, if it
   *   is not to be dereferenced via a `documentLoader`.
   * @param [currentDate = new Date()] {Date} - The date used for comparison
   *   when determining if a capability has expired.
   * @param [expectedAction] {string} the capability action that is expected
   *   when validating a proof.
   * @param [expectedRootCapability] {string} the expected root capability
   *   for the `expectedTarget`, should it be different; in cases where an
   *   object can express its authority it will be the root capability and
   *   the `expectedTarget` should match this object's ID, however, when
   *   an object cannot express its own authority another object can act
   *   as its authority if the verifier specifies it via this property.
   * @param [expectedTarget] {string} the target we expect a capability to
   *   apply to (URI).
   * @param {function} [inspectCapabilityChain] -  See documentation for
   *   `utils.verifyCapabilityChain`.
   * @param [maxChainLength=10] - The maximum length of the capability
   *   delegation chain.
   * @param [maxDelegationTtl=Infinity] {number} - The maximum time to live
   *   for a delegated zcap (as measured by the time difference between
   *   `expires`, which MUST be present if `maxDelegationTtl !== Infinity`, and
   *   `created` on the delegation proof.
   * @param [maxTimestampDelta] {number} a maximum number of seconds that
   *   the date on the signature can deviate from, defaults to `Infinity`.
   * @param [requireChainDateMonotonicity=false] {boolean} - Require the
   *   created dates on delegation proofs to be monotonically increasing
   *   forward in time.
   * @param {object|array} suite - the jsonld-signature suites to use to
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
    super({term: 'capabilityInvocation', controller, date, maxTimestampDelta});

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

    // default to proof creation to cover case where neither create nor
    // verify params were provided
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
      if(currentDate !== undefined && !(currentDate instanceof Date)) {
        throw new TypeError('"currentDate" must be a Date object.');
      }
      if(typeof expectedAction !== 'string') {
        throw new TypeError('"expectedAction" must be a string.');
      }
      if(!(typeof expectedTarget === 'string' ||
        Array.isArray(expectedTarget))) {
        throw new TypeError('"expectedTarget" must be a string or array.');
      }

      this.allowTargetAttenuation = allowTargetAttenuation;
      this.currentDate = currentDate || new Date();
      this.expectedTarget = expectedTarget;
      this.expectedRootCapability = expectedRootCapability;
      this.expectedAction = expectedAction;
      this.inspectCapabilityChain = inspectCapabilityChain;
      this.maxChainLength = maxChainLength;
      this.maxDelegationTtl = maxDelegationTtl;
      this.requireChainDateMonotonicity = requireChainDateMonotonicity;
      this.suite = suite;
    }
  }

  async validate(proof, {verificationMethod, documentLoader, expansionMap}) {
    // ensure proof has expected context (even though this is called in
    // `match`, it is possible to call `validate` separately without calling
    // `match`, so check here too)
    utils.checkProofContext({proof});

    try {
      const {
        allowTargetAttenuation,
        currentDate,
        expectedAction,
        expectedRootCapability,
        expectedTarget,
        inspectCapabilityChain,
        maxChainLength,
        maxDelegationTtl,
        requireChainDateMonotonicity,
        suite
      } = this;

      let {capability} = proof;
      const {capabilityAction} = proof;
      const purposeParameters = {
        expectedTarget, expectedRootCapability,
        expectedAction, capabilityAction, CapabilityDelegation, suite
      };

      // FIXME: remove any duplicated validation code around this call
      const {dereferencedChain} = await utils.dereferenceCapabilityChain({
        capability,
        // FIXME: allow custom `getRootCapability`
        async getRootCapability({id}) {
          const {document} = await documentLoader(id);
          return {rootCapability: document};
        },
        maxChainLength
      });

      // update root capability to dereferenced root zcap
      if(typeof capability === 'string') {
        ([capability] = dereferencedChain);
      }

      // 2. verify the invocation target in the proof is expected
      // if `invocationTarget` is not specified in top-level proof, it
      // defaults to the invocation target in the capability
      const capabilityTarget = utils.getTarget({capability});
      const {invocationTarget = capabilityTarget} = proof;
      if(!((Array.isArray(expectedTarget) &&
        expectedTarget.includes(invocationTarget)) ||
        (typeof expectedTarget === 'string' &&
        invocationTarget === expectedTarget))) {
        throw new Error(
          `Expected target (${expectedTarget}) does not match ` +
          `invocation target (${invocationTarget}).`);
      }

      // 3. verify the capability's invocation target matches the one in the
      // proof
      if(!_isValidTarget({
        invocationTarget, capabilityTarget, allowTargetAttenuation
      })) {
        throw new Error(
          `Invocation target (${invocationTarget}) does not match ` +
          `capability target (${capabilityTarget}).`);
      }

      // 4. verify the capability delegation chain
      const {verified, error} = await utils.verifyCapabilityChain({
        capability, dereferencedChain,
        inspectCapabilityChain, purposeParameters, documentLoader,
        expansionMap, currentDate, allowTargetAttenuation,
        requireChainDateMonotonicity, maxDelegationTtl
      });
      if(!verified) {
        throw error;
      }

      // 5. verify the controller of the capability...
      // zcap controller must match the invoking verification method (or its
      // controller
      if(!utils.isController({capability, verificationMethod})) {
        throw new Error(
          'The capability controller does not match the verification method ' +
          '(or its controller) used to invoke.');
      }

      const validateResult = await super.validate(proof, {
        documentLoader, verificationMethod, expansionMap});

      if(!validateResult.valid) {
        throw validateResult.error;
      }

      // the controller of the verification method from the proof is the
      // invoker of the capability
      validateResult.invoker = validateResult.controller;

      // check verification method controller
      return validateResult;
    } catch(error) {
      return {valid: false, error};
    }
  }

  async update(proof) {
    const {capability, capabilityAction, invocationTarget} = this;

    proof.proofPurpose = 'capabilityInvocation';
    if(capability.parentCapability) {
      // delegated capability must be fully embedded
      proof.capability = capability;
    } else {
      // root capability must be provided by reference
      proof.capability = capability;
    }
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
};

function _isValidTarget({
  invocationTarget, capabilityTarget, allowTargetAttenuation
}) {
  // direct match, valid
  if(capabilityTarget === invocationTarget) {
    return true;
  }
  if(allowTargetAttenuation) {
    /* Note: When `allowTargetAttenuation=true`, a zcap can be invoked
    with a more narrow target and delegated zcap can have a different
    invocation target from its parent. Here we must ensure that the
    zcap's invocation target is a proper prefix for the one from the
    proof. */
    // target is only acceptable if it is a path-prefix
    const prefix = `${capabilityTarget}/`;
    if(invocationTarget.startsWith(prefix)) {
      return true;
    }
  }
  // not a match
  return false;
}

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
   *   to be added to a proof.
   * @param [invocationTarget] {string} the invocation target to use; this
   *   is required and can be used to attenuate the capability's invocation
   *   target if the verifier supports target attentuation.
   * @param [expectedAction] {string} the capability action that is expected
   *   when validating a proof.
   * @param {Object or Array} suite - the jsonld-signature suites to use to
   *   verify the capability chain.
   * @param [controller] {object} the description of the controller, if it
   *   is not to be dereferenced via a `documentLoader`.
   * @param [date] {string or Date or integer} the expected date for
   *   the creation of the proof.
   * @param [maxTimestampDelta] {integer} a maximum number of seconds that
   *   the date on the signature can deviate from, defaults to `Infinity`.
   * @param {function} [inspectCapabilityChain] -  See documentation for
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
    expectedTarget, expectedRootCapability, inspectCapabilityChain,
    capability, capabilityAction, invocationTarget,
    expectedAction, currentDate, suite, controller, date,
    maxTimestampDelta = Infinity, maxChainLength,
    allowTargetAttenuation = false, requireChainDateMonotonicity = false,
    maxDelegationTtl = Infinity
  } = {}) {
    super({term: 'capabilityInvocation', controller, date, maxTimestampDelta});
    this.expectedTarget = expectedTarget;
    this.expectedRootCapability = expectedRootCapability;
    this.capability = capability;
    this.capabilityAction = capabilityAction;
    this.invocationTarget = invocationTarget;
    this.expectedAction = expectedAction;
    this.inspectCapabilityChain = inspectCapabilityChain;
    this.maxChainLength = maxChainLength;
    this.allowTargetAttenuation = allowTargetAttenuation;
    this.requireChainDateMonotonicity = requireChainDateMonotonicity;
    this.maxDelegationTtl = maxDelegationTtl;
    this.suite = suite;

    if(currentDate !== undefined && !(currentDate instanceof Date)) {
      throw new TypeError('`currentDate` must be a Date object.');
    }
    this.currentDate = currentDate || new Date();
  }

  async validate(proof, {verificationMethod, documentLoader, expansionMap}) {
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

      if(!this.expectedTarget) {
        throw new Error('"expectedTarget" is required.');
      }

      // check the `proof` context before using its terms
      utils.checkProofContext({proof});

      let {capability} = proof;
      if(!capability) {
        throw new Error(
          '"capability" was not found in the capability invocation proof.');
      }

      const {capabilityAction} = proof;
      const purposeParameters = {
        expectedTarget, expectedRootCapability,
        expectedAction, capabilityAction, CapabilityDelegation, suite
      };

      // 1. get the capability in the security v2 context
      capability = await utils.fetchInSecurityContext(
        {url: capability, documentLoader, expansionMap});

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
        capability, inspectCapabilityChain, purposeParameters, documentLoader,
        expansionMap, currentDate, maxChainLength, allowTargetAttenuation,
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
    if(!capability) {
      throw new Error('"capability" is required.');
    }
    if(capabilityAction && typeof capabilityAction !== 'string') {
      throw new TypeError('"capabilityAction" must be a string.');
    }
    if(!invocationTarget) {
      throw new Error('"invocationTarget" is required.');
    }

    proof.proofPurpose = 'capabilityInvocation';
    proof.capability = capability;
    proof.invocationTarget = invocationTarget;
    if(capabilityAction) {
      proof.capabilityAction = capabilityAction;
    }
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

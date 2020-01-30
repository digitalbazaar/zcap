/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
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
   * @param [expectedAction] {string} the capability action that is expected
   *   when validating a proof.
   * @param [caveat] {object or array} one or more Caveat instances that
   *   can be used to check whether or not caveats have been met when
   *   verifying a proof.
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
   */
  constructor({
    expectedTarget, expectedRootCapability, inspectCapabilityChain,
    capability, capabilityAction, expectedAction, caveat,
    suite, controller, date, maxTimestampDelta = Infinity} = {}) {
    super({term: 'capabilityInvocation', controller, date, maxTimestampDelta});
    this.expectedTarget = expectedTarget;
    this.expectedRootCapability = expectedRootCapability;
    this.capability = capability;
    this.capabilityAction = capabilityAction;
    this.expectedAction = expectedAction;
    this.inspectCapabilityChain = inspectCapabilityChain;
    if(caveat !== undefined) {
      if(!Array.isArray(caveat)) {
        this.caveat = [caveat];
      } else {
        this.caveat = caveat;
      }
    }
    this.suite = suite;
  }

  async validate(proof, {verificationMethod, documentLoader, expansionMap}) {
    try {
      const {
        expectedTarget, expectedRootCapability, expectedAction, caveat, suite,
        inspectCapabilityChain
      } = this;

      if(!this.expectedTarget) {
        throw new Error('"expectedTarget" is required.');
      }

      let {capability} = proof;
      if(!capability) {
        throw new Error(
          '"capability" was not found in the capability invocation proof.');
      }

      const {capabilityAction} = proof;
      const purposeParameters = {
        expectedTarget, expectedRootCapability,
        expectedAction, capabilityAction, caveat,
        CapabilityDelegation, suite
      };

      // 1. get the capability in the security v2 context
      capability = await utils.fetchInSecurityContext(
        {url: capability, documentLoader, expansionMap});

      // 2. verify the capability delegation chain
      const {verified, error} = await utils.verifyCapabilityChain({
        capability, inspectCapabilityChain, purposeParameters, documentLoader,
        expansionMap
      });
      if(!verified) {
        throw error;
      }

      // 3. verify the invoker...
      // authorized invoker must match the verification method itself OR
      // the controller of the verification method
      if(!utils.isInvoker({capability, verificationMethod})) {
        throw new Error(
          'The authorized invoker does not match the verification method ' +
          'or its controller.');
      }

      // check verification method controller
      return await super.validate(proof, {
        documentLoader, verificationMethod, expansionMap});
    } catch(error) {
      return {valid: false, error};
    }
  }

  async update(proof) {
    const {capability, capabilityAction} = this;
    if(!capability) {
      throw new Error('"capability" is required.');
    }
    if(capabilityAction && typeof capabilityAction !== 'string') {
      throw new TypeError('"capabilityAction" must be a string.');
    }

    proof.proofPurpose = 'capabilityInvocation';
    proof.capability = capability;
    if(capabilityAction) {
      proof.capabilityAction = capabilityAction;
    }
    return proof;
  }

  async match(proof, {document, documentLoader, expansionMap}) {
    const {capabilityAction} = this;
    return await super.match(proof, {document, documentLoader, expansionMap}) &&
      (!capabilityAction || capabilityAction === proof.capabilityAction);
  }
};

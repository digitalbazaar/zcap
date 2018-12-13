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
   * @param [capability] {string or object} the capability that is to be
   *   added/referenced in a created proof.
   * @param [capabilityAction] {string} the capability action that is
   *   to be added to a proof or is expected when validating a proof.
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
   */
  constructor({
    expectedTarget, capability, capabilityAction, caveat,
    suite, controller, date, maxTimestampDelta = Infinity} = {}) {
    super({
      term: 'capabilityInvocation', controller, date, maxTimestampDelta});
    this.expectedTarget = expectedTarget;
    this.capability = capability;
    this.capabilityAction = capabilityAction;
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
      const {expectedTarget, capabilityAction, caveat, suite} = this;

      if(!this.expectedTarget) {
        throw new Error('"expectedTarget" is required.');
      }

      let {capability} = proof;
      if(!capability) {
        throw new Error(
          '"capability" was not found in the capability invocation proof.');
      }

      const purposeParameters = {
        expectedTarget, capabilityAction, caveat,
        CapabilityDelegation, suite
      };

      // 1. get the capability in the security v2 context
      capability = await utils.fetchInSecurityContext(
        {url: capability, documentLoader, expansionMap});

      // 2. verify the capability delegation chain
      const {verified, error} = await utils.verifyCapabilityChain(
        {capability, purposeParameters, documentLoader, expansionMap});
      if(!verified) {
        throw error;
      }

      // 3. verify the invoker
      const invoker = utils.getInvoker(capability);
      // authorized invoker must match the verification method itself OR
      // the controller of the verification method
      if(!(invoker &&
        (invoker === verificationMethod.id ||
        invoker === verificationMethod.controller ||
        invoker === verificationMethod.owner))) {
        throw new Error(
          'The authorized invoker does not match the verification method ' +
          'or its controller.');
      }

      // check verification method controller
      return await super.validate(proof, {
        documentLoader, verificationMethod, documentLoader, expansionMap});
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

/*!
 * Copyright (c) 2018-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const jsigs = require('jsonld-signatures');
const utils = require('./utils');
const {ControllerProofPurpose} = jsigs.purposes;

module.exports = class CapabilityDelegation extends ControllerProofPurpose {
  /**
   * @param {Array<object>} [capabilityChain] - An array of capabilities with
   *   the first entry representing the root capability and the last
   *   representing the parent of the capability to be delegated (only used when
   *   creating a proof, not validating one).
   * @param [verifiedParentCapability] the previously verified parent
   *   capability, if any.
   * @param {string} [expectedTarget] - The target we expect a capability to
   *   apply to (URI).
   * @param {string} [expectedRootCapability] - The expected root capability
   *   for the `expectedTarget`, should it be different; in cases where an
   *   object can express its authority it will be the root capability and
   *   the `expectedTarget` should match this object's ID, however, when
   *   an object cannot express its own authority another object can act
   *   as its authority if the verifier specifies it via this property.
   * @param {string|object} [capability] - The capability that is to be
   *   added/referenced in a created proof.
   * @param {string} [capabilityAction] - The capability action that is
   *   to be added to a proof or is expected when validating a proof.
   * @param {object|Array<object>} [caveat] - One or more Caveat instances that
   *   can be used to check whether or not caveats have been met when
   *   verifying a proof.
   * @param {object|Array<object>} suite - The jsonld-signature suites to use to
   *   verify the capability chain.
   * @param {object} [controller] - The description of the controller, if it
   *   is not to be loaded via a `documentLoader`.
   * @param {string|Date|number} [date] - The expected date for
   *   the creation of the proof.
   * @param {number} [maxTimestampDelta] - A maximum number of seconds that
   *   the date on the signature can deviate from, defaults to `Infinity`.
   * @param {function} [inspectCapabilityChain] - See documentation for
   *   `utils.verifyCapabilityChain`.
   * @param {Date} [currentDate = new Date()] - The date used for comparison
   *   when determining if a capability has expired.
   * @param {number} [maxChainLength=10] - The maximum length of the capability
   *   delegation chain.
   * @param {boolean} [allowTargetAttenuation=false] - Allow the
   *   invocationTarget of a delegation chain to be increasingly restrictive
   *   based on a hierarchical RESTful URL structure.
   */
  constructor({
    capabilityChain, verifiedParentCapability,
    expectedTarget, expectedRootCapability, inspectCapabilityChain,
    capability, capabilityAction, caveat, suite, currentDate, maxChainLength,
    controller, date, maxTimestampDelta = Infinity,
    allowTargetAttenuation = false
  } = {}) {
    super({term: 'capabilityDelegation', controller, date, maxTimestampDelta});

    if(capabilityChain) {
      if(!Array.isArray(capabilityChain)) {
        throw new TypeError('"capabilityChain" must be an array.');
      }
      // ensure that all capabilityChain entries except the last are strings
      const capabilityChainLengthMinusOne = capabilityChain.length - 1;
      for(let i = 0; i < capabilityChainLengthMinusOne; ++i) {
        if(typeof capabilityChain[i] !== 'string') {
          throw new TypeError('All "capabilityChain" entries except the last ' +
            'one must be strings.');
        }
      }
    }

    this.capabilityChain = capabilityChain;
    this.verifiedParentCapability = verifiedParentCapability;
    this.expectedTarget = expectedTarget;
    this.expectedRootCapability = expectedRootCapability;
    this.capability = capability;
    this.capabilityAction = capabilityAction;
    this.inspectCapabilityChain = inspectCapabilityChain;
    this.maxChainLength = maxChainLength;
    this.allowTargetAttenuation = allowTargetAttenuation;
    if(caveat !== undefined) {
      if(!Array.isArray(caveat)) {
        this.caveat = [caveat];
      } else {
        this.caveat = caveat;
      }
    }
    this.suite = suite;

    if(currentDate !== undefined && !(currentDate instanceof Date)) {
      throw new TypeError('"currentDate" must be a Date object.');
    }
    this.currentDate = currentDate || new Date();
  }

  async validate(
    proof, {document, verificationMethod, documentLoader, expansionMap}) {
    try {
      // a delegated capability requires a reference to its parent capability
      if(!('parentCapability' in document)) {
        throw new Error(
          `"parentCapability" was not found in the delegated capability.`);
      }
      if(!('invocationTarget' in document)) {
        throw new Error(
          `"invocationTarget" was not found in the delegated capability.`);
      }

      const {
        allowTargetAttenuation,
        capability,
        capabilityAction,
        capabilityChain,
        caveat,
        expectedRootCapability,
        expectedTarget,
        currentDate,
        inspectCapabilityChain,
        suite,
        maxChainLength,
      } = this;

      const purposeParameters = {
        capabilityChain, expectedTarget, expectedRootCapability, capability,
        capabilityAction, caveat, CapabilityDelegation, suite};

      // see if the parent capability has already been verified
      let {verifiedParentCapability} = this;
      if(!verifiedParentCapability) {
        // parent capability not yet verified, so verify delegation chain

        // `proof` must be reattached to the capability because it contains
        // a `capabilityChain` property that must be validated.
        // The `excludeGivenCapability` flag below prevents the cryptographic
        // proof from being checked because it has already been checked prior to
        // calling `validate` API.
        const capabilityWithProof = await _reattachProof(
          {document, documentLoader, expansionMap, proof});

        const result = await utils.verifyCapabilityChain({
          allowTargetAttenuation,
          capability: capabilityWithProof,
          currentDate,
          documentLoader,
          excludeGivenCapability: true,
          expansionMap,
          inspectCapabilityChain,
          maxChainLength,
          purposeParameters,
        });
        if(!result.verified) {
          throw result.error;
        }
        ({verifiedParentCapability} = result);
      }

      purposeParameters.verifiedParentCapability = verifiedParentCapability;

      // ensure parent capability matches
      if(document.parentCapability !== verifiedParentCapability.id) {
        throw new Error('"parentCapability" does not match.');
      }

      // ensure proof created by authorized delegator...
      // parent delegator must match the verification method itself OR
      // the controller of the verification method
      if(!utils.isDelegator(
        {capability: verifiedParentCapability, verificationMethod})) {
        throw new Error(
          'The delegator does not match the verification method ' +
          'or its controller.');
      }

      // make sure invocationTarget is valid
      const target = utils.getTarget(document);
      const parentTarget = utils.getTarget(verifiedParentCapability);

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
      const validateResult = await super.validate(proof, {
        documentLoader, verificationMethod, expansionMap});
      if(!validateResult.valid) {
        throw validateResult.error;
      }

      // finally, ensure caveats are met
      const caveatCheck = await utils.checkCaveats({
        capability: document, purposeParameters,
        documentLoader, expansionMap});
      if(!caveatCheck.valid) {
        throw caveatCheck.error;
      }

      // the controller of the proof is the delegator of the capability
      validateResult.delegator = validateResult.controller;
      delete validateResult.controller;

      // validateResult includes meta data about the proof controller
      return validateResult;
    } catch(error) {
      return {valid: false, error};
    }
  }

  async update(proof, {document, documentLoader, expansionMap}) {
    let {capabilityChain} = this;
    if(capabilityChain && !Array.isArray(capabilityChain)) {
      throw new TypeError('"capabilityChain" must be an array.');
    }

    // no capability chain given, attempt to compute from parent
    if(!capabilityChain) {
      const capability = await utils.fetchInSecurityContext(
        {url: document, documentLoader, expansionMap});
      capabilityChain = await utils.computeCapabilityChain(
        {capability, documentLoader, expansionMap});
    }

    proof.proofPurpose = 'capabilityDelegation';
    proof.capabilityChain = capabilityChain;
    return proof;
  }
};

// the capability must be fetched in the security context
// so that the `proof` which is already in the security context) can be
// safely attached to it
async function _reattachProof({document, documentLoader, expansionMap, proof}) {
  const capability = await utils.fetchInSecurityContext(
    {url: document, documentLoader, expansionMap});
  return {...capability, proof};
}

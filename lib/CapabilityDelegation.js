/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {CapabilityProofPurpose} from './CapabilityProofPurpose.js';
import * as utils from './utils.js';

/**
 * @typedef InspectCapabilityChain
 */

export class CapabilityDelegation extends CapabilityProofPurpose {
  /**
   * @param {object} options - The options.
   * @param {object} [options.parentCapability] - An alternative to passing
   *   `capabilityChain` when creating a proof; passing `parentCapability` will
   *   enable the capability chain to be auto-computed.
   * @param {boolean} [options.allowTargetAttenuation=false] - Allow the
   *   invocationTarget of a delegation chain to be increasingly restrictive
   *   based on a hierarchical RESTful URL structure.
   * @param {string|Date|number} [options.date] - Used during proof
   *   verification as the expected date for the creation of the proof
   *   (within a maximum timestamp delta) and for checking to see if a
   *   capability has expired; if not passed the current date will be used.
   * @param {string|Array} [options.expectedRootCapability] - The expected root
   *   capability for the delegation chain (this can be a single root
   *   capability ID expressed as a string or, if there is more than one
   *   acceptable root capability, several root capability IDs in an array.
   * @param {object} [options.controller] - The description of the controller,
   *   if it is not to be dereferenced via a `documentLoader`.
   * @param {InspectCapabilityChain} [options.inspectCapabilityChain] - An
   *   async function that can be used to check for revocations related to any
   *   of verified capabilities.
   * @param {number} [options.maxChainLength=10] - The maximum length of the
   *   capability delegation chain.
   * @param {number} [options.maxClockSkew=300] - A maximum number of seconds
   *   that clocks may be skewed when checking capability expiration date-times
   *   against `date`.
   * @param {number} [options.maxDelegationTtl=Infinity] - The maximum
   *   milliseconds to live for a delegated zcap as measured by the time
   *   difference between *   `expires` and `created` on the delegation proof.
   * @param {object|Array} options.suite - The jsonld-signature suite(s) to
   *   use to verify the capability chain.
   * @param {object} options._verifiedParentCapability - Private.
   * @param {object} options._capabilityChain - Private.
   * @param {boolean} options._skipLocalValidationForTesting - Private.
   */
  constructor({
    // proof creation params
    parentCapability,
    // proof verification params
    allowTargetAttenuation,
    controller,
    date,
    expectedRootCapability,
    inspectCapabilityChain,
    maxChainLength,
    maxClockSkew,
    maxDelegationTtl,
    suite,
    _verifiedParentCapability,
    // for testing purposes only, not documented intentionally
    _capabilityChain,
    _skipLocalValidationForTesting = false
  } = {}) {
    // parameters used to create a proof
    const hasCreateProofParams = parentCapability || _capabilityChain;
    // params used to verify a proof
    const hasVerifyProofParams = controller || date ||
      expectedRootCapability ||
      inspectCapabilityChain || suite ||
      _verifiedParentCapability;

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
      maxChainLength, maxClockSkew, maxDelegationTtl,
      // always `Infinity` for capability delegation proofs, as their "created"
      // values are not checked for liveness, rather "expires" is used instead
      maxTimestampDelta: Infinity,
      suite,
      term: 'capabilityDelegation'
    });

    // validate `CapabilityDelegation` specific params, the base class will
    // have already handled validating common ones...

    // use negative conditional to cover case where neither create nor
    // verify params were provided and default to proof creation case to
    // avoid creating bad proofs
    if(!hasVerifyProofParams) {
      if(!(typeof parentCapability === 'string' ||
        (typeof parentCapability === 'object' &&
        typeof parentCapability.id === 'string'))) {
        throw new TypeError(
          '"parentCapability" must be a string expressing the ID of a root ' +
          'capability or an object expressing the full parent capability.');
      }

      this.parentCapability = parentCapability;
      if(_capabilityChain) {
        if(!Array.isArray(_capabilityChain)) {
          throw new TypeError('"_capabilityChain" must be an array.');
        }
        this._capabilityChain = _capabilityChain;
      }
      if(_skipLocalValidationForTesting !== undefined) {
        this._skipLocalValidationForTesting = _skipLocalValidationForTesting;
      }
    } else {
      this._verifiedParentCapability = _verifiedParentCapability;
    }
  }

  async update(proof, {document}) {
    // if no capability chain given (*for testing purposes only*), then
    // compute from parent
    let capabilityChain;
    const {
      parentCapability, term,
      _capabilityChain, _skipLocalValidationForTesting
    } = this;
    if(_capabilityChain) {
      // use chain override from tests
      capabilityChain = _capabilityChain;
    } else {
      capabilityChain = utils.computeCapabilityChain({
        parentCapability, _skipLocalValidationForTesting
      });
    }

    proof.proofPurpose = term;
    proof.capabilityChain = capabilityChain;

    if(!_skipLocalValidationForTesting) {
      // check capability data model
      const capability = {...document, proof};
      utils.checkCapability({capability, expectRoot: false});

      // ensure proof will not be created after it expires
      const created = Date.parse(proof.created);
      const expires = Date.parse(capability.expires);
      /* Note: Intentionally do not use `utils.compareTime` as there is no
      clock drift issue here. We are not comparing against any live values
      but against date-time values expressed in the chain. */
      if(created > expires) {
        throw new Error('Cannot delegate an expired capability.');
      }

      // ensure `allowedAction`, if present, is not less restrictive
      const {allowedAction: parentAllowedAction} = parentCapability;
      const {allowedAction} = document;
      if(!utils.hasValidAllowedAction({allowedAction, parentAllowedAction})) {
        throw new Error(
          'The "allowedAction" in a delegated capability ' +
          'must not be less restrictive than its parent.');
      }

      // ensure `expires` is not less restrictive
      const {expires: parentExpires} = parentCapability;
      if(parentExpires !== undefined) {
        // handle case where `expires` is set in the parent, but the child
        // has an expiration date greater than the parent;
        /* Note: Intentionally do not use `utils.compareTime` as there is no
        clock drift issue here. We are not comparing against any live values
        but against date-time values expressed in the chain. Additionally,
        allowing skew here could introduce vulnerabilities where the expires
        time drift could aggregate with each new capability in the chain. */
        if(expires > Date.parse(parentExpires)) {
          throw new Error(
            'The `expires` property in a delegated capability must not be ' +
            'less restrictive than its parent.');
        }
      }

      // ensure capability won't be delegated before its parent was delegated
      // (if that parent is non-root)
      if(capabilityChain.length > 1) {
        // get delegated date-time (note: `computeCapabilityChain` has already
        // validated that there is a single delegation proof in
        // `parentCapability`)
        const [parentProof] = utils.getDelegationProofs(
          {capability: parentCapability});
        const parentDelegationTime = Date.parse(parentProof.created);
        const childDelegationTime = Date.parse(proof.created);
        // verify parent capability was not delegated after child
        if(parentDelegationTime > childDelegationTime) {
          throw new Error(
            'A capability in the delegation chain was delegated before ' +
            'its parent.');
        }
      }
    }

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

  _getCapabilityDelegationClass() {
    return CapabilityDelegation;
  }

  _getTailCapability({document, proof}) {
    // `proof` must be reattached to the capability because it contains
    // the `capabilityChain` that must be dereferenced and verified
    return {capability: {...document, proof}};
  }

  async _runChecksBeforeChainVerification() {
    /* Note: Here we create a signal to be sent to `_verifyCapabilityChain`
    that the capability delegation proof for the tail has already been
    verified (to avoid it being reverified). We will compute the full
    `verifyResult` in `_runChecksAfterChainVerification` once we have verified
    the parent capability. */
    return {capabilityChainMeta: [{verifyResult: {}}]};
  }

  async _runChecksAfterChainVerification({
    capabilityChainMeta, dereferencedChain, proof, validateOptions
  }) {
    // verified parent is second to last in the chain (i.e., it is the parent
    // of the last in the chain)
    const verifiedParentCapability = dereferencedChain[
      dereferencedChain.length - 2];

    // get purpose result which needs to be used to build `verifyResult`
    const purposeResult = await this._validateAgainstParent({
      proof, verifiedParentCapability, validateOptions
    });

    // build verify result
    const {verificationMethod} = validateOptions;
    const {verifyResult} = capabilityChainMeta[capabilityChainMeta.length - 1];
    verifyResult.verified = purposeResult.valid;
    verifyResult.results = [{
      proof, verified: true, verificationMethod, purposeResult
    }];

    return purposeResult;
  }

  async _shortCircuitValidate({proof, validateOptions}) {
    // see if the parent capability has already been verified
    const {
      _verifiedParentCapability: verifiedParentCapability
    } = this;
    if(verifiedParentCapability) {
      // simple case, just validate against parent and return, we have been
      // called from within a chain verification and can short circuit proof
      // validation
      return this._validateAgainstParent({
        proof, verifiedParentCapability, validateOptions
      });
    }

    // no short-circuit possible, we've just started validating the proof
    // from root => tail
  }

  async _validateAgainstParent({
    proof, verifiedParentCapability, validateOptions
  }) {
    // ensure proof created by authorized delegator...
    // parent zcap controller must match the delegating verification method
    // (or its controller)
    const {verificationMethod} = validateOptions;
    if(!utils.isController(
      {capability: verifiedParentCapability, verificationMethod})) {
      const error = new Error(
        'The capability controller does not match the verification ' +
        'method (or its controller) used to delegate.');
      error.details = {
        capability: verifiedParentCapability,
        verificationMethod
      };
      throw error;
    }

    // run base level validation checks
    const result = await this._runBaseProofValidation({proof, validateOptions});
    if(!result.valid) {
      throw result.error;
    }

    // the controller of the proof is the delegator of the capability
    result.delegator = result.controller;

    // `result` includes meta data about the proof controller
    return result;
  }
}

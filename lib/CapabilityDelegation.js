/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const CapabilityProofPurpose = require('./CapabilityProofPurpose');
const utils = require('./utils');

module.exports = class CapabilityDelegation extends CapabilityProofPurpose {
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
   * @param {object|array} suite - The jsonld-signature suite(s) to use to
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
    // parameters used to create a proof
    const hasCreateProofParams = capabilityChain || date || parentCapability;
    // params used to verify a proof
    const hasVerifyProofParams = controller || currentDate ||
      expectedRootCapability ||
      inspectCapabilityChain || suite || verifiedParentCapability;

    if(hasCreateProofParams && hasVerifyProofParams) {
      // cannot provide both create and verify params
      throw new Error(
        'Parameters for both creating and verifying a proof must not be ' +
        'provided together.');
    }

    super({
      capabilityChain, date, parentCapability,
      allowTargetAttenuation,
      controller, currentDate,
      expectedRootCapability, inspectCapabilityChain,
      maxChainLength, maxDelegationTtl, maxTimestampDelta,
      requireChainDateMonotonicity,
      suite, term: 'capabilityDelegation'
    });

    // validate `CapabilityDelegation` specific params, the base class will
    // have already handled validating common ones...

    // use negative conditional to cover case where neither create nor
    // verify params were provided and default to proof creation case to
    // avoid creating bad proofs
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
      this.verifiedParentCapability = verifiedParentCapability;
    }
  }

  // FIXME: parent class should handle this

  // async validate(
  //   proof, {document, verificationMethod, documentLoader, expansionMap}) {
  //   try {
  //     // FIXME: figure out how to avoid double-checking the context here

  //     // ensure proof has expected context (even though this is called in
  //     // `match`, it is possible to call `validate` separately without calling
  //     // `match`, so check here too)
  //     utils.checkProofContext({proof});

  //     const {
  //       allowTargetAttenuation,
  //       currentDate,
  //       expectedRootCapability,
  //       inspectCapabilityChain,
  //       maxChainLength,
  //       maxDelegationTtl,
  //       requireChainDateMonotonicity,
  //       suite
  //     } = this;

  //     /* Note: In order to reduce time wasted by attackers that submit long
  //     zcap chains that are valid beyond the root (but not at the root because
  //     the attacker hasn't actually be delegated authority), we start chain
  //     verification at the root and move forward. This means that each parent
  //     zcap must be verified before a child is. This also means that we can't
  //     simplify recursively unwind the chain in reverse -- so the code is a bit
  //     more complex.

  //     This means that the verification process is:

  //     1. Verify the tail proof (which has already occurred before this function
  //       (`validate`) is called.
  //     2. Verify the chain from root => tail by calling `verifyCapabilityChain`
  //       just once -- when validating the tail. To ensure we don't call it more
  //       than once, we use `verifiedParentCapability` as a guard; if the parent
  //       capability has been verified, we don't call it, presuming that we are
  //       presently inside of a call to `verifyCapabilityChain` initiated by
  //       validating the tail as mentioned. If we are not inside such a call,
  //       then it will also be the case that the capability delegation proof
  //       will already have been verified, so we send a signal when we call
  //       `verifyCapabilityChain` not to reverify it -- by passing in the
  //       `capabilityChainMeta` array that captures verify results such that it
  //       already contains a result. */

  //     // see if the parent capability has already been verified
  //     if(this.verifiedParentCapability) {
  //       // simple case, just validate against parent and return, we have been
  //       // called from within a chain verification
  //       return await this._validateAgainstParent({
  //         documentLoader, expansionMap, proof, verificationMethod,
  //         verifiedParentCapability: this.verifiedParentCapability
  //       });
  //     }

  //     // FIXME: now call parent
  //     const result = await super.validate(proof, {
  //       documentLoader, verificationMethod, expansionMap
  //     });

  //     // parent capability not yet verified, so verify delegation chain...

  //     // `proof` must be reattached to the capability because it contains
  //     // the `capabilityChain` that must be dereferenced and verified
  //     const capabilityWithProof = {...document, proof};
  //     const {dereferencedChain} = await utils.dereferenceCapabilityChain({
  //       capability: capabilityWithProof,
  //       // FIXME: allow custom `getRootCapability`
  //       async getRootCapability({id}) {
  //         const {document} = await documentLoader(id);
  //         return {rootCapability: document};
  //       },
  //       maxChainLength
  //     });

  //     /* Note: Here we create a signal to be sent to `verifyCapabilityChain`
  //     that the capability delegation proof for `capability` has already been
  //     verified (to avoid it being reverified). We will compute the full
  //     verify result within this function once we get the verified parent
  //     capability from `verifyCapabilityChain`. */
  //     const verifyResult = {};
  //     const capabilityChainMeta = [{verifyResult}];
  //     const result = await utils.verifyCapabilityChain({
  //       CapabilityDelegation,
  //       allowTargetAttenuation,
  //       capabilityChainMeta,
  //       currentDate,
  //       dereferencedChain,
  //       documentLoader,
  //       expansionMap,
  //       expectedRootCapability,
  //       maxDelegationTtl,
  //       requireChainDateMonotonicity,
  //       suite
  //     });
  //     if(!result.verified) {
  //       throw result.error;
  //     }
  //     const {verifiedParentCapability} = result;

  //     // get purpose result which needs to be used to build `verifyResult`
  //     const purposeResult = await this._validateAgainstParent({
  //       documentLoader, expansionMap, proof, verificationMethod,
  //       verifiedParentCapability
  //     });

  //     // build verify result
  //     verifyResult.verified = purposeResult.valid;
  //     verifyResult.results = [{
  //       proof, verified: true, verificationMethod, purposeResult
  //     }];

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

  //     return purposeResult;
  //   } catch(error) {
  //     return {valid: false, error};
  //   }
  // }

  async update(proof) {
    // FIXME: can we remove the optionality and always compute the chain
    // instead?
    let {capabilityChain} = this;

    // no capability chain given, attempt to compute from parent
    if(!capabilityChain) {
      const {parentCapability} = this;
      // FIXME: determine if capability needs to be validated at this point
      capabilityChain = utils.computeCapabilityChain({parentCapability});
    }

    proof.proofPurpose = this.term;
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

  _getCapabilityDelegationClass() {
    return CapabilityDelegation;
  }

  _getTailCapability({document, proof}) {
    // `proof` must be reattached to the capability because it contains
    // the `capabilityChain` that must be dereferenced and verified
    return {capability: {...document, proof}};
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
    const {verifiedParentCapability} = this;
    if(verifiedParentCapability) {
      // simple case, just validate against parent and return, we have been
      // called from within a chain verification
      return this._validateAgainstParent({
        proof, verifiedParentCapability, validateOptions
      });
    }
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
      throw new Error(
        'The capability controller does not match the verification ' +
        'method (or its controller) used to delegate.');
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
};

/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {ProofPurposeHandler} = require('jsonld-signatures');
const utils = require('./utils');

// TODO: Maybe convert this to a non-recursive version that iterates through
//   the cap chain as an array instead
module.exports = class CapabilityDelegation extends ProofPurposeHandler {
  constructor(injector) {
    super(injector);
    this.uri = 'https://w3id.org/security#capabilityDelegationSuite';
  }

  // When `validate` is invoked, the signature for the given proof has already
  // been verified.
  //
  // Arguments:
  //  - document: A framed version of the invocation document the proof is
  //    attached to, using the security v2 context.
  //  - proof: The proof we're checking in the security v2 context.
  //
  // purposeParameters keywords:
  //  - expectedTarget: the target we expect this capability to apply to (URI).
  //  - caveatVerifiers: a hashmap of caveat URIs to procedures which
  //    verify those caveats.  The caveat-verifying procedures should take
  //    two arguments: the caveat being verified, and the expanded invocation
  //    document.
  async validate({document, proof, purposeParameters, documentLoader}) {
    try {
      // a delegated capability requires a reference to its parent capability
      if(!('parentCapability' in document)) {
        throw new Error(
          `"parentCapability" was not found in the delegated capability.`);
      }

      const jsigs = this.injector.use('jsonld-signatures');
      const jsonld = this.injector.use('jsonld');

      // see if the parent capability has already been verified
      let {verifiedParentCapability} = purposeParameters;
      if(!verifiedParentCapability) {
        // parent capability not yet verified, so verify delegation chain
        const result = await utils.verifyCapabilityChain({
          capability: document,
          proof,
          purposeParameters,
          jsigs,
          jsonld,
          documentLoader
        });
        if(!result) {
          throw result.error;
        }
        ({verifiedParentCapability} = result);
      }

      // ensure parent capability matches
      if(document.parentCapability !== verifiedParentCapability.id) {
        throw new Error('"parentCapability" does not match.');
      }

      // FIXME: use purposeParameters.key and purposeParameters.keyOptions
      // to optimize the following lookup

      // ensure proof created by authorized delegator
      const creator = proof.creator;
      const parentDelegator = verifiedParentCapability.delegator;
      const result = await utils.validateDelegator({
        creator,
        delegator: parentDelegator,
        jsonld,
        documentLoader
      });
      if(!result.valid) {
        return result;
      }

      // finally, ensure caveats are met
      return await utils.checkCaveats({
        capability: document,
        purposeParameters,
        jsigs,
        jsonld,
        documentLoader
      });
    } catch(error) {
      return {valid: false, error};
    }
  }

  async createProof({input, proof, purposeParameters, documentLoader}) {
    // get capability chain from parameters
    let {capabilityChain} = purposeParameters;
    if(capabilityChain && !Array.isArray(purposeParameters.capabilityChain)) {
      throw new TypeError(
        '"purposeParameters.capabilityChain" must be an array.');
    }

    // no capability chain given, attempt to compute from parent
    if(!capabilityChain) {
      const jsonld = this.injector.use('jsonld');
      const capability = await utils.fetchInSecurityContext(
        {url: input, jsonld, documentLoader});
      capabilityChain = await utils.computeCapabilityChain(
        {capability, jsonld, documentLoader});
    }

    return {...proof, proofPurpose: 'capabilityDelegation', capabilityChain};
  }
};

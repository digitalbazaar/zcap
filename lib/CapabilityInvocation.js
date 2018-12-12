/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {ProofPurposeHandler} = require('jsonld-signatures');
const utils = require('./utils');

module.exports = class CapabilityInvocation extends ProofPurposeHandler {
  constructor(injector) {
    super(injector);
    this.uri = 'https://w3id.org/security#capabilityInvocationSuite';
  }

  // When `validate` is invoked, the signature for the given proof has already
  // been verified.
  //
  // Arguments:
  //  - document: A framed version of the invocation document the proof is
  //    attached to, using the security v2 context
  //  - proof: The proof we're checking in the security v2 context
  //
  // purposeParameters keywords:
  //  - expectedTarget: the target we expect this capability to apply to (URI).
  //  - caveatVerifiers: a hashmap of caveat URIs to procedures which
  //    verify those caveats.  The caveat-verifying procedures should take
  //    two arguments: the caveat being verified, and the expanded invocation
  //    document.
  async validate({proof, purposeParameters, documentLoader}) {
    try {
      const {expectedTarget} = purposeParameters;
      if(!expectedTarget) {
        throw new Error('"purposeParameters.expectedTarget" is required.');
      }

      let {capability} = proof;
      if(!capability) {
        throw new Error(
          '"capability" was not found in the capability invocation proof.');
      }

      // 1. get the capability in the security v2 context
      const jsonld = this.injector.use('jsonld');
      capability = await utils.fetchInSecurityContext(
        {url: capability, jsonld, documentLoader});

      // 2. verify the capability delegation chain
      const jsigs = this.injector.use('jsonld-signatures');
      const {verified, error} = await utils.verifyCapabilityChain(
        {capability, purposeParameters, jsigs, jsonld, documentLoader});
      if(!verified) {
        throw error;
      }

      // FIXME: use purposeParameters.key and purposeParameters.keyOptions
      // to optimize the following lookup

      // 3. verify the invoker
      const {creator} = proof;
      const authorizedInvoker = utils.getInvoker(capability);
      return await utils.validateInvoker({
        creator,
        invoker: authorizedInvoker,
        jsonld,
        documentLoader
      });
    } catch(error) {
      return {valid: false, error};
    }
  }

  async createProof({proof, purposeParameters}) {
    const {capability, capabilityAction} = purposeParameters;
    if(!capability) {
      throw new Error('Please specify "capability"; the URI of the capability' +
      ' to be invoked.');
    }
    if(capabilityAction && typeof capabilityAction !== 'string') {
      throw new TypeError(
        '"purposeParameters.capabilityAction" must be a string.');
    }
    const newProof = {
      ...proof, proofPurpose: 'capabilityInvocation', capability
    };
    if(capabilityAction) {
      newProof.capabilityAction = capabilityAction;
    }
    return newProof;
  }
};

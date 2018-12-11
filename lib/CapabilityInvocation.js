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

  // Arguments:
  //  - document: An already-expanded version of the invocation document
  //    this proof is attached to
  //  - proof: An already-expanded version of the proof we are checking
  //
  // purposeParameters keywords:
  //  - expectedTarget: the target we expect this capability to apply to (URI).
  //  - caveatVerifiers: a hashmap of caveat URIs to procedures which
  //    verify those caveats.  The caveat-verifying procedures should take
  //    two arguments: the caveat being verified, and the expanded invocation
  //    document.
  async validate({document, proof, purposeParameters = {}, documentLoader}) {
    // Retrieve the JSON-LD document associated with the capability ID
    if(!('capability' in proof)) {
      const error = new Error(
        `"capability" was not found in the proof for the invoked capability.`);
      return {
        verified: false,
        error
      };
    }
    // FIXME: `capability` needs to be compacted to security context and
    // potentially validated
    const {document: capability} = await documentLoader(proof.capability);
    // Prepare to check that the creator matches the parentCapability's invoker
    const {creator} = proof;
    const authorizedInvoker = utils.getInvoker(capability);

    try {
      const verifiedInvoker = utils.verifyInvoker({
        creator,
        invoker: authorizedInvoker,
        jsonld: this.injector.use('jsonld'),
        documentLoader
      });
      const verifiedCaveats = utils.verifyCaveats({
        capability: document,
        purposeParameters
      });
      const verifiedCapability = utils.verifyCapability({
        capability,
        jsigs: this.injector.use('jsonld-signatures'),
        purposeParameters
      });

      const verified = await verifiedInvoker &&
        await verifiedCaveats &&
        (await verifiedCapability).verified;
      const {error} = (await verifiedCapability);
      return error ? {verified, error} : {verified};
    } catch(e) {
      return {
        verified: false,
        error: e
      };
    }
  }

  async createProof({proof, purposeParameters = {}}) {
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

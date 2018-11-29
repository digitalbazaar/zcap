/**
 * Copyright (c) 2018 Digital Bazaar, Inc.
 *
 * @author Christopher Lemmer Webber
 * @author Ganesh Annan <gannan@digitalbazaar.com>
 *
 */
'use strict';

const jsigs = require('jsonld-signatures');
const utils = require('./utils');

const {ProofPurposeHandler} = jsigs;

module.exports = class CapabilityInvocation extends ProofPurposeHandler {
  constructor(injector) {
    super(injector);
    this.documentLoader = injector.use('jsonld').documentLoader;
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
  async validate({document, proof, purposeParameters}) {
    // Retrieve the JSON-LD document associated with the capability ID
    const {document: capability} = await this.documentLoader(proof.capability);
    // Prepare to check that the creator matches the parentCapability's invoker
    const {creator} = proof;
    const authorizedInvoker = utils.getInvoker(capability);

    try {
      const verifiedCaveats = utils.verifyCaveats({
        capability: document,
        purposeParameters
      });

      const verifiedCapability = utils.verifyCapability({
        capability,
        purposeParameters
      });

      const verified = authorizedInvoker === creator
        && await verifiedCaveats
        && (await verifiedCapability).verified;

      const {error} = (await verifiedCapability);
      return error ?  {verified, error} : {verified};
    } catch(e) {
      return {
        verified: false,
        error: e
      }
    }
  }

  async createProof({proof, purposeParameters = {}}) {
    const {capability} = purposeParameters;
    if(!capability) {
      throw new Error('Please specify "capability"; the URI of the capability' +
      ' to be invoked.')
    }
    // FIXME: May need to use jsonld to properly add field
    return Object.assign({}, proof, {
      proofPurpose: 'capabilityInvocation',
      capability
    });
  }
};

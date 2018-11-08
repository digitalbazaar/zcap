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
const vocab = require('./vocab');

const {ProofPurpose} = jsigs;

module.exports = class CapabilityInvocation extends ProofPurpose {
  constructor(injector) {
    super(injector);
    this.documentLoader = injector.use('jsonld').documentLoader;
    this.uri = vocab.capabilityInvocationUri;
  }

  // Arguments:
  //  - document: An already-expanded version of the invocation document
  //    this proof is attached to
  //  - proof: An already-expanded version of the proof we are checking
  //
  // proofPurposeOptions keywords:
  //  - expectedTarget: the target we expect this capability to apply to (URI).
  //  - caveatVerifiers: a hashmap of caveat URIs to procedures which
  //    verify those caveats.  The caveat-verifying procedures should take
  //    two arguments: the caveat being verified, and the expanded invocation
  //    document.
  async verify(document, proof, proofPurposeOptions) {
    const {capabilityUri, creatorUri} = vocab;

    // Retrieve the JSON-LD document associated with the capability ID
    const {document: capability} = await this.documentLoader(
      utils.getOne(proof[capabilityUri]));

    // Prepare to check that the creator matches the parentCapability's invoker
    const creator = utils.getOne(proof[creatorUri]);
    const parentInvoker = await utils.getParentInvoker({
      capability: parent,
      documentLoader :this.documentLoader
    });

    const verifiedCaveats = utils.verifyCaveats({
      capability: document,
      proofPurposeOptions
    });
    const verifiedCapability = utils.verifyCap({
      capability,
      jsigs: this.injector.use('jsonld-signatures'),
      proofPurposeOptions
    });
    return (parentInvoker === creator && // proof created by authorized invoker
            await verifiedCaveats &&
            await verifiedCapability);
  }
};

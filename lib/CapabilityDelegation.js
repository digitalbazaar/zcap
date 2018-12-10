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

  // Arguments:
  //  - document: An already-expanded version of the delegation document
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
    const checkIfRevoked = purposeParameters['revocationChecker'] ||
      noopRevocationChecker;

    const revoked = await checkIfRevoked(document, purposeParameters);
    if(revoked) {
      const error = new Error('Capability has been revoked.');
      return {
        verified: false,
        error
      };
    }
    // A delegated capability requires a reference to its parentCapability.
    if(!('parentCapability' in document)) {
      const error = new Error(
        `"parentCapability" was not found in the delegated capability.`);
      return {
        verified: false,
        error
      };
    }

    const {document: parent} = await documentLoader(document.parentCapability);

    // proof created by authorized delegator
    const creator = proof.creator;
    const parentDelegator = parent.delegator;
    const verifiedDelegator = await utils.verifyDelegator({
      creator,
      delegator: parentDelegator,
      jsonld: this.injector.use('jsonld'),
      documentLoader
    });
    if(!verifiedDelegator) {
      const error = new Error('Parent delegator does not match the creator.');
      return {
        verified: false,
        error
      };
    }

    // Does the capability pass its caveats
    const verifiedCaveats = await utils.verifyCaveats({
      capability: document,
      purposeParameters
    });
    if(!verifiedCaveats) {
      const error = new Error(
        `"parentCapability" was not found in the delegated capability.`);
      return {
        verified: false,
        error
      };
    }

    // Is the parent an invalid cap?
    return utils.verifyCapability({
      capability: parent,
      jsigs: this.injector.use('jsonld-signatures'),
      purposeParameters
    });
  }

  async createProof({proof}) {
    // FIXME: May need to use jsonld to properly add field
    return {...proof, proofPurpose: 'capabilityDelegation'};
  }
};

/**
 * The default do-nothing check for if things are revoked
 */
async function noopRevocationChecker() {
  return false;
}

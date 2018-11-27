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

// TODO: Maybe convert this to a non-recursive version that iterates through
//   the cap chain as an array instead
module.exports = class CapabilityDelegation extends ProofPurpose {
  constructor(injector) {
    super(injector);
    this.documentLoader = injector.use('jsonld').documentLoader;
    this.uri = vocab.capabilityDelegationUri;
  }

  // Arguments:
  //  - document: An already-expanded version of the delegation document
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

    const checkIfRevoked = proofPurposeOptions['revocationChecker'] ||
      noopRevocationChecker;

    // Revoked?  Then nope...
    const revoked = await checkIfRevoked(document, proofPurposeOptions);
    if(revoked) {
      return {
        verified: false,
        error: 'Capability has been revoked.'
      };
    }
    // No parentCapability?  Delegation doesn't apply to the target, so nope...
    if(!('parentCapability' in document)) {
      return {
        verified: false,
        error: `"parentCapability" was not found in the delegated capability.`
      };
    }

    const {document: parent} = await this.documentLoader(
      document.parentCapability);
    // proof created by authorized invoker
    const creator = proof.creator;
    const parentInvoker = parent.invoker;

    if(parentInvoker !== creator) {
      return {
        verified: false,
        error: 'Parent invoker does not match the creator.'
      };
    }

    // Does the capability pass its caveats
    const verifiedCaveats = await utils.verifyCaveats({
      capability: document,
      proofPurposeOptions
    });
    if(!verifiedCaveats) {
      return {
        verified: false,
        error: `"parentCapability" was not found in the delegated capability.`
      };
    }

    // Is the parent an invalid cap?
    const verifiedCapability = await utils.verifyCapability({
      capability: parent,
      proofPurposeOptions
    });
    if(!verifiedCapability) {
      return false;
    }
    // Ok, we're good!
    return true;
  }

  async addFieldsToProof(proof, proofPurposeOptions) {
    // FIXME: May need to use jsonld to properly add field
    return Object.assign({}, proof, {proofPurpose: 'capabilityDelegation'})
  }
};

/**
 * The default do-nothing check for if things are revoked
 */
async function noopRevocationChecker() {
  return false;
}

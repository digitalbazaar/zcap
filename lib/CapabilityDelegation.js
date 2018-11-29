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

// TODO: Maybe convert this to a non-recursive version that iterates through
//   the cap chain as an array instead
module.exports = class CapabilityDelegation extends ProofPurposeHandler {
  constructor(injector) {
    super(injector);
    this.documentLoader = injector.use('jsonld').documentLoader;
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
  async validate({document, proof, purposeParameters = {}}) {
    // console.log({document, proof, purposeParameters});
    const checkIfRevoked = purposeParameters['revocationChecker'] ||
      noopRevocationChecker;

    // Revoked?  Then nope...
    const revoked = await checkIfRevoked(document, purposeParameters);
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
    // proof created by authorized delegator
    const creator = proof.creator;
    const parentDelegator = parent.delegator;

    if(parentDelegator !== creator) {
      return {
        verified: false,
        error: 'Parent delegator does not match the creator.'
      };
    }

    // Does the capability pass its caveats
    const verifiedCaveats = await utils.verifyCaveats({
      capability: document,
      purposeParameters
    });
    if(!verifiedCaveats) {
      return {
        verified: false,
        error: `"parentCapability" was not found in the delegated capability.`
      };
    }

    // Is the parent an invalid cap?
    return utils.verifyCapability({
      capability: parent,
      purposeParameters
    });
  }

  async createProof({proof, purposeParameters = {}}) {
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

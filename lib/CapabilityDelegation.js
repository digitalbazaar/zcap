/**
 * Linked Data Signatures/Proofs
 *
 * @author Christopher Lemmer Webber
 * @author Ganesh Annan <gannan@digitalbazaar.com>
 * 
 * @license BSD 3-Clause License
 * Copyright (c) 2018 Digital Bazaar, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of the Digital Bazaar, Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
    const {parentCapabilityUri, creatorUri} = vocab;

    const checkIfRevoked = proofPurposeOptions['revocationChecker'] ||
      noopRevocationChecker;

    // Revoked?  Then nope...
    const revoked = await checkIfRevoked(document, proofPurposeOptions);
    if(revoked) {
      return false;
    }
    // No parentCapability?  Delegation doesn't apply to the target, so nope...
    if (!(parentCapabilityUri in document)) {
      return false;
    }

    const {document: parent} = await this.documentLoader(
      utils.getOneOrDie(document[parentCapabilityUri]));

    // proof created by authorized invoker
    const creator = utils.getOneOrDie(proof[creatorUri]);
    const parentInvoker = await utils.getParentInvoker({
      capability: parent,
      documentLoader: this.documentLoader
    });
    if(parentInvoker !== creator) {
      return false;
    }

    // Does the capability pass its caveats
    const verifiedCaveats = await utils.verifyCaveats({
      capability: document,
      proofPurposeOptions
    });
    if(!verifiedCaveats) {
      return false;
    }

    // Is the parent an invalid cap?
    const verifiedCapability = await utils.verifyCapability({
      capability: parent,
      jsigs: this.injector.use('jsonld-signatures'),
      proofPurposeOptions
    });
    if(!verifiedCapability) {
      return false;
    }
    // Ok, we're good!
    return true;
  }
};

/**
 * The default do-nothing check for if things are revoked
 */
async function noopRevocationChecker() {
  return true;
}

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
    this.uri = vocab.capabilityDelegationUri;
  }

  async verify(document, proof, proofPurposeOptions) {
    const {parentCapabilityUri, creatorUri} = vocab;

    const checkIfRevoked = proofPurposeOptions['revocationChecker'] || noopRevocationChecker;
    // Revoked?  Then nope...
    if (await checkIfRevoked(document, proofPurposeOptions)) {
      return false;
    }
    // No parentCapability?  Delegation doesn't apply to the target, so nope...
    if (!(parentCapabilityUri in document)) {
      return false;
    }
    const parent = utils.getOneOrDie(document[parentCapabilityUri]);
    // Not a member of the parent invokers?  Then nope...
    const creator = utils.getOneOrDie(proof[creatorUri]);
    const invokers = await utils.getCapInvokers(parent);
    if (!invokers.includes(creator)) {
      return false;
    }
    // Is the parent an invalid cap?
    if (!await utils.verifyCap(cap, proofPurposeOptions, this.injector.use('jsonld'))) {
      return false;
    }
    // Ok, we're good!
    return true;
  }
};

// The default do-nothing check for if things are revoked
async function noopRevocationChecker(cap, proofPurposeOptions) {
  return true;
}

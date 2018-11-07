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

const defaultCaveatRegistry = require('./caveatRegistry');
const vocab = require('./vocab');

const api = {};
module.exports = api;

const {
  capabilityDelegationUri,
  caveatUri,
  invocationTargetUri,
  invokerUri,
  parentCapabilityUri
} = vocab;

/**
 * Retrieves a capability's parent's invoker
 *
 * @param {Object} capability - the fully expanded JSON-LD document for the
 *                              object capability
 * @param {Object} documentLoader - a JSON-LD document loader
 *
 */
api.getParentInvoker = async ({capability, documentLoader}) => {
  const {document: parentCapability} =
    await documentLoader(capability[parentCapabilityUri]);

  return parentCapability.invoker;
};

/**
 * Plucks the single element of an array that contains a single item.
 *
 * @param {Array} array - an array with one item.
 */
api.getOneOrDie = array => {
  if(Array.isArray(array) && array.length === 1) {
    return array[0];
  }
  throw new Error('Expected an array of size 1');
};

/**
 * Retrieves the invoker from a capability.
 *
 * @param {Object} capability - the fully expanded JSON-LD document for the
 *                              object capability
 */
api.getInvoker = capability => {
  const invoker = capability[invokerUri];
  const id = capability['@id'];
  if(!invoker || !id) {
    throw new Error('Invoker not found for capability');
  }

  return invoker || id;
};

/**
 * Verifies the caveats for a given object capability.
 *
 * @param {Object} capability - the fully expanded JSON-LD document for the
 *                              object capability
 * @param {Object} jsigs - a configured instance of jsonld-signatures
 * @param {Object} proofPurposeOptions  - a set of options for validating the
 *                                        proof purpose.
 */
api.verifyCapability = async ({capability, jsigs, proofPurposeOptions}) => {
  // Capability does not point to a parent capability and it was capable of
  // delegating a capability
  if(!(parentCapabilityUri in capability) &&
    capabilityDelegationUri in capability) {
    const {expectedTarget} = proofPurposeOptions;
    // target is the root capability unless an invocation target is specified
    const target = invocationTargetUri in capability ?
      api.getOneOrDie(capability[invocationTargetUri]) : capability['@id'];
    // It's the toplevel capability, which means it's valid if the target
    // matches the expected target
    return target === expectedTarget;
  } else {
    // Otherwise, we have to check the signature
    return jsigs.verify(capability, {
      proofPurpose: 'CapabilityDelegation',
      proofPurposeOptions: proofPurposeOptions
    });
  }
};

/**
 * Verifies the caveats for a given object capability.
 *
 * @param {Object} capability - the fully expanded JSON-LD document for the
 *                              object capability
 * @param {Object} proofPurposeOptions  - a set of options for validating the
 *                                        proof purpose.
 */
api.verifyCaveats = async ({capability, proofPurposeOptions}) => {
  const caveats = capability[caveatUri] || [];
  const caveatRegistry = proofPurposeOptions.caveatRegistry ||
    defaultCaveatRegistry;

  for(const caveat of caveats) {
    const caveatType = caveat['@type'];
    if(!(caveatType in caveatRegistry)) {
      throw new Error(
        'Caveat handler not found for caveat type: ' + caveatType);
    }
    const caveatChecker = caveatRegistry[caveatType];
    const success = await caveatChecker(
      caveat, capability, proofPurposeOptions);
    if(!success) {
      return false;
    }
  }

  return true;
};

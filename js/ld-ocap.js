/**
 * A JavaScript implementation of Linked Data Capabilities
 *
 * @author Christopher Lemmer Webber
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

// Vocabulary
// ==========

const jsonld = require('jsonld');
const jsig = require('jsonld-signatures');
jsig.use('jsonld', jsonld);
const _ = require('lodash');

const ocapBaseUri = 'https://example.org/ocap/v1#';

function prefixedOcapUri(suffix) {
  return ocapBaseUri + suffix;
}

// Vocabulary URIs
const caveatUri = prefixedOcapUri('caveat');
const capabilityAuthorizationUri = prefixedOcapUri(
  'capabilityAuthorization');

const proofUri = 'https://w3id.org/security#proof'
const signatureUri = 'https://w3id.org/security#signature'


// Helper functions
// ================

async function makeCaveatVerifier(verifierMap) {
  async function dispatchVerifier(caveat, expandedInvocation, options) {
    // FIXME: We might need to load the caveat from a url
    let caveatTypeArray = caveat['@type'] || [];
    if(caveat['@type'].length !== 1) {
      throw new LdOcapError('Caveat @type must have exactly one element');
    }
    let [caveatType] = caveat['@type'];
    // retrieve the verifier for this type
    if(!_.has(verifierMap, caveatType)) {
      // TODO: Probably we should specify which caveat / type caused this
      //   error?
      throw new LdOcapError('No verifier supplied for caveat type');
    }
    let caveatVerifier = verifierMap[caveatType];
    // Run the caveat verifier, which will raise an exception if
    // the verification fails
    await caveatVerifier(caveat, expandedInvocation, options);
  }
  return dispatchVerifier;
}

// TODO: Add some default caveats here
const defaultCaveatVerifier = makeCaveatVerifier({});


// Core API
// ========

/**
 * Ensures this capability chain is valid within the context of the
 * Invocation, including verifying all caveats.  Raises an exception
 * if unsuccessful, otherwise returns true.
 */
async function verifyInvocation(invocation, options) {
  try {
    const expandedInvocation = await jsonld.expand(invocation);
    // Expands each, and makes sure each has type of Capability
    const capChain = await getCapChain(expandedInvocation);

    const caveatverifier = options['caveatVerifier'] || defaultCaveatVerifier;
    async function verifyCaveats(expandedCapDoc) {
      const caveats = expandedCapDoc[caveatUri] || [];
      for (const caveat in caveats) {
        await caveatVerifier(caveat, expandedInvocation, options);
      }
    }

    // Who's currently authorized to invoke this capability.
    // Start with whatever the root document says...
    const rootCap = _.head(capChain);
    let currentlyAuthorized = rootCap[capabilityAuthorizationUri] || [];

    if(currentlyAuthorized.length === 0) {
      throw new LdOcapError(
        'Root capability must grant authority to an initial set of credentials');
    }

    //// on to the rest of the capability docs ////
    // The function we use to make sure that any of the later capability
    // documents are proved by a currently authorized participant
    async function verifySignedByAuthorized(capDoc) {
      // TODO: This is super kludgy... does the solution come from
      //   changes to Linked Data Proofs though?
      // A hacky workaround so we can support the proof field even if
      // someone supplied signature instead.
      if(_.has(capDoc, proofUri)) {
        const updateDict = {[signatureUri]: capDoc[proofUri]};
        capDoc = _.assign(_.omit(capDoc, [proofUri]), updateDict);
      }
      
      const numProofs = (capDoc[signatureUri] || []).length;
      if(numProofs === 0) {
        throw new LdOcapError(
          'Capability document must have one or more associated proofs');
      }

      // Make sure that one of the currentlyAuthorized keys are able to verify
      // this proof
      // FIXME: We can check the proof(s) to see if a specific entity signed
      //   this in many (all?) cases rather than iterating through everything
      // like this
      for(const authorized in currentlyAuthorized) {
        const result = await jsig.promises.verify(authorized);
        if (result.verified) {
          // Ok, it was signed by someone who is currentlyAuthorized
          return true;
        }
      }
      // Welp, no success, raise an error
      throw new LdOcapError(
        'Capability document not signed by an authorized entity');
    }

    // Verify each capability and associated caveats...
    for(const cap in capChain) {
      await verifySignedByAuthorized(cap);
      await verifyCaveats(cap);
      if(_.has(cap, capabilityAuthorizationUri)) {
        // time to delegate!
        currentlyAuthorized = cap[capabilityAuthorizationUri];
      }
    }

    // Made it this far... now to check that the invocation itself is signed
    // by one of the currentlyAuthorized
    await verifySignedByAuthorized(expandedInvocation);

    // Looks like we're solid
    return {verified: true};
  } catch(e) {
    return {verified: false, error: e};
  }
}

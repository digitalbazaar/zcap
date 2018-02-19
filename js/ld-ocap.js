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
const invokerUri = prefixedOcapUri(
  'invoker');
const capabilityUri = prefixedOcapUri(
  'capability');
const invokeCapabilityUri = prefixedOcapUri(
  'invokeCapability');
const parentCapabilityUri = prefixedOcapUri(
  'parentCapability');

const proofUri = 'https://w3id.org/security#proof';
const proofPurposeUri = 'https://w3id.org/security#proofPurpose';
const signatureUri = 'https://w3id.org/security#signature';

class LdOcapError extends Error {
  constructor(message, name='ldocap.error', details={}) {
    super(message);
    this.name = name;
    this.message = message;
    this.details = details;
  }
}


// Helper functions
// ================

async function makeCaveatVerifier(verifierMap) {
  return async function (
    caveat, expandedInvocation, {jsonLdOptions={}, state={}}) {
    // FIXME: We might need to load the caveat from a url
    const caveatTypeArray = caveat['@type'] || [];
    if(caveat['@type'].length !== 1) {
      throw new LdOcapError('Caveat @type must have exactly one element');
    }
    const [caveatType] = caveatTypeArray;
    // retrieve the verifier for this type
    if(!_.has(verifierMap, caveatType)) {
      // TODO: Probably we should specify which caveat / type caused this
      //   error?
      throw new LdOcapError('No verifier supplied for caveat type');
    }
    let caveatVerifier = verifierMap[caveatType];
    // Run the caveat verifier, which will raise an exception if
    // the verification fails
    await caveatVerifier(
      caveat, expandedInvocation, {jsonLdOptions, state});
  };
}

// TODO: Add some default caveats here
const defaultCaveatVerifier = makeCaveatVerifier({});

// The function we use to make sure that any of the later capability
// documents are proved by a currently authorized participant
async function verifySignedByAuthorized(capDoc, currentlyAuthorized) {
  // FIXME: This is super kludgy... does the solution come from
  //   changes to Linked Data Proofs though?  Linked Data Signatures
  //   should be the one providing this functionality
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
  for(const authorized of currentlyAuthorized) {
    // FIXME: We'd only call verify once, we check that it was verified
    //   and we check the key results to make sure our key is in there
    const result = await jsig.promises.verify(
      capDoc,
      // FIXME:
      {publicKeySomething: authorized});
    if (result.verified) {
      // Ok, it was signed by someone who is currentlyAuthorized
      return true;
    }
  }
  // Welp, no success, raise an error
  throw new LdOcapError(
    'Capability document not signed by an authorized entity');
}

// Get the capability chain as a list of fully expanded json-ld documents,
// starting with the root capability document and working from there.
async function getCapChain(
  ocapProof, {getCapability=defaultGetCapability, jsonLdOptions={}}) {
  // Make sure we don't end up somehow infinitely recursing
  // This is a set of ids
  const seen = new Set();
  // Capbility chain... 
  const capChain = [];

  // Get a capability, possibly from a URI, and
  const addCap = async function(capOrUri) {
    let cap;
    // maybe retrieve the capability
    if(_.isString(capOrUri)) {
      cap = jsonld.expand(await getCapability(capOrUri), jsonLdOptions);
    } else {
      // It should already be expanded at this point
      cap = capOrUri;
    }
    capChain.unshift(cap);
    if(_.has(cap, '@id')) {
      if(seen.has(cap['@id'])) {
        throw LdOcapError(
          'Cyclical capability chain detected');
      }
      seen.add(cap['@id']);
    }

    const parentCapabilityLength = (cap[parentCapabilityUri] || []).length;
    if (parentCapabilityLength === 0) {
      // We're done here, this must be the root... this is a no-op
      return;
    } else if(parentCapabilityLength === 1) {
      // Time to recursively add this capability 
      return addCap(cap[parentCapabilityUri][0]);
    } else {
      throw new LdOcapError(
        'parentCapability should be empty or have a single value');
    }
  };

  // TODO: We have a lot of this "get a single value from an expanded document"
  //   logic; refactor into a single procedure
  if ((ocapProof[capabilityUri] || []).length !== 1) {
    throw new LdOcapError(
      'capability field must have exactly one value');
  }
  const [firstCapDoc] = ocapProof[capabilityUri];

  // Start recursively adding capchain documents, starting with this
  // leaf
  await addCap(firstCapDoc);

  return capChain;
}

async function defaultGetCapability(ocapOrUri) {
  // no-op kludge so linter doesn't complain about unused variables
  ocapOrUri;
  throw new LdOcapError(
    'getCapability argument not set');
}

// Core API
// ========

/**
 * Ensures this capability chain is valid within the context of the
 * Invocation, including verifying all caveats.  Raises an exception
 * if unsuccessful, otherwise returns true.
 */
async function verifyInvocation(
  invocation,
  {
    getCapability=defaultGetCapability, caveatVerifier=defaultCaveatVerifier,
    jsonLdOptions={}, state={}
  }) {
  try {
    const expandedInvocation = await jsonld.expand(invocation, jsonLdOptions);

    // First let's look for the ocap proof(s)
    const ocapProofs = _.filter(
      expandedInvocation[proofUri] || [],
      function (item) {
        (_.has(item, capabilityUri) &&
         item[proofPurposeUri] === invokeCapabilityUri);});
    // They'd better be there!
    if(ocapProofs.length === 0) {
      throw new LdOcapError(
        'Invocation document does not have a capability proof');
    }

    for (const ocapProof of ocapProofs) {
      // Expands each, and makes sure each has type of Capability
      const capChain = await getCapChain(
        ocapProof, {jsonLdOptions, getCapability});

      // Who's currently authorized to invoke this capability.
      // Start with whatever the root document says...
      // FIXME: This should use grantCapability invocationTarget,
      //   not the currentlyAuthorized.  That's a serious bug!
      // FIXME: And probably this should even be overrideable
      const rootCap = _.head(capChain);
      let currentlyAuthorized = rootCap[invokerUri] || [];

      if(currentlyAuthorized.length === 0) {
        throw new LdOcapError(
          'Root capability must grant authority to initial set ' +
          'of credentials');
      }

      // Verify each capability and associated caveats...
      for(const cap of capChain) {
        await verifySignedByAuthorized(
          cap, currentlyAuthorized,
          {jsonLdOptions, state});

        // Verify caveats
        const caveats = cap[caveatUri] || [];
        for (const caveat of caveats) {
          // TODO: Maybe destructure named arguments
          await caveatVerifier(
            caveat, expandedInvocation, ocapProof,
            {jsonLdOptions, state});
        }

        // Maybe delegate
        if(_.has(cap, invokerUri)) {
          currentlyAuthorized = cap[invokerUri];
        }
      }
      // Made it this far... now to check that the invocation itself is signed
      // by one of the currentlyAuthorized
      // FIXME: How do we check the specific proof?
      await verifySignedByAuthorized(expandedInvocation, currentlyAuthorized);
    }

    // Looks like we're solid
    return {verified: true};
  } catch(e) {
    return {verified: false, error: e};
  }
}

const api = {verifyInvocation};

module.exports = api;

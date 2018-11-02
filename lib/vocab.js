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

const creatorUri = 'http://purl.org/dc/terms/creator';
const ocapBaseUri = 'https://example.org/ocap/v1#';
const proofUri = 'https://w3id.org/security#proof';
const proofPurposeUri = 'https://w3id.org/security#proofPurpose';


// Vocabulary URIs
// TODO: It may be this isn't necessary since we have proofPurpose of
const CapabilityUri = prefixedOcapUri('Capability'); // Capability, the type
const capabilityUri = prefixedOcapUri('capability'); // capability, the property
const caveatUri = prefixedOcapUri('caveat');
const invokerUri = prefixedOcapUri('invoker');
const capabilityInvocationUri = prefixedOcapUri('capabilityInvocation');
const capabilityDelegationUri = prefixedOcapUri('capabilityDelegation');
const parentCapabilityUri = prefixedOcapUri('parentCapability');
const invocationTargetUri = prefixedOcapUri('invocationTarget');

const RestrictActionUri = prefixedOcapUri('RestrictAction');
const restrictActionUri = prefixedOcapUri('restrictAction');

const ExpireAtUri = prefixedOcapUri('ExpireAt');
const expireAtUri = prefixedOcapUri('expireAt');

module.exports = {
  creatorUri,
  ocapBaseUri,
  proofUri,
  proofPurposeUri,
  CapabilityUri,
  capabilityUri,
  caveatUri,
  invokerUri,
  capabilityInvocationUri,
  capabilityDelegationUri,
  parentCapabilityUri,
  invocationTargetUri,
  RestrictActionUri,
  restrictActionUri,
  ExpireAtUri,
  expireAtUri
};

function prefixedOcapUri(suffix) {
  return ocapBaseUri + suffix;
}

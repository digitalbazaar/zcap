/**
 * Copyright (c) 2018 Digital Bazaar, Inc.
 *
 * @author Christopher Lemmer Webber
 * @author Ganesh Annan <gannan@digitalbazaar.com>
 *
 */
'use strict';

const creatorUri = 'http://purl.org/dc/terms/creator';
// FIXME: Update ocap context url before release
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

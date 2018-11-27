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
const securityBaseUri = 'https://w3id.org/security#';
const ocapBaseUri = 'https://example.org/ocap/v1#';
const proofUri = 'https://w3id.org/security#proof';
const proofPurposeUri = 'https://w3id.org/security#proofPurpose';

// Vocabulary URIs
const capabilityUri = prefixedSecurityUri('capability');
const caveatUri = prefixedSecurityUri('caveat');
const invokerUri = prefixedSecurityUri('invoker');
const capabilityInvocationUri = prefixedSecurityUri('capabilityInvocation');
const capabilityDelegationUri = prefixedSecurityUri('capabilityDelegation');
const parentCapabilityUri = prefixedSecurityUri('parentCapability');
const invocationTargetUri = prefixedSecurityUri('invocationTarget');

const RestrictActionUri = prefixedOcapUri('RestrictAction');
const restrictActionUri = prefixedOcapUri('restrictAction');

const ExpireAtUri = prefixedOcapUri('ExpireAt');
const expireAtUri = prefixedOcapUri('expireAt');

module.exports = {
  creatorUri,
  ocapBaseUri,
  proofUri,
  proofPurposeUri,
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

function prefixedSecurityUri(suffix) {
  return securityBaseUri + suffix;
}

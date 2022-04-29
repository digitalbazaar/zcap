/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as zcap from '../lib/index.js';
const {constants: {ZCAP_CONTEXT_URL}} = zcap;

export const capabilities = {};
export const didDocs = {};
export const privateDidDocs = {};
export const controllers = {};
const _loaderData = new Map();

const KEY_TYPES = [
  'capabilityDelegation', 'capabilityInvocation', 'verificationMethod'
];

export {default as exampleDoc} from './mock-documents/example-doc.js';
export const exampleDocWithInvocation = {};

import exampleDocWithInvocation_alpha from
  './mock-documents/example-doc-with-alpha-invocation.js';
exampleDocWithInvocation.alpha = exampleDocWithInvocation_alpha;
import exampleDocWithInvocation_beta from
  './mock-documents/example-doc-with-beta-invocation.js';
exampleDocWithInvocation.beta = exampleDocWithInvocation_beta;

import didContext from './mock-documents/did-context.js';
_loaderData.set('https://www.w3.org/ns/did/v1', didContext);

import v1Context from './mock-documents/veres-one-context.js';
_loaderData.set('https://w3id.org/veres-one/v1', v1Context);

import {suiteContext} from '@digitalbazaar/ed25519-signature-2020';
_loaderData.set(suiteContext.CONTEXT_URL, suiteContext.CONTEXT);

import controllers_alice from './mock-documents/ed25519-alice-keys.js';
controllers.alice = controllers_alice;
import controllers_bob from './mock-documents/ed25519-bob-keys.js';
controllers.bob = controllers_bob;
import controllers_carol from './mock-documents/ed25519-carol-keys.js';
controllers.carol = controllers_carol;
import controllers_diana from './mock-documents/ed25519-diana-keys.js';
controllers.diana = controllers_diana;

import privateDidDocs_alpha from './mock-documents/did-doc-alpha.js';
privateDidDocs.alpha = privateDidDocs_alpha;
import privateDidDocs_beta from './mock-documents/did-doc-beta.js';
privateDidDocs.beta = privateDidDocs_beta;
import privateDidDocs_gamma from './mock-documents/did-doc-gamma.js';
privateDidDocs.gamma = privateDidDocs_gamma;
import privateDidDocs_delta from './mock-documents/did-doc-delta.js';
privateDidDocs.delta = privateDidDocs_delta;

didDocs.alpha = _stripPrivateKeys(privateDidDocs.alpha);
didDocs.beta = _stripPrivateKeys(privateDidDocs.beta);
didDocs.gamma = _stripPrivateKeys(privateDidDocs.gamma);
didDocs.delta = _stripPrivateKeys(privateDidDocs.delta);

capabilities.root = {};

// keys as controller
capabilities.root.alpha = {
  '@context': ZCAP_CONTEXT_URL,
  id: 'https://example.org/alice/caps#1',
  controller: 'https://example.com/i/alice/keys/1',
  invocationTarget: 'https://example.org/alice/targets/alpha'
};
capabilities.root.beta = {
  '@context': ZCAP_CONTEXT_URL,
  id: 'https://example.org/alice/caps#0',
  controller: controllers.alice.id,
  invocationTarget: 'https://example.org/alice/targets/beta'
};

capabilities.root.restful = {
  '@context': ZCAP_CONTEXT_URL,
  id: `urn:zcap:root:${encodeURIComponent('https://zcap.example')}`,
  controller: controllers.alice.id,
  invocationTarget: 'https://zcap.example'
};

capabilities.delegated = {};
import capabilities_delegated_alpha from
  './mock-documents/delegated-zcap-alpha.js';
capabilities.delegated.alpha = capabilities_delegated_alpha;
import capabilities_delegated_beta from
  './mock-documents/delegated-zcap-beta.js';
capabilities.delegated.beta = capabilities_delegated_beta;

// generate a flattened list of all keys
const keyList = [].concat(
  ...Object.values(controllers).map(_getKeysWithContext),
  ...Object.values(privateDidDocs).map(_getKeysWithContext));

export function addToLoader({doc}) {
  if(_loaderData.has(doc.id)) {
    throw new Error(
      `ID of document has already been registered in the loader: ${doc.id}`);
  }
  _loaderData.set(doc.id, doc);
}

export const testLoader = zcap.extendDocumentLoader(async url => {
  const document = _loaderData.get(url);
  if(document !== undefined) {
    return {
      contextUrl: null,
      document,
      documentUrl: url
    };
  }
  throw new Error(`Document "${url}" not found.`);
});

function _stripPrivateKeys(privateDidDocument) {
  // clone the doc
  const didDocument = JSON.parse(JSON.stringify(privateDidDocument));
  delete didDocument.authentication[0].privateKeyMultibase;
  delete didDocument.capabilityDelegation[0].privateKeyMultibase;
  delete didDocument.capabilityInvocation[0].privateKeyMultibase;
  return didDocument;
}

const docsForLoader = [
  controllers.alice,
  controllers.bob,
  controllers.carol,
  controllers.diana,
  didDocs.alpha,
  didDocs.beta,
  didDocs.gamma,
  didDocs.delta,
  capabilities.root.alpha,
  capabilities.root.beta,
  capabilities.root.restful,
  ...keyList
];

docsForLoader.map(doc => addToLoader({doc}));

function _getKeysWithContext(doc) {
  const keys = [];
  for(const keyType of KEY_TYPES) {
    keys.push(...(doc[keyType] || [])
      .filter(k => typeof k !== 'string')
      .map(k => ({'@context': doc['@context'], ...k})));
  }
  return keys;
}

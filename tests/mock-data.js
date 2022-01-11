/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const zcap = require('../lib');
const {constants: {ZCAP_CONTEXT_URL}} = zcap;

const mock = {};
module.exports = mock;

const capabilities = mock.capabilities = {};
const didDocs = mock.didDocs = {};
const privateDidDocs = mock.privateDidDocs = {};
const controllers = mock.controllers = {};
const _loaderData = new Map();

const KEY_TYPES = [
  'capabilityDelegation', 'capabilityInvocation', 'verificationMethod'
];

mock.exampleDoc = require('./mock-documents/example-doc');
mock.exampleDocWithInvocation = {};

mock.exampleDocWithInvocation.alpha =
  require('./mock-documents/example-doc-with-alpha-invocation');
mock.exampleDocWithInvocation.beta =
  require('./mock-documents/example-doc-with-beta-invocation');

const didContext = require('./mock-documents/did-context');
_loaderData.set('https://www.w3.org/ns/did/v1', didContext);

const v1Context = require('./mock-documents/veres-one-context');
_loaderData.set('https://w3id.org/veres-one/v1', v1Context);

const {suiteContext} = require('@digitalbazaar/ed25519-signature-2020');
_loaderData.set(suiteContext.CONTEXT_URL, suiteContext.CONTEXT);

controllers.alice = require('./mock-documents/ed25519-alice-keys');
controllers.bob = require('./mock-documents/ed25519-bob-keys');
controllers.carol = require('./mock-documents/ed25519-carol-keys');
controllers.diana = require('./mock-documents/ed25519-diana-keys');

privateDidDocs.alpha = require('./mock-documents/did-doc-alpha');
privateDidDocs.beta = require('./mock-documents/did-doc-beta');
privateDidDocs.gamma = require('./mock-documents/did-doc-gamma');
privateDidDocs.delta = require('./mock-documents/did-doc-delta');

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
capabilities.delegated.alpha = require('./mock-documents/delegated-zcap-alpha');
capabilities.delegated.beta = require('./mock-documents/delegated-zcap-beta');

// generate a flattened list of all keys
const keyList = [].concat(
  ...Object.values(controllers).map(_getKeysWithContext),
  ...Object.values(privateDidDocs).map(_getKeysWithContext));

mock.addToLoader = ({doc}) => {
  if(_loaderData.has(doc.id)) {
    throw new Error(
      `ID of document has already been registered in the loader: ${doc.id}`);
  }
  _loaderData.set(doc.id, doc);
};

mock.testLoader = zcap.extendDocumentLoader(async url => {
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

docsForLoader.map(doc => mock.addToLoader({doc}));

function _getKeysWithContext(doc) {
  const keys = [];
  for(const keyType of KEY_TYPES) {
    keys.push(...(doc[keyType] || [])
      .filter(k => typeof k !== 'string')
      .map(k => ({'@context': doc['@context'], ...k})));
  }
  return keys;
}

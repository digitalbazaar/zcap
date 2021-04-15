/*!
 * Copyright (c) 2018-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {SECURITY_CONTEXT_URL} = require('jsonld-signatures');

const mock = {};
module.exports = mock;

const capabilities = mock.capabilities = {};
const didDocs = mock.didDocs = {};
const privateDidDocs = mock.privateDidDocs = {};
const controllers = mock.controllers = {};
const _loaderData = {};

const KEY_TYPES = ['capabilityDelegation', 'capabilityInvocation', 'publicKey'];

mock.exampleDoc = require('./mock-documents/example-doc');
mock.exampleDocWithInvocation = {};

mock.exampleDocWithInvocation.alpha =
  require('./mock-documents/example-doc-with-alpha-invocation');
mock.exampleDocWithInvocation.beta =
  require('./mock-documents/example-doc-with-beta-invocation');

const didContext = require('./mock-documents/did-context');
_loaderData['https://w3id.org/did/v0.11'] = didContext;

const v1Context = require('./mock-documents/veres-one-context');
_loaderData['https://w3id.org/veres-one/v1'] = v1Context;

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
// keys as invoker and delegator
capabilities.root.alpha = {
  '@context': SECURITY_CONTEXT_URL,
  id: 'https://example.org/alice/caps#1',
  invoker: 'https://example.com/i/alice/keys/1',
  delegator: 'https://example.com/i/alice/keys/1'
};
// using `controller` to cover both `delegator` and `invoker`
capabilities.root.beta = {
  '@context': SECURITY_CONTEXT_URL,
  id: 'https://example.org/alice/caps#0',
  controller: controllers.alice.id
};

capabilities.delegated = {};
capabilities.delegated.alpha =
  require('./mock-documents/delegated-ocap-root-alpha');
capabilities.delegated.beta =
  require('./mock-documents/delegated-ocap-root-beta');

// Generate a flattened list of all keys
let controllersKeyList = Object.keys(controllers).map(name => KEY_TYPES
  .map(keyType => controllers[name][keyType])
  .reduce((acc, curr) => acc.concat(curr), [])
);
controllersKeyList = [].concat.apply([], controllersKeyList)
  .filter(key => !!key && typeof key !== 'string');

let ddocKeyList = Object.keys(privateDidDocs).map(name => KEY_TYPES
  .map(keyType => privateDidDocs[name][keyType])
  .reduce((acc, curr) => acc.concat(curr), [])
);
ddocKeyList = [].concat.apply([], ddocKeyList)
  .filter(key => !!key && typeof key !== 'string')
  .reduce((acc, curr) => acc.concat(curr), []);

const keyList = controllersKeyList.concat(ddocKeyList);

mock.addToLoader = ({doc}) => {
  if(doc.id in _loaderData) {
    throw new Error(
      `ID of document has already been registered in the loader: ${doc.id}`);
  }
  if(!('@context' in doc)) {
    doc = {'@context': SECURITY_CONTEXT_URL, ...doc};
  }
  _loaderData[doc.id] = doc;
};

mock.testLoader = async url => {
  if(url in _loaderData) {
    return {
      contextUrl: null,
      document: _loaderData[url],
      documentUrl: url
    };
  }
  throw new Error(`Document "${url}" not found.`);
};

function _stripPrivateKeys(privateDidDocument) {
  // clone the doc
  const didDocument = JSON.parse(JSON.stringify(privateDidDocument));
  delete didDocument.authentication[0].privateKeyBase58;
  delete didDocument.capabilityDelegation[0].privateKeyBase58;
  delete didDocument.capabilityInvocation[0].privateKeyBase58;
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
  ...keyList
];

docsForLoader.map(doc => mock.addToLoader({doc}));

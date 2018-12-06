
const mock = {};
module.exports = mock;

const capabilities = mock.capabilities = {};
const ddocs = mock.ddocs = {};
const owners = mock.owners = {};
const _loaderData = {};

const KEY_TYPES = ['capabilityDelegation', 'capabilityInvocation', 'publicKey'];

owners.alice = require('./mock-documents/ed25519-alice-keys');
owners.bob = require('./mock-documents/ed25519-bob-keys');
owners.carol = require('./mock-documents/ed25519-carol-keys');
owners.diana = require('./mock-documents/ed25519-diana-keys');

ddocs.alpha = require('./mock-documents/did-doc-alpha');
ddocs.beta = require('./mock-documents/did-doc-beta');
ddocs.gamma = require('./mock-documents/did-doc-gamma');
ddocs.delta = require('./mock-documents/did-doc-delta');

capabilities.root = {};
capabilities.root.controller = {
  '@context': 'https://w3id.org/security/v2',
  id: 'https://example.org/alice/caps#0',
  invoker: owners.alice.id,
  delegator: owners.alice.id
};
capabilities.root.keys = {
  '@context': 'https://w3id.org/security/v2',
  id: 'https://example.org/alice/caps#1',
  invoker: 'https://example.com/i/alice/keys/1',
  delegator: 'https://example.com/i/alice/keys/1'
};

// Generate a flattened list of all keys
let ownersKeyList = Object.keys(owners).map(name => KEY_TYPES
  .map(keyType => owners[name][keyType])
  .reduce((acc, curr) => acc.concat(curr), [])
);
ownersKeyList = [].concat.apply([], ownersKeyList)
  .filter(key => !!key && typeof key.publicKey !== 'string')
  .map((doc) => doc.publicKey ? doc.publicKey : doc);

let ddocKeyList = Object.keys(ddocs).map(name => KEY_TYPES
  .map(keyType => ddocs[name][keyType])
  .reduce((acc, curr) => acc.concat(curr), [])
);
ddocKeyList = [].concat.apply([], ddocKeyList)
  .filter(key => !!key && typeof key.publicKey !== 'string')
  .map(doc => doc.publicKey ? doc.publicKey : doc)
  .reduce((acc, curr) => acc.concat(curr), []);

const keyList = ownersKeyList.concat(ddocKeyList);

mock.addToLoader = ({doc}) => {
  if(doc.id in _loaderData) {
    throw new Error(
      `ID of document has already been registered in the loader: ${doc.id}`);
  }
  _loaderData[doc.id] = doc;
};

mock.testLoader = oldLoader => async url => {
  // register root capability
  if(url in _loaderData) {
    return {
      contextUrl: null,
      document: _loaderData[url],
      documentUrl: url
    };
  }
  return oldLoader(url);
};

const docsForLoader = [
  owners.alice,
  owners.bob,
  owners.carol,
  owners.diana,
  capabilities.root.keys,
  capabilities.root.controller,
  ...keyList
];

docsForLoader.map(doc => mock.addToLoader({doc}));


const mock = {};
module.exports = mock;

const capabilities = mock.capabilities = {};
const owners = mock.owners = {};
const _loaderData = {};

const KEY_TYPES = ['capabilityDelegation', 'capabilityInvocation', 'publicKey'];

owners.alice = require('./mock-documents/ed25519-alice-keys');
owners.bob = require('./mock-documents/ed25519-bob-keys');
owners.carol = require('./mock-documents/ed25519-carol-keys');
owners.diana = require('./mock-documents/ed25519-diana-keys');

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
let keyList = Object.keys(owners).map(name => KEY_TYPES
  .map(keyType => owners[name][keyType])
  .reduce((acc, curr) => acc.concat(curr), [])
);
keyList = [].concat.apply([], keyList)
  .filter(key => !!key && typeof key.publicKey !== 'string')
  .map((doc) => doc.publicKey ? doc.publicKey : doc);

mock.addToLoader = ({doc}) => {
  if(doc.id in _loaderData) {
    throw new Error('ID of document has already been registered in the loader');
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

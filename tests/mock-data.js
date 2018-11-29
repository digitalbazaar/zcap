const jsonld = require('jsonld');

const mock = {};
module.exports = mock;

const capabilities = mock.capabilities = {};
const owners = mock.owners = {};

const KEY_TYPES = ['capabilityDelegation', 'capabilityInvocation'];

owners['alice'] = require('./mock-documents/ed25519-alice-keys');
owners['bob'] = require('./mock-documents/ed25519-bob-keys');
owners['carol'] = require('./mock-documents/ed25519-carol-keys');
owners['diana'] = require('./mock-documents/ed25519-diana-keys');

// Generate a flattened list of all keys
let keyList = Object.keys(owners).map(name => KEY_TYPES
  .map(keyType => owners[name][keyType])
  .reduce((acc, curr) => acc.concat(curr), [])
)
keyList = [].concat.apply([], keyList)

capabilities['root'] = {
  "@context": "https://w3id.org/security/v2",
  "id": "https://example.org/alice/caps#1",
  "invoker": "https://example.com/i/alice/keys/1",
  "delegator": "https://example.com/i/alice/keys/1"
}

mock.testLoader = oldLoader => async url => {
  // register root capability
  if(url === capabilities.root.id) {
    return {
      contextUrl: null,
      document: capabilities.root,
      documentUrl: capabilities.root.id
    };
  }
  //FIXME: rename owners to controllers
  // register key owners
  if(url === owners.alice.id) {
    return {
      contextUrl: null,
      document: owners.alice,
      documentUrl: owners.alice.id
    };
  }
  if(url === owners.bob.id) {
    return {
      contextUrl: null,
      document: owners.bob,
      documentUrl: owners.bob.id
    };
  }
  if(url === owners.carol.id) {
    return {
      contextUrl: null,
      document: owners.carol,
      documentUrl: owners.carol.id
    };
  }
  if(url === owners.diana.id) {
    return {
      contextUrl: null,
      document: owners.diana,
      documentUrl: owners.diana.id
    };
  }
  // register keys
  const [key, ...rest] = keyList.filter(key => key.publicKey.id === url);

  // verify that the same key used for different proof purposes are equal
  if(rest.length > 0) {
    const opts = {
      algorithm: 'URDNA2015',
      format: 'application/n-quads'
    }
    const canonizedKey = await jsonld.canonize(key.publicKey, opts);
    rest.forEach(async duplicateKey => {
      const canonizedDuplicateKey = await jsonld.canonize(
        duplicateKey.publicKey, opts);
      if(canonizedKey !== canonizedDuplicateKey) {
        const {id} = key.publicKey;
        throw new Error(
          `Keys with the same id were found with different data: ${id}`);
      }
    });
  }
  if(key) {
    return {
      contextUrl: null,
      document: key.publicKey,
      documentUrl: key.publicKey.id
    };
  }
  return oldLoader(url);
};

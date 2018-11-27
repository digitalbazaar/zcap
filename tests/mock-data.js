
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
  "invoker": "https://example.com/i/alice/keys/1"
}

mock.testLoader = oldLoader => (url, callback) => {
  // register root capability
  if(url === capabilities.root.id) {
    return callback(null, {
      contextUrl: null,
      document: capabilities.root,
      documentUrl: capabilities.root.id
    });
  }
  //FIXME: rename owners to controllers
  // register key owners
  if(url === owners.alice.id) {
    return callback(null, {
      contextUrl: null,
      document: owners.alice,
      documentUrl: owners.alice.id
    });
  }
  if(url === owners.bob.id) {
    return callback(null, {
      contextUrl: null,
      document: owners.bob,
      documentUrl: owners.bob.id
    });
  }
  if(url === owners.carol.id) {
    return callback(null, {
      contextUrl: null,
      document: owners.carol,
      documentUrl: owners.carol.id
    });
  }
  if(url === owners.diana.id) {
    return callback(null, {
      contextUrl: null,
      document: owners.diana,
      documentUrl: owners.diana.id
    });
  }
  // register keys
  const [key, ...rest] = keyList.filter(key => key.publicKey.id === url);
  // ensure one and only one key is found for a url, if rest.length > 0, then we
  // accidentally created keys that have the same id
  if(key && rest.length === 0) {
    return callback(null, {
      contextUrl: null,
      document: key.publicKey,
      documentUrl: key.publicKey.id
    });
  }
  return oldLoader(url, callback);
};

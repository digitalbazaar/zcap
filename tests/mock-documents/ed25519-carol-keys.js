module.exports = {
  "@context": "https://w3id.org/security/v2",
  "id": "https://example.com/i/carol",
  "capabilityInvocation": [
    {
      "type": "Ed25519SignatureCapabilityInvocation2018",
      "publicKey": {
        "@context": "https://w3id.org/security/v2",
        "id": "https://example.com/i/carol/keys/1",
        "type": ["CryptographicKey", "Ed25519VerificationKey2018"],
        "owner": "https://example.com/i/carol",
        "publicKeyBase58": "Fg15hCqJ19LP4X4RaiumJVb8YeZnzUjWLh74hKqBvk5B",
        "privateKeyBase58": "5NXABW3kdXgAGhSwXecHq61Pi1mMVaq6cEe4E3hjhdksUYQ7fnwYNxSEkkthwMzTc2y4AoVsLnW5eFVjhT1stg2R"
      }
    }
  ],
  "capabilityDelegation": [
    {
      "type": "Ed25519SignatureCapabilityDelegation2018",
      "publicKey": {
        "@context": "https://w3id.org/security/v2",
        "id": "https://example.com/i/carol/keys/2",
        "type": ["CryptographicKey", "Ed25519VerificationKey2018"],
        "owner": "https://example.com/i/carol",
        "publicKeyBase58": "Fg15hCqJ19LP4X4RaiumJVb8YeZnzUjWLh74hKqBvk5B",
        "privateKeyBase58": "5NXABW3kdXgAGhSwXecHq61Pi1mMVaq6cEe4E3hjhdksUYQ7fnwYNxSEkkthwMzTc2y4AoVsLnW5eFVjhT1stg2R"
      }
    }
  ],
  "https://example.org/special-authentication": {
    "publicKey": "https://example.com/i/carol/keys/1"
  }
};

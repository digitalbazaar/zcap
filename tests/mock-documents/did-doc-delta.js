module.exports = {
  "@context": ["https://w3id.org/did/v0.11", "https://w3id.org/veres-one/v1"],
  "id": "did:v1:test:nym:9iofLVptQB9BwZ484xTHbvwfxEmN2ByNR8hSXE2uho88",
  "authentication": [
    {
      "id": "did:v1:test:nym:9iofLVptQB9BwZ484xTHbvwfxEmN2ByNR8hSXE2uho88#authn-key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:9iofLVptQB9BwZ484xTHbvwfxEmN2ByNR8hSXE2uho88",
      "publicKeyBase58": "9iofLVptQB9BwZ484xTHbvwfxEmN2ByNR8hSXE2uho88",
      "privateKeyBase58": "38aVNnnSMwoCoENhtRdxriZXbJnezeqvbTNiromuBrD6HgADSXDkPA5mnuinoikNimF3u2Eu6P7ATGXtezDzqYHi"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "did:v1:test:nym:9iofLVptQB9BwZ484xTHbvwfxEmN2ByNR8hSXE2uho88#ocap-grant-key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:9iofLVptQB9BwZ484xTHbvwfxEmN2ByNR8hSXE2uho88",
      "publicKeyBase58": "5F3zHUr8xpVzS1W7tGWTEfaybTQZmVJkuNH49Y89ryj8",
      "privateKeyBase58": "39396uTD1gZBmSzpYUXreL2KvEhDZypdT8DvMueHFAkbHa9GCQH7qqK51SMKMUjaoi2nXiYKik6LMVLRkbYvCq3Q"
    }
  ],
  "capabilityInvocation": [
    {
      "id": "did:v1:test:nym:9iofLVptQB9BwZ484xTHbvwfxEmN2ByNR8hSXE2uho88#ocap-invoke-key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:9iofLVptQB9BwZ484xTHbvwfxEmN2ByNR8hSXE2uho88",
      "publicKeyBase58": "7Am8p94Sbi1bvmLych2FNvBdrEsyhbiqcCtWR6ztg2ho",
      "privateKeyBase58": "3sVpdhTCguiuWs6qxLAgpeejJbAAAehUdKXkS7fjkqMxocUzbzwBQuqy7G3AQ5SAKZBZWHeJaRjwuKPFEu3yfYcH"
    }
  ]
};

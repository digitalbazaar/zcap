module.exports = {
  "@context": [
    "https://w3id.org/zcap/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "urn:uuid:710910c8-61e4-11ec-8739-10bf48838a41",
  "parentCapability": "https://example.org/alice/caps#0",
  "controller": "https://example.com/i/bob",
  "invocationTarget": "https://example.org/alice/targets/beta",
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2018-02-13T21:26:08Z",
    "capabilityChain": [
      "https://example.org/alice/caps#0"
    ],
    "proofPurpose": "capabilityDelegation",
    "proofValue": "z28dbP4b1dJw1h9Maho7TJ5M7Ar53zJdFAa5sq2iVW4BiegBntZqKkmBkTSJesfxhv2PjHCo12VozW2v8sSJz1NCa",
    "verificationMethod": "https://example.com/i/alice/keys/1"
  }
};

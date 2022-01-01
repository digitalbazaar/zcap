module.exports = {
  "@context": [
    "https://w3id.org/zcap/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "urn:uuid:055f47a4-61d3-11ec-9144-10bf48838a41",
  "parentCapability": "https://example.org/alice/caps#1",
  "controller": "https://example.com/i/bob/keys/1",
  "invocationTarget": "https://example.org/alice/targets/alpha",
  "expires": "3000-01-01T00:01Z",
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2018-02-13T21:26:08Z",
    "capabilityChain": [
      "https://example.org/alice/caps#1"
    ],
    "proofPurpose": "capabilityDelegation",
    "proofValue": "z4Hm6e5ziMoiG2eWpRyB1ozrnh65gikaVAZzkXpMUNFarzouKNYYXCc4YqLZch12JgcfCqpSmgYfV6JXL8FSyC4pW",
    "verificationMethod": "https://example.com/i/alice/keys/1"
  }
};

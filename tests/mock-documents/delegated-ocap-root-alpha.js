module.exports = {
  "@context": "https://w3id.org/security/v2",
  "id": "https://whatacar.example/a-fancy-car/proc/7a397d7b-alpha",
  "parentCapability": "https://example.org/alice/caps#1",
  "invoker": "https://example.com/i/bob/keys/1",
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2018-02-13T21:26:08Z",
    "creator": "https://example.com/i/alice/keys/1",
    "capabilityChain": [
      "https://example.org/alice/caps#1"
    ],
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..7gWpVs_N0phkQShsT9cdYLAaLi_83xWphYFjhj2aIjNtYdNn37R0d8ko9fCj-q6bY8o4qpAuTxYNPApVawtxBg",
    "proofPurpose": "capabilityDelegation"
  }
};

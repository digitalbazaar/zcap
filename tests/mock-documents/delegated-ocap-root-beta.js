module.exports = {
  "@context": "https://w3id.org/security/v2",
  "id": "https://whatacar.example/a-fancy-car/proc/7a397d7b-beta",
  "parentCapability": "https://example.org/alice/caps#0",
  "invoker": "https://example.com/i/bob",
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2018-02-13T21:26:08Z",
    "capabilityChain": [
      "https://example.org/alice/caps#0"
    ],
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..K40i_9n8N41PQhfVoOhsZ7p2RNJEWwtXkJbdnA4f9EobBG1bGl7Uk9DIWmNFu4qEo8aI0D0Lm64JTaY43lMKBQ",
    "proofPurpose": "capabilityDelegation",
    "verificationMethod": "https://example.com/i/alice/keys/1"
  }
};

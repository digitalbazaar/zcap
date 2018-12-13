module.exports = {
  "@context": "https://w3id.org/security/v2",
  "id": "https://whatacar.example/a-fancy-car/proc/7a397d7b-beta",
  "parentCapability": "https://example.org/alice/caps#0",
  "invoker": "https://example.com/i/bob",
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2018-02-13T21:26:08Z",
    "creator": "https://example.com/i/alice/keys/1",
    "capabilityChain": [
      "https://example.org/alice/caps#0"
    ],
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..zSmqpL85cdZ6byzrgYOgjnlAgKDqHquorRdNKMAfqHVYEMNSV_zmhwbTCC6KqbZkzr7fb46-onqCqGbHnYPqDQ",
    "proofPurpose": "capabilityDelegation"
  }
};

module.exports = {
  "@context": "https://w3id.org/security/v2",
  "id": "urn:uuid:cab83279-c695-4e66-9458-4327de49197a",
  "nonce": "123",
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2018-02-13T21:26:08Z",
    "capability": "https://example.org/alice/caps#0",
    "invocationTarget": "https://example.org/alice/caps#0",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..QyM223BkvuaSE9pLNq9lFbSAa6gI5yEGAZ6a4lGaf25FuDaphDUdzJQLyqA5dSVgcyBDe1GVoPfTN_d7R23UCA",
    "proofPurpose": "capabilityInvocation",
    "verificationMethod": "https://example.com/i/alice/keys/1"
  }
};

module.exports = {
  "@context": "https://w3id.org/security/v2",
  "id": "urn:uuid:cab83279-c695-4e66-9458-4327de49197a",
  "nonce": "123",
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2018-02-13T21:26:08Z",
    "capability": "https://example.org/alice/caps#0",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..nW6G_xUHxK49mwimQlcfhSmjGvTc3FcFzopzusBwsz-EYN_WNM4rQWPBcWG6gmLxk9QES1bude5NhSRXWgwVCw",
    "proofPurpose": "capabilityInvocation",
    "verificationMethod": "https://example.com/i/alice/keys/1"
  }
};

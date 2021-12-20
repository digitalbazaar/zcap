module.exports = {
  "@context": [
    "https://w3id.org/security/v2",
    "https://w3id.org/zcap/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "urn:uuid:cab83279-c695-4e66-9458-4327de49197a",
  "nonce": "123",
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2018-02-13T21:26:08Z",
    "capability": "https://example.org/alice/caps#0",
    "invocationTarget": "https://example.org/alice/caps#0",
    "proofPurpose": "capabilityInvocation",
    "proofValue": "z243z8m8YQb8Fis6vJWgLwJSGnd9z3Hb8CSekWYDrqm9GiqoPoBTcaRRa5M1GLKNxizSSRLSgckYhUCj8iqoidBhZ",
    "verificationMethod": "https://example.com/i/alice/keys/1"
  }
};

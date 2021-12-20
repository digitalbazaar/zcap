module.exports = {
  "@context": [
    "https://w3id.org/security/v2",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "https://example.com/i/bob",
  "capabilityInvocation": [
    {
      "id": "https://example.com/i/bob/keys/1",
      "type": "Ed25519VerificationKey2020",
      "controller": "https://example.com/i/bob",
      "publicKeyMultibase": "z6MkqyrirHAq8Acicq1FyNJGd9R7D1DW7Q8A3v1qqZfP4pdY",
      "privateKeyMultibase": "zrv2yZunr7Cz1cZTSQgJPZ35CQaSiJt5iN3Ah4JCND7cBAzyrfRaiE4HhFsUtcSadaf7f9qMDH9rXVutKr12LGxgXPY"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "https://example.com/i/bob/keys/2",
      "type": "Ed25519VerificationKey2020",
      "controller": "https://example.com/i/bob",
      "publicKeyMultibase": "z6MkqyrirHAq8Acicq1FyNJGd9R7D1DW7Q8A3v1qqZfP4pdY",
      "privateKeyMultibase": "zrv2yZunr7Cz1cZTSQgJPZ35CQaSiJt5iN3Ah4JCND7cBAzyrfRaiE4HhFsUtcSadaf7f9qMDH9rXVutKr12LGxgXPY"
    }
  ]
};

module.exports = {
  "@context": "https://w3id.org/security/v2",
  "id": "https://example.com/i/alice",
  "capabilityInvocation": [
    {
      "type": "Ed25519SignatureCapabilityInvocation2018",
      "publicKey": {
        "@context": "https://w3id.org/security/v2",
        "id": "https://example.com/i/alice/keys/1",
        "type": "Ed25519VerificationKey2018",
        "owner": "https://example.com/i/alice",
        "publicKeyBase58": "GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq",
        "privateKeyBase58": "3Mmk4UzTRJTEtxaKk61LxtgUxAa2Dg36jF6VogPtRiKvfpsQWKPCLesKSV182RMmvMJKk6QErH3wgdHp8itkSSiF"
      }
    }
  ],
  "capabilityDelegation": [
    {
      "type": "Ed25519ignatureCapabilityDelegation2018",
      "publicKey": {
        "@context": "https://w3id.org/security/v2",
        "id": "https://example.com/i/alice/keys/1",
        "type": "Ed25519VerificationKey2018",
        "owner": "https://example.com/i/alice",
        "publicKeyBase58": "GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq",
        "privateKeyBase58": "3Mmk4UzTRJTEtxaKk61LxtgUxAa2Dg36jF6VogPtRiKvfpsQWKPCLesKSV182RMmvMJKk6QErH3wgdHp8itkSSiF"
      }
    }
  ]
};

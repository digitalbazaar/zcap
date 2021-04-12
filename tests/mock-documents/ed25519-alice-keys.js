module.exports = {
  "@context": "https://w3id.org/security/v2",
  "id": "https://example.com/i/alice",
  "verificationMethod": [
    {
      "@context": "https://w3id.org/security/v2",
      "id": "https://example.com/i/alice/keys/1",
      "type": "Ed25519VerificationKey2018",
      "controller": "https://example.com/i/alice",
      "publicKeyBase58": "GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq",
      "privateKeyBase58": "3Mmk4UzTRJTEtxaKk61LxtgUxAa2Dg36jF6VogPtRiKvfpsQWKPCLesKSV182RMmvMJKk6QErH3wgdHp8itkSSiF"
    }
  ],
  "capabilityInvocation": ["https://example.com/i/alice/keys/1"],
  "capabilityDelegation": ["https://example.com/i/alice/keys/1"]
};

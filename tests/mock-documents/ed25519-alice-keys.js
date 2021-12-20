module.exports = {
  "@context": [
    "https://w3id.org/security/v2",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "https://example.com/i/alice",
  "verificationMethod": [
    {
      "id": "https://example.com/i/alice/keys/1",
      "type": "Ed25519VerificationKey2020",
      "controller": "https://example.com/i/alice",
      "publicKeyMultibase": "z6MkvRsV39xVQc8HevAQwCqEw18DwrEtzVLz8NJY15NtfMmD",
      "privateKeyMultibase": "zrv2zfksN9F1MiYpTVoLjZKks7UArP87c1dKbdkzXkMTwtoAYadt7ozJEVZwQpcroQruoLxY7kESHpnVyJ1a6bbSVK9"
    }
  ],
  "capabilityInvocation": [
    "https://example.com/i/alice/keys/1"
  ],
  "capabilityDelegation": [
    "https://example.com/i/alice/keys/1"
  ]
};

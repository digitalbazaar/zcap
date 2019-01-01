module.exports = {
  "@context": "https://w3id.org/security/v2",
  "id": "https://example.com/i/bob",
  "capabilityInvocation": [
    {
      "id": "https://example.com/i/bob/keys/1",
      "type": "Ed25519VerificationKey2018",
      "controller": "https://example.com/i/bob",
      "publicKeyBase58": "CXbgG2vPnd8FWLAZHoLRn3s7PRwehWsoMu6v1HhN9brA",
      "privateKeyBase58": "3LftyxxRPxMFXwVChk14HDybE2VnBnPWaLX31WreZwc8V8xCCuoGL7dcyxnwkFXa8D7CZBwAGWj54yqoaxa7gUne"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "https://example.com/i/bob/keys/2",
      "type": "Ed25519VerificationKey2018",
      "controller": "https://example.com/i/bob",
      "publicKeyBase58": "CXbgG2vPnd8FWLAZHoLRn3s7PRwehWsoMu6v1HhN9brA",
      "privateKeyBase58": "3LftyxxRPxMFXwVChk14HDybE2VnBnPWaLX31WreZwc8V8xCCuoGL7dcyxnwkFXa8D7CZBwAGWj54yqoaxa7gUne"
    }
  ]
};

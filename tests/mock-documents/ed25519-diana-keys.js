module.exports = {
  "@context": "https://w3id.org/security/v2",
  "id": "https://example.com/i/diana",
  "capabilityInvocation": [
    {
      "id": "https://example.com/i/diana/keys/1",
      "type": "Ed25519VerificationKey2018",
      "controller": "https://example.com/i/diana",
      "publicKeyBase58": "8VkLC59zjqEAvyuqc1XPJsQyBbR6qABB32wH1aSeV9Jf",
      "privateKeyBase58": "4M2Ly3iFehEffeoYwebkiRbeb99WbGJzv3hzw4jrtRXcwSF4BKWM9z84p5es8GYYSgt7N1RAAp8HhBLZiRbxaKHq"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "https://example.com/i/diana/keys/2",
      "type": "Ed25519VerificationKey2018",
      "controller": "https://example.com/i/diana",
      "publicKeyBase58": "8VkLC59zjqEAvyuqc1XPJsQyBbR6qABB32wH1aSeV9Jf",
      "privateKeyBase58": "4M2Ly3iFehEffeoYwebkiRbeb99WbGJzv3hzw4jrtRXcwSF4BKWM9z84p5es8GYYSgt7N1RAAp8HhBLZiRbxaKHq"
    }
  ]
};

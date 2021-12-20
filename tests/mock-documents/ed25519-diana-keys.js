module.exports = {
  "@context": [
    "https://w3id.org/security/v2",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "https://example.com/i/diana",
  "capabilityInvocation": [
    {
      "id": "https://example.com/i/diana/keys/1",
      "type": "Ed25519VerificationKey2020",
      "controller": "https://example.com/i/diana",
      "publicKeyMultibase": "z6Mkmx1NnKQS5Nie3UkYHaVE9xxy1AgxF3RXj3rCqrQfQN63",
      "privateKeyMultibase": "zrv3yvMmvs3EkVyb9j2YJ9jWQ2dopxcVCHXWQFG7v6Kvf6VS9xHZ7w97ZkKK1UMxebdS8vkA2m9kpu8WXLm9oJoaMtj"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "https://example.com/i/diana/keys/2",
      "type": "Ed25519VerificationKey2020",
      "controller": "https://example.com/i/diana",
      "publicKeyMultibase": "z6Mkmx1NnKQS5Nie3UkYHaVE9xxy1AgxF3RXj3rCqrQfQN63",
      "privateKeyMultibase": "zrv3yvMmvs3EkVyb9j2YJ9jWQ2dopxcVCHXWQFG7v6Kvf6VS9xHZ7w97ZkKK1UMxebdS8vkA2m9kpu8WXLm9oJoaMtj"
    }
  ]
};

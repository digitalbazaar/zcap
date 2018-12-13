module.exports = {
  "@context": ["https://w3id.org/did/v0.11", "https://w3id.org/veres-one/v1"],
  "id": "did:v1:test:nym:8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa",
  "authentication": [
    {
      "id": "did:v1:test:nym:8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa#authn-key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa",
      "publicKeyBase58": "8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa",
      "privateKeyBase58": "2zKdDUaipASwDLmn9TS4GPFv8gQ2iu1rVB4D7Juyd4kap8D9H9U5vsVgJssz53w9djNAJVUVGMnrkah6zaCDEMqz"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "did:v1:test:nym:8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa#ocap-grant-key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa",
      "publicKeyBase58": "E68w5N8gZYoemxnmJrQWwA4fTSjc5KUTMQ3Z3DJhk95C",
      "privateKeyBase58": "4kVqpZWb5L5MaBVDGrhgANq8jiQe9LriXwvwH18i4tZUwe4tgDLUipa2wTdb9bmfmFiPyJLUj4Emb6wEkNUjaKzJ"
    }
  ],
  "capabilityInvocation": [
    {
      "id": "did:v1:test:nym:8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa#ocap-invoke-key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa",
      "publicKeyBase58": "4sjfmLbFgKiZUFPAo9tkMpz2Hb2gvyxzmGMnaHJaBgMi",
      "privateKeyBase58": "4kwqy7hsmDYYiHVH1CBir4vSQfte2L2QZUZx1nxRwv1rbYG3ieEk3qvekctamQQk8kzBdyHmNgY4VVpBMS3KVfME"
    }
  ]
}

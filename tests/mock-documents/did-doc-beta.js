module.exports = {
  "@context": ["https://w3id.org/did/v0.11", "https://w3id.org/veres-one/v1"],
  "id": "did:v1:test:nym:E9VV25zZbvGpYfArYLmwSCqT1aNjeDJmEe2K75gWghDo",
  "authentication": [
    {
      "id": "did:v1:test:nym:E9VV25zZbvGpYfArYLmwSCqT1aNjeDJmEe2K75gWghDo#authn-key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:E9VV25zZbvGpYfArYLmwSCqT1aNjeDJmEe2K75gWghDo",
      "publicKeyBase58": "E9VV25zZbvGpYfArYLmwSCqT1aNjeDJmEe2K75gWghDo",
      "privateKeyBase58": "5utFD9KtJLzsWCyW4NjG88C3c9Be2qVHM86vvptJAKJxbphCX4CEZJfqbw8B6p42YW5mRTXKC6M7vgkjgAaRhsp1"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "did:v1:test:nym:E9VV25zZbvGpYfArYLmwSCqT1aNjeDJmEe2K75gWghDo#ocap-grant-key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:E9VV25zZbvGpYfArYLmwSCqT1aNjeDJmEe2K75gWghDo",
      "publicKeyBase58": "4FCS8xaVwJtkYeN3GwJYk93YLQBQ6Zogws4R2CJXNyCD",
      "privateKeyBase58": "5rQjc9wPFMmvDWNf7cgWKhJAwB4W22dgHBBakekVver12ijeqxcauz4h9TkFzmZcirU16HdZ3ocPrrEar2JS1kim"
    }
  ],
  "capabilityInvocation": [
    {
      "id": "did:v1:test:nym:E9VV25zZbvGpYfArYLmwSCqT1aNjeDJmEe2K75gWghDo#ocap-invoke-key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:E9VV25zZbvGpYfArYLmwSCqT1aNjeDJmEe2K75gWghDo",
      "publicKeyBase58": "8uLCnve63B2D9YkyZj1oUpWeLpmFucivczxWobnuZ9DD",
      "privateKeyBase58": "2zf3wuR7pe4FYc1EB7wLJSHnFUJz6LMoAH8aV6wxMH6ZHcwxYM825XjD95gaTVp9HR8P1sjgmgWGykj8KP1mycps"
    }
  ]
};

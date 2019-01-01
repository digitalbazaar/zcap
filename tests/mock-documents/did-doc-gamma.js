module.exports = {
  "@context": ["https://w3id.org/did/v0.11", "https://w3id.org/veres-one/v1"],
  "id": "did:v1:test:nym:9kjA8yct16UzvpTgynCECTuPEoozn8s36FxRxUJv6xhC",
  "authentication": [
    {
      "id": "did:v1:test:nym:9kjA8yct16UzvpTgynCECTuPEoozn8s36FxRxUJv6xhC#authn-key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:9kjA8yct16UzvpTgynCECTuPEoozn8s36FxRxUJv6xhC",
      "publicKeyBase58": "9kjA8yct16UzvpTgynCECTuPEoozn8s36FxRxUJv6xhC",
      "privateKeyBase58": "5YsLYhXmqcw2WKSicZob14EURohAWeYPkxrMQonbC2BUjM7Qguro1D1UCLQgoaqt3VaJFxFjj6Mg8fhL5TjTw3y8"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "did:v1:test:nym:9kjA8yct16UzvpTgynCECTuPEoozn8s36FxRxUJv6xhC#ocap-grant-key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:9kjA8yct16UzvpTgynCECTuPEoozn8s36FxRxUJv6xhC",
      "publicKeyBase58": "2gAygUyQ4MnxZ1UyVVbvJ3QHEsQB6fywDToe4Lbar3hh",
      "privateKeyBase58": "bTHLTVJDARpc9NmbBhgcPsnh2ZFsCwKoV8mKvq5wFQ759ALjJqgZegwTE2sh23cLfw4jw7bgSN3waCWkZMc85Dh"
    }
  ],
  "capabilityInvocation": [
    {
      "id": "did:v1:test:nym:9kjA8yct16UzvpTgynCECTuPEoozn8s36FxRxUJv6xhC#ocap-invoke-key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:9kjA8yct16UzvpTgynCECTuPEoozn8s36FxRxUJv6xhC",
      "publicKeyBase58": "EVRh8DSLecgqnb7C9gtvwGiVUgeDf8inbdL9YioK93dR",
      "privateKeyBase58": "2ET7HYSiSFyHbCZozHiXH89rDfJZ3G2BPsvtQyi7HhPaRCCv2RkDtkUydgYsTAeER8nAqwbRnx43tqxktNDhbhMq"
    }
  ]
};

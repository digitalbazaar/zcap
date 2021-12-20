module.exports = {
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/veres-one/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:v1:test:nym:9kjA8yct16UzvpTgynCECTuPEoozn8s36FxRxUJv6xhC",
  "authentication": [
    {
      "id": "did:v1:test:nym:9kjA8yct16UzvpTgynCECTuPEoozn8s36FxRxUJv6xhC#authn-key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:9kjA8yct16UzvpTgynCECTuPEoozn8s36FxRxUJv6xhC",
      "publicKeyMultibase": "z6MkoCzCjDsKLdyU3KJPfMA53ZTP4P5rC27PnGsMnkGw2BUa",
      "privateKeyMultibase": "zrv5BmMMagZRgCLRpNCDDMZo2fTeVWGQaWvMKPcbf94EFkME4pe4iHaxndihGEBdxty2wcw3ybjK78Wx1hXWqSJw6a2"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "did:v1:test:nym:9kjA8yct16UzvpTgynCECTuPEoozn8s36FxRxUJv6xhC#ocap-grant-key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:9kjA8yct16UzvpTgynCECTuPEoozn8s36FxRxUJv6xhC",
      "publicKeyMultibase": "z6Mkg8S2GjDqPuHRfWKgB4Zm98xH4Sg2WZEHuUiZtcZbmGV5",
      "privateKeyMultibase": "zrv1EMJ9Le5oDh8XeJFBqFfQNJmuiNMm8urPqg2WnBYyUxyZrsa77GUXEKBx9rNXQ6hL7yhXxTbGT8tkvCiBw4T87pb"
    }
  ],
  "capabilityInvocation": [
    {
      "id": "did:v1:test:nym:9kjA8yct16UzvpTgynCECTuPEoozn8s36FxRxUJv6xhC#ocap-invoke-key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:9kjA8yct16UzvpTgynCECTuPEoozn8s36FxRxUJv6xhC",
      "publicKeyMultibase": "z6MkswgjiTgmzABJu5wtqFrmnNGVJFv551y9HeF5NzmL4GQo",
      "privateKeyMultibase": "zrv1sM86RbW2KEbWhVHawGW56aqSM7ewBzhzEU9bq4aKvxSuuv9QEB1rL7E8cNNHYhKQapodxwRNxptiBxxKjvYbjxj"
    }
  ]
};

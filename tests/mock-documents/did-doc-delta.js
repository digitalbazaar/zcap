export default {
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/veres-one/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:v1:test:nym:9iofLVptQB9BwZ484xTHbvwfxEmN2ByNR8hSXE2uho88",
  "authentication": [
    {
      "id": "did:v1:test:nym:9iofLVptQB9BwZ484xTHbvwfxEmN2ByNR8hSXE2uho88#authn-key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:9iofLVptQB9BwZ484xTHbvwfxEmN2ByNR8hSXE2uho88",
      "publicKeyMultibase": "z6MkoB4hvk5Kjidf43tpkXR8T2Vfmp3DS5Dj79cNMVzvd1uW",
      "privateKeyMultibase": "zrv2mUWBfwDx14WijJBV5BwegzWozbktapTBouz3f8NE5mxnPsSpKeYLji2HqYHe6oTiDHgh3atgPt1GcY66Mvqqatc"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "did:v1:test:nym:9iofLVptQB9BwZ484xTHbvwfxEmN2ByNR8hSXE2uho88#ocap-grant-key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:9iofLVptQB9BwZ484xTHbvwfxEmN2ByNR8hSXE2uho88",
      "publicKeyMultibase": "z6MkihK2sj6aJMzTYWLpZqUJ5m8yR2gRBNZ7bPByyp6AnCWW",
      "privateKeyMultibase": "zrv2mw9unbzbjpVgwvJ985qSJTK8vWKTuoA3UmBYkzkHQKTnHrVaChuoQwKWNApBrnfoA5RKjtKJksBAqLdByFmCseJ"
    }
  ],
  "capabilityInvocation": [
    {
      "id": "did:v1:test:nym:9iofLVptQB9BwZ484xTHbvwfxEmN2ByNR8hSXE2uho88#ocap-invoke-key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:9iofLVptQB9BwZ484xTHbvwfxEmN2ByNR8hSXE2uho88",
      "publicKeyMultibase": "z6Mkkd2BQPJswFW53GBgJFz6E1jdfp9q7UyCJDoSFNxubFVB",
      "privateKeyMultibase": "zrv3WPqSabzGxzDSN2KYyifcd5iXGyG4ag1Dg51cy2Co4vqJLCDyoMyNVUDcBrfETVFK1ECJJzJASWnifPSgGkpfbDB"
    }
  ]
};

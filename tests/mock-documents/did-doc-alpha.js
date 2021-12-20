module.exports = {
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/veres-one/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:v1:test:nym:8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa",
  "authentication": [
    {
      "id": "did:v1:test:nym:8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa#authn-key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa",
      "publicKeyMultibase": "z6MkmiaTWH2pqNm3uTGvfFAYyH5rFoZzkfLksiTJM2KDRmzx",
      "privateKeyMultibase": "zrv2dDe2MjWQDiF8qhFk6z34MguMND8cpzP5XbUJAGSfJKTJqvNewtstT7voohUuRzEdBQo6WpUrNZhZvhJRwu4EQSt"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "did:v1:test:nym:8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa#ocap-grant-key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa",
      "publicKeyMultibase": "z6MksYPyfcP7u6J7tTdTzRNMnFcfH21TVCip3QxUsVGifMra",
      "privateKeyMultibase": "zrv4PPrdSfNfPLfVgQgsWFexMG7xQDk3GqF8JUCTrVB788MSMn841mGgQCHSPT5yypkkhm2mKgUK51cQSwSBkBaaNbC"
    }
  ],
  "capabilityInvocation": [
    {
      "id": "did:v1:test:nym:8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa#ocap-invoke-key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa",
      "publicKeyMultibase": "z6MkiKziMaqh1sD2akDsUirbCvY27AJYLsDMTHGiQZGb6u96",
      "privateKeyMultibase": "zrv4PqrmzrfMGordnQkbqjhe3MRdMhjvFzw9q7DCeJtz9aj6FyH6SfY1RYuFYi5bnTq8D2pRzdkxhJuJqpNnokAVhx8"
    }
  ]
};

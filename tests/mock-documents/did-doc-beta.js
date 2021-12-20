module.exports = {
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/veres-one/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:v1:test:nym:E9VV25zZbvGpYfArYLmwSCqT1aNjeDJmEe2K75gWghDo",
  "authentication": [
    {
      "id": "did:v1:test:nym:E9VV25zZbvGpYfArYLmwSCqT1aNjeDJmEe2K75gWghDo#authn-key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:E9VV25zZbvGpYfArYLmwSCqT1aNjeDJmEe2K75gWghDo",
      "publicKeyMultibase": "z6MksbkXcLEzwTmHfA1ZDujnHJPSq9eb46Z7vewEwMeXbv1B",
      "privateKeyMultibase": "zrv5YnG22UftQGBRhtyf2HEv6d2ppzjvmTowUeC7gEmCYsq6YQRtrd2WtJ66rwfwC77Xx8QDUsJn77xk2kw7YHGhvQu"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "did:v1:test:nym:E9VV25zZbvGpYfArYLmwSCqT1aNjeDJmEe2K75gWghDo#ocap-grant-key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:E9VV25zZbvGpYfArYLmwSCqT1aNjeDJmEe2K75gWghDo",
      "publicKeyMultibase": "z6MkhhTUjCpwGrPDf9CjxWGPbEbY9yTFWT43dsyLrUGYJByb",
      "privateKeyMultibase": "zrv5VJkR36AqR3E91J8iGEV7fjA9rsbuxcCsXiqwW6xxtQsXSStDm3NsZgwePZkq9chiJWdtJyYdpPEgCEnHQ1H1oKf"
    }
  ],
  "capabilityInvocation": [
    {
      "id": "did:v1:test:nym:E9VV25zZbvGpYfArYLmwSCqT1aNjeDJmEe2K75gWghDo#ocap-invoke-key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:E9VV25zZbvGpYfArYLmwSCqT1aNjeDJmEe2K75gWghDo",
      "publicKeyMultibase": "z6MknMbFPAtXNiWgG3bgFHyeKv4eAQ37KVyHK1sSdskvUMzb",
      "privateKeyMultibase": "zrv2dZ4knZuQhKZU6vhmmVK6QimUA85zGLKkdfqfxJRPWfRnLfBv9Yp37MTe1W5HssEGsB1ou5gMhH7o6jKkkicyfRm"
    }
  ]
};

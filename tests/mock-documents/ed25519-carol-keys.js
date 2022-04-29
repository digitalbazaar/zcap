export default {
  "@context": [
    "https://w3id.org/security/v2",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "https://example.com/i/carol",
  "capabilityInvocation": [
    {
      "id": "https://example.com/i/carol/keys/1",
      "type": "Ed25519VerificationKey2020",
      "controller": "https://example.com/i/carol",
      "publicKeyMultibase": "z6Mku8G8HT5jLgprB1u8GHsc9b98NDqeQMys2i1zXboCqxrZ",
      "privateKeyMultibase": "zrv51RAzPCYDawUCCNR8JAGd4SNvhaTPWodCbBKQu4CjsKjyG7M3bNLLY4VFgiCmk3YbV1gxpqrvoGvTbVw8piitidK"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "https://example.com/i/carol/keys/2",
      "type": "Ed25519VerificationKey2020",
      "controller": "https://example.com/i/carol",
      "publicKeyMultibase": "z6Mku8G8HT5jLgprB1u8GHsc9b98NDqeQMys2i1zXboCqxrZ",
      "privateKeyMultibase": "zrv51RAzPCYDawUCCNR8JAGd4SNvhaTPWodCbBKQu4CjsKjyG7M3bNLLY4VFgiCmk3YbV1gxpqrvoGvTbVw8piitidK"
    }
  ]
};

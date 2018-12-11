/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {
  owners,
  didDocs,
  privateDidDocs,
  testLoader,
  capabilities,
  addToLoader,
} = require('./mock-data');
const {Owner} = require('./helpers');

module.exports = function(options) {

  const {expect, jsonld, jsigs, ocapld} = options;

  // setup
  jsonld.documentLoader = testLoader(jsonld.documentLoader);
  jsigs.use('jsonld', jsonld);

  // helper

  const alice = new Owner(owners.alice);
  const bob = new Owner(owners.bob);
  const carol = new Owner(owners.carol);
  const diana = new Owner(owners.diana);
  const alpha = new Owner(privateDidDocs.alpha);
  const beta = new Owner(privateDidDocs.beta);
  const gamma = new Owner(privateDidDocs.gamma);
  const delta = new Owner(privateDidDocs.delta);

  // run tests
  describe('ocapld.js', () => {
    context('Common', () => {
      describe('installation of library', () => {
        it('should successfully install the ocapld.js library', done => {
          ocapld.install(jsigs);
          expect(jsigs.proofPurposes.use('capabilityInvocation')).to.exist;
          expect(jsigs.proofPurposes.use('capabilityDelegation')).to.exist;
          done();
        });
      });
      describe('signing with capabilityInvocation', () => {
        beforeEach(() => {
          ocapld.install(jsigs);
        });
        it('should successfully sign w/ capabilityInvocation' +
          ' proofPurpose', async () => {
          let err;
          let signedDocument;
          try {
            const {privateKeyBase58} = alice.get('publicKey', 0);
            signedDocument = await jsigs.sign(capabilities.root.alpha, {
              algorithm: 'Ed25519Signature2018',
              creator: alice.get('publicKey', 0).id,
              privateKeyBase58,
              purpose: 'capabilityInvocation',
              purposeParameters: {
                capability: capabilities.root.alpha.id
              },
            });
          } catch(e) {
            err = e;
          }
          expect(signedDocument).to.exist;
          expect(err).to.be.undefined;
        });
        it('should fail signing with capabilityInvocation proofPurpose and' +
          ' missing purposeOptions', async () => {
          let err;
          let signedDocument;
          try {
            const {privateKeyBase58} = alice.get('publicKey', 0);
            signedDocument = await jsigs.sign(capabilities.root.alpha, {
              algorithm: 'Ed25519Signature2018',
              creator: alice.get('publicKey', 0).id,
              privateKeyBase58,
              purpose: 'capabilityInvocation'
            });
          } catch(e) {
            err = e;
          }
          expect(signedDocument).to.be.undefined;
          expect(err).to.exist;
          expect(err.message).to.equal('Please specify "capability"; the URI' +
            ' of the capability to be invoked.');
        });
        it('should successfully sign with capabilityDelegation proofPurpose',
          async () => {
            let err;
            let signedDocument;
            try {
              const {privateKeyBase58} = alice.get('publicKey', 0);
              signedDocument = await jsigs.sign(capabilities.root.alpha, {
                algorithm: 'Ed25519Signature2018',
                creator: alice.get('publicKey', 0).id,
                privateKeyBase58,
                purpose: 'capabilityDelegation',
                purposeParameters: {
                  capabilityChain: [capabilities.root.alpha.id]
                }
              });
            } catch(e) {
              err = e;
            }
            expect(signedDocument).to.exist;
            expect(err).to.be.undefined;
          });
      });
      describe('signing with capabilityDelegation', () => {
        beforeEach(() => {
          ocapld.install(jsigs);
        });
        it('should successfully sign with capabilityDelegation proofPurpose',
          async () => {
            let err;
            let signedDocument;
            try {
              const {privateKeyBase58} = alice.get('publicKey', 0);
              signedDocument = await jsigs.sign(capabilities.root.alpha, {
                algorithm: 'Ed25519Signature2018',
                creator: alice.get('publicKey', 0).id,
                privateKeyBase58,
                purpose: 'capabilityDelegation',
                purposeParameters: {
                  capabilityChain: [capabilities.root.alpha.id]
                }
              });
            } catch(e) {
              err = e;
            }
            expect(signedDocument).to.exist;
            expect(err).to.be.undefined;
          });
      });
    });
    context('Verifying capability chains', () => {
      describe('Invoker and Delegator as keys', () => {
        beforeEach(() => {
          ocapld.install(jsigs);
        });
        it('should successfully verify a self invoked root' +
          ' capability', async () => {
          let err;
          let res;
          try {
            const {privateKeyBase58} = alice.get('publicKey', 0);
            // Invoke the root capability using the invoker key
            const capInv = await jsigs.sign(capabilities.root.alpha, {
              algorithm: 'Ed25519Signature2018',
              creator: alice.get('publicKey', 0).id,
              privateKeyBase58,
              purpose: 'capabilityInvocation',
              purposeParameters: {
                capability: capabilities.root.alpha.id
              }
            });
            addToLoader({doc: {...capInv, id: 'urn:foo'}});
            // Verify a self invoked capability
            res = await jsigs.verify(capInv, {
              purpose: 'capabilityInvocation',
              purposeParameters: {
                expectedTarget: capabilities.root.alpha.id
              }
            });
          } catch(e) {
            err = e;
          }
          expect(res).to.exist;
          expect(err).to.not.exist;
          expect(res.verified).to.be.true;
        });
        it('should successfully verify a capability chain of depth 2',
          async () => {
            let err;
            let res;
            try {
              // Create a delegated capability
              //   1. Parent capability should point to the root capability
              //   2. The invoker should be Bob's invocation key
              const newCapability = {
                '@context': 'https://w3id.org/security/v2',
                id: 'https://whatacar.example/a-fancy-car/proc/7a397d7b',
                parentCapability: capabilities.root.alpha.id,
                invoker: bob.get('capabilityInvocation', 0).publicKey.id
              };
              let {privateKeyBase58} = alice.get('publicKey', 0);
              //  3. Sign the delegated capability with Alice's delegation key
              //     that was specified as the delegator in the root capability
              const capDel = await jsigs.sign(newCapability, {
                algorithm: 'Ed25519Signature2018',
                creator: alice.get('publicKey', 0).id,
                privateKeyBase58,
                purpose: 'capabilityDelegation',
                purposeParameters: {
                  capabilityChain: [newCapability.parentCapability]
                }
              });
              addToLoader({doc: capDel});
              // Invoke the capability that was delegated
              const capabilityInvocation = {
                '@context': 'https://w3id.org/security/v2',
                id: 'https://example.org/bob/caps#1'
              };
              ({privateKeyBase58} = bob.get(
                'capabilityInvocation', 0).publicKey);
              //   4. Use Bob's invocation key that was assigned as invoker in
              //      the delegated capability
              //   5. The invoker should be Bob's invocation key
              const capInv = await jsigs.sign(capabilityInvocation, {
                algorithm: 'Ed25519Signature2018',
                creator: bob.get('capabilityInvocation', 0).publicKey.id,
                privateKeyBase58,
                purpose: 'capabilityInvocation',
                purposeParameters: {
                  capability:
                    'https://whatacar.example/a-fancy-car/proc/7a397d7b'
                }
              });
              addToLoader({doc: capInv});
              res = await jsigs.verify(capInv, {
                purpose: 'capabilityInvocation',
                purposeParameters: {
                  expectedTarget: capabilities.root.alpha.id
                }
              });
            } catch(e) {
              err = e;
            }
            expect(res).to.exist;
            expect(err).to.not.exist;
            expect(res.verified).to.be.true;
          });
      });
      describe('Invoker and Delegator as controllers', () => {
        beforeEach(() => {
          ocapld.install(jsigs);
        });
        it('should successfully verify a self invoked root' +
          ' capability', async () => {
          let err;
          let res;
          try {
            const {privateKeyBase58} = alice.get('publicKey', 0);
            // Invoke the root capability using the invoker key
            const capInv = await jsigs.sign(capabilities.root.beta, {
              algorithm: 'Ed25519Signature2018',
              creator: alice.get('publicKey', 0).id,
              privateKeyBase58,
              purpose: 'capabilityInvocation',
              purposeParameters: {
                capability: capabilities.root.beta.id
              }
            });
            addToLoader({doc: {...capInv, id: 'urn:foo:1'}});
            // Verify a self invoked capability
            res = await jsigs.verify(capInv, {
              purpose: 'capabilityInvocation',
              purposeParameters: {
                expectedTarget: capabilities.root.beta.id
              }
            });
          } catch(e) {
            err = e;
          }
          expect(res).to.exist;
          expect(err).to.not.exist;
          expect(res.verified).to.be.true;
        });
        it('should successfully verify a self invoked root' +
          ' capability with missing invoker and delegator', async () => {
          let err;
          let res;
          try {
            const {privateKeyBase58, id} =
              alpha.get('capabilityInvocation', 0).publicKey[0];
            // Invoke the root capability using the invoker key
            const doc = {
              id: 'urn:alpha:caps:1',
              '@context': 'https://w3id.org/security/v2'
            };
            const capInv = await jsigs.sign(doc, {
              algorithm: 'Ed25519Signature2018',
              creator: id,
              privateKeyBase58,
              purpose: 'capabilityInvocation',
              purposeParameters: {
                capability: didDocs.alpha.id
              }
            });
            // Verify a self invoked capability
            res = await jsigs.verify(capInv, {
              purpose: 'capabilityInvocation',
              purposeParameters: {
                expectedTarget: didDocs.alpha.id
              }
            });
          } catch(e) {
            err = e;
          }
          expect(res).to.exist;
          expect(err).to.not.exist;
          expect(res.verified).to.be.true;
        });
        it('should successfully verify a capability chain of depth 2',
          async () => {
            let err;
            let res;
            try {
              // Create a delegated capability
              //   1. Parent capability should point to the root capability
              //   2. The invoker should be the id Bob's controller doc
              const newCapability = {
                '@context': 'https://w3id.org/security/v2',
                id: 'https://example.com/caps/bob/1',
                parentCapability: capabilities.root.beta.id,
                invoker: bob.id()
              };
              let {privateKeyBase58} = alice.get('publicKey', 0);
              //  3. Sign the delegated capability with Alice's delegation key
              //     that was specified as the delegator in the root capability
              const capDel = await jsigs.sign(newCapability, {
                algorithm: 'Ed25519Signature2018',
                creator: alice.get('publicKey', 0).id,
                privateKeyBase58,
                purpose: 'capabilityDelegation',
                purposeParameters: {
                  capabilityChain: [newCapability.parentCapability]
                }
              });
              addToLoader({doc: capDel});
              // Invoke the capability that was delegated
              const capabilityInvocation = {
                '@context': 'https://w3id.org/security/v2',
                id: 'https://example.com/caps/bob/2'
              };
              ({privateKeyBase58} = bob.get(
                'capabilityInvocation', 0).publicKey);
              //   4. Use Bob's invocation key that can be found in Bob's
              //      controller document of keys
              //   5. The invoker should be the id Bob's document that contains
              //      key material
              const capInv = await jsigs.sign(capabilityInvocation, {
                algorithm: 'Ed25519Signature2018',
                creator: bob.get('capabilityInvocation', 0).publicKey.id,
                privateKeyBase58,
                purpose: 'capabilityInvocation',
                purposeParameters: {
                  capability: 'https://example.com/caps/bob/1'
                }
              });
              addToLoader({doc: capInv});
              res = await jsigs.verify(capInv, {
                purpose: 'capabilityInvocation',
                purposeParameters: {
                  expectedTarget: capabilities.root.beta.id
                }
              });
            } catch(e) {
              err = e;
            }
            expect(res).to.exist;
            expect(err).to.not.exist;
            expect(res.verified).to.be.true;
          });
        it('should successfully verify a capability chain of depth 2 and a ' +
          'valid caveat on one capability', async () => {
          let err;
          let res;
          try {
            // Create a delegated capability
            //   1. Parent capability should point to the root capability
            //   2. The invoker should be the id Bob's controller doc
            //   3. Add a caveat that states the capability should expire an
            //      hour from now
            const expires = new Date();
            expires.setHours(expires.getHours() + 1);
            const newCapability = {
              '@context': 'https://w3id.org/security/v2',
              id: 'https://example.com/caps/bob/3',
              parentCapability: capabilities.root.beta.id,
              caveat: [{
                type: 'https://example.org/ocap/v1#ExpireAt',
                expires: expires.toISOString()
              }],
              invoker: bob.id()
            };
            let {privateKeyBase58} = alice.get('publicKey', 0);
            //  4. Sign the delegated capability with Alice's delegation key
            //     that was specified as the delegator in the root capability
            const capDel = await jsigs.sign(newCapability, {
              algorithm: 'Ed25519Signature2018',
              creator: alice.get('publicKey', 0).id,
              privateKeyBase58,
              purpose: 'capabilityDelegation',
              purposeParameters: {
                capabilityChain: [newCapability.parentCapability]
              }
            });
            addToLoader({doc: capDel});
            // Invoke the capability that was delegated
            const capabilityInvocation = {
              '@context': 'https://w3id.org/security/v2',
              id: 'https://example.com/caps/bob/4'
            };
            ({privateKeyBase58} = bob.get('capabilityInvocation', 0).publicKey);
            //   5. Use Bob's invocation key that can be found in Bob's
            //      controller document of keys
            //   6. The invoker should be the id Bob's document that contains
            //      key material
            const capInv = await jsigs.sign(capabilityInvocation, {
              algorithm: 'Ed25519Signature2018',
              creator: bob.get('capabilityInvocation', 0).publicKey.id,
              privateKeyBase58,
              purpose: 'capabilityInvocation',
              purposeParameters: {
                capability: 'https://example.com/caps/bob/3'
              }
            });
            addToLoader({doc: capInv});
            res = await jsigs.verify(capInv, {
              purpose: 'capabilityInvocation',
              purposeParameters: {
                expectedTarget: capabilities.root.beta.id
              }
            });
          } catch(e) {
            err = e;
          }
          expect(res).to.exist;
          expect(err).to.not.exist;
          expect(res.verified).to.be.true;
        });
        it('should fail to verify a capability chain of depth 2 and a ' +
          'valid expiration caveat on one capability', async () => {
          let err;
          let res;
          try {
            // Create a delegated capability
            //   1. Parent capability should point to the root capability
            //   2. The invoker should be the id Bob's controller doc
            //   3. Add a caveat that states the capability should expire now
            const newCapability = {
              '@context': 'https://w3id.org/security/v2',
              id: 'https://example.com/caps/bob/5',
              parentCapability: capabilities.root.beta.id,
              caveat: [{
                type: 'https://example.org/ocap/v1#ExpireAt',
                expires: new Date().toISOString()
              }],
              invoker: bob.id()
            };
            let {privateKeyBase58} = alice.get('publicKey', 0);
            //  4. Sign the delegated capability with Alice's delegation key
            //     that was specified as the delegator in the root capability
            const capDel = await jsigs.sign(newCapability, {
              algorithm: 'Ed25519Signature2018',
              creator: alice.get('publicKey', 0).id,
              privateKeyBase58,
              purpose: 'capabilityDelegation',
              purposeParameters: {
                capabilityChain: [newCapability.parentCapability]
              }
            });
            addToLoader({doc: capDel});
            // Invoke the capability that was delegated
            const capabilityInvocation = {
              '@context': 'https://w3id.org/security/v2',
              id: 'https://example.com/caps/bob/6'
            };
            ({privateKeyBase58} = bob.get('capabilityInvocation', 0).publicKey);
            //   5. Use Bob's invocation key that can be found in Bob's
            //      controller document of keys
            //   6. The invoker should be the id Bob's document that contains
            //      key material
            const capInv = await jsigs.sign(capabilityInvocation, {
              algorithm: 'Ed25519Signature2018',
              creator: bob.get('capabilityInvocation', 0).publicKey.id,
              privateKeyBase58,
              purpose: 'capabilityInvocation',
              purposeParameters: {
                capability: 'https://example.com/caps/bob/5'
              }
            });
            addToLoader({doc: capInv});
            res = await jsigs.verify(capInv, {
              purpose: 'capabilityInvocation',
              purposeParameters: {
                expectedTarget: capabilities.root.beta.id
              }
            });
          } catch(e) {
            err = e;
          }
          expect(res).to.exist;
          expect(err).to.not.exist;
          expect(res.verified).to.be.false;
        });
      });
    });
  });

  return Promise.resolve();
};

/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
/* eslint-disable indent */
module.exports = async function(options) {

'use strict';

const should = require('chai').should();
const {expect, helpers, jsigs, mock, ocapld} = options;

const {
  CapabilityInvocation,
  CapabilityDelegation,
  ExpirationCaveat
} = ocapld;

const {
  Ed25519Signature2018
} = jsigs.suites;

const {
  Ed25519KeyPair,
  SECURITY_CONTEXT_URL
} = jsigs;

const {
  controllers,
  didDocs,
  privateDidDocs,
  capabilities,
  addToLoader,
  testLoader
} = mock;
const {Controller, uuid} = helpers;

// helper:
function clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

const alice = new Controller(controllers.alice);
const bob = new Controller(controllers.bob);
const carol = new Controller(controllers.carol);
// const diana = new Controller(controllers.diana);
const alpha = new Controller(privateDidDocs.alpha);
// const beta = new Controller(privateDidDocs.beta);
// const gamma = new Controller(privateDidDocs.gamma);
// const delta = new Controller(privateDidDocs.delta);

const CONSTANT_DATE = '2018-02-13T21:26:08Z';

// run tests
describe('ocapld.js', () => {
  context('Common', () => {
    describe('sign with capabilityInvocation proof purpose', () => {
      it('should succeed w/key invoker', async () => {
        const doc = clone(mock.exampleDoc);
        const signed = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0)),
            date: CONSTANT_DATE
          }),
          purpose: new CapabilityInvocation({
            capability: capabilities.root.alpha.id
          })
        });
        expect(signed).to.deep.equal(mock.exampleDocWithInvocation.alpha);
      });

      it('should succeed w/controller invoker', async () => {
        const doc = clone(mock.exampleDoc);
        const signed = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0)),
            date: CONSTANT_DATE
          }),
          purpose: new CapabilityInvocation({
            capability: capabilities.root.beta.id
          })
        });
        expect(signed).to.deep.equal(mock.exampleDocWithInvocation.beta);
      });

      it('should fail when missing "capability"', async () => {
        let err;
        try {
          const doc = clone(mock.exampleDoc);
          await jsigs.sign(doc, {
            suite: new Ed25519Signature2018({
              key: new Ed25519KeyPair(alice.get('publicKey', 0))
            }),
            purpose: new CapabilityInvocation()
          });
        } catch(e) {
          err = e;
        }
        expect(err).to.exist;
        expect(err.message).to.equal('"capability" is required.');
      });
    });

    describe('sign with capabilityDelegation proof purpose', () => {
      it('should succeed w/key delegator', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's invocation key
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: 'https://whatacar.example/a-fancy-car/proc/7a397d7b-alpha',
          parentCapability: capabilities.root.alpha.id,
          invoker: bob.get('capabilityInvocation', 0).id
        };
        //  3. Sign the delegated capability with Alice's delegation key
        //     that was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0)),
            date: CONSTANT_DATE
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.alpha.id]
          })
        });
        expect(delegatedCapability).to.deep.equal(capabilities.delegated.alpha);
      });

      it('should succeed w/controller delegator', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's invocation key
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: 'https://whatacar.example/a-fancy-car/proc/7a397d7b-beta',
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key
        //     that was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0)),
            date: CONSTANT_DATE
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        expect(delegatedCapability).to.deep.equal(capabilities.delegated.beta);
      });

      it('should fail when missing "capabilityChain" and "parentCapability"',
        async () => {
        let err;
        try {
          const doc = clone(mock.exampleDoc);
          await jsigs.sign(doc, {
            suite: new Ed25519Signature2018({
              key: new Ed25519KeyPair(alice.get('publicKey', 0))
            }),
            purpose: new CapabilityDelegation()
          });
        } catch(e) {
          err = e;
        }
        expect(err).to.exist;
        expect(err.message).to.equal(
          'Cannot compute capability chain; capability has no ' +
          '"parentCapability".');
      });
    });
  });

  context('Verifying capability chains', () => {
    describe('Invoker and Delegator as keys', () => {
      it('should verify a self-invoked root capability', async () => {
        const result = await jsigs.verify(mock.exampleDocWithInvocation.alpha, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.alpha.id
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify w/array expected target', async () => {
        const result = await jsigs.verify(mock.exampleDocWithInvocation.alpha, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: [capabilities.root.alpha.id]
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify a capability chain of depth 2', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's invocation key
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.alpha.id,
          invoker: bob.get('capabilityInvocation', 0).id
        };
        //  3. Sign the delegated capability with Alice's delegation key
        //     that was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.alpha.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        // verify the delegation chain
        const result = await jsigs.verify(delegatedCapability, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation(),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify a capability chain of depth 2' +
        'when the expectedRootCapability does not match', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's invocation key
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.alpha.id,
          invoker: bob.get('capabilityInvocation', 0).id
        };
        //  3. Sign the delegated capability with Alice's delegation key
        //     that was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.alpha.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        // verify the delegation chain
        const result = await jsigs.verify(delegatedCapability, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation(
            {expectedRootCapability: 'urn:uuid:fake'}),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
      });

      it('should verify invoking a capability chain of depth 2', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's invocation key
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.alpha.id,
          invoker: bob.get('capabilityInvocation', 0).id
        };
        //  3. Sign the delegated capability with Alice's delegation key
        //     that was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.alpha.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   4. Use Bob's invocation key that was assigned as invoker in
        //      the delegated capability
        //   5. The invoker should be Bob's invocation key
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.alpha.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });
    });

    describe('Invoker and Delegator as controllers', () => {
      it('should verify a self-invoked root capability', async () => {
        const result = await jsigs.verify(mock.exampleDocWithInvocation.beta, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail verifying a root capability as delegated', async () => {
        // root has no invoker and no keys
        const doc = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid()
        };
        const result = await jsigs.verify(doc, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation(),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
      });

      it('should verify a self-invoked root ' +
        'capability with missing invoker and delegator', async () => {
        // invoke the root capability using the invoker key
        const doc = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid()
        };
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alpha.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: didDocs.alpha.id
          })
        });
        // verify a self invoked capability
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: didDocs.alpha.id
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify a invoking root capability w/ separate target when ' +
        'a matching `expectedRootCapability` is given', async () => {
        const root = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          invocationTarget: uuid(),
          invoker: bob.id()
        };
        addToLoader({doc: root});
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: root.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: root.invocationTarget,
            expectedRootCapability: root.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify a root capability w/ separate target when ' +
        'a matching `expectedRootCapability` array is given', async () => {
        const root = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          invocationTarget: uuid(),
          invoker: bob.id()
        };
        addToLoader({doc: root});
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: root.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: root.invocationTarget,
            expectedRootCapability: [root.id],
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should NOT verify a root capability w/ separate target when ' +
        '`expectedRootCapability` is not a URI', async () => {
        const root = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          invocationTarget: uuid(),
          invoker: bob.id()
        };
        addToLoader({doc: root});
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: root.id
          })
        });
        // truncate the urn from the start of the root id
        // this will make it an invalid expectedRootCapability
        const expectedRootCapability = [root.id.replace('urn:uuid:', '')];
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: root.invocationTarget,
            expectedRootCapability,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
      });

      it('should NOT verify a root capability w/ separate target when ' +
        'no `expectedRootCapability` is given', async () => {
        const root = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          invocationTarget: uuid(),
          invoker: bob.id()
        };
        addToLoader({doc: root});
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: root.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: root.invocationTarget,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        // TODO: assert more about result.error
      });

      it('should verify a root capability w/ multiple controllers',
        async () => {
        const root = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          invocationTarget: uuid(),
          controller: ['urn:other', bob.id()],
        };
        addToLoader({doc: root});
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: root.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: root.invocationTarget,
            expectedRootCapability: root.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify a root capability w/ multiple invokers', async () => {
        const root = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          invocationTarget: uuid(),
          invoker: ['urn:other', bob.id()],
        };
        addToLoader({doc: root});
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: root.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: root.invocationTarget,
            expectedRootCapability: root.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify a capability chain of depth 2', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        const result = await jsigs.verify(delegatedCapability, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation(),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify invoking a capability chain of depth 2', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   4. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   5. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail if expectedRootCapability does not match', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   4. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   5. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            expectedRootCapability: 'urn:this-should-matter',
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
      });

      it('should fail if target does not match root ID', async () => {
        const mockRootCapability = clone(capabilities.root.beta);
        mockRootCapability.id = 'urn:bar';
        mockRootCapability.invocationTarget = 'urn:foo';
        addToLoader({doc: mockRootCapability});
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: mockRootCapability.id,
          invoker: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [mockRootCapability.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   4. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   5. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: 'urn:foo',
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
      });

      it('should verify a capability chain of depth 2 and a ' +
        'valid caveat on one capability', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add a caveat that states the capability should expire an
        //      hour from now
        const expires = new Date();
        expires.setHours(expires.getHours() + 1);
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id()
        };
        new ExpirationCaveat({expires}).update(newCapability);
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018(),
            caveat: new ExpirationCaveat()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify a capability chain of depth 2 when a ' +
        'caveat is not met on one capability', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add a caveat that states the capability should expire an
        //      hour ago
        const expires = new Date();
        expires.setHours(expires.getHours() - 1);
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id()
        };
        new ExpirationCaveat({expires}).update(newCapability);
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018(),
            caveat: new ExpirationCaveat()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        // TODO: assert more about result.error
      });

      it('should verify a capability chain of depth 2 and an ' +
        'allowed action on one capability', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add an allowed action of `write`
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id(),
          allowedAction: 'write'
        };
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id,
            capabilityAction: 'write'
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify a capability chain of depth 2 when a ' +
        '"capabilityAction" is required but missing', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add a caveat that states the capability should expire an
        //      hour ago
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id(),
          allowedAction: 'write'
        };
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            expectedAction: 'write',
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        // TODO: assert more about result.error
      });

      it('should fail to verify a capability chain of depth 2 when a ' +
        '"capabilityAction" is not in "allowedAction"', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add a caveat that states the capability should expire an
        //      hour ago
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id(),
          allowedAction: 'write'
        };
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id,
            capabilityAction: 'invalid'
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        // TODO: assert more about result.error
      });

      it('should verify a capability chain of depth 2 and a ' +
        'specific expected capability action', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add an allowed action of `write`
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id()
        };
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id,
            capabilityAction: 'write'
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018(),
            capabilityAction: 'write'
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify a capability chain of depth 2 when an ' +
        'expected "capabilityAction" is required but missing', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add a caveat that states the capability should expire an
        //      hour ago
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id()
        };
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018(),
            capabilityAction: 'write'
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        // TODO: assert more about result.error
      });

      it('should fail to verify a capability chain of depth 2 when an ' +
        'expected "capabilityAction" does not match', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add a caveat that states the capability should expire an
        //      hour ago
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id()
        };
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id,
            capabilityAction: 'write'
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018(),
            capabilityAction: 'read'
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        // TODO: assert more about result.error
      });

      it('should verify a capability chain of depth 3', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker and delegator should be Bob's ID
        const bobCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id(),
          delegator: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const bobDelCap = await jsigs.sign(bobCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: bobDelCap});
        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The invoker should be Carol's ID
        const carolCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invoker: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await jsigs.sign(carolCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id, bobCap.id]
          })
        });
        addToLoader({doc: carolDelCap});
        const result = await jsigs.verify(carolDelCap, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation({
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify a capability chain of depth 3 ' +
        'because of bad middle capability', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker and delegator should be Bob's ID
        const bobCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id(),
          delegator: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const bobDelCap = await jsigs.sign(bobCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        // change ID to something else (breaking signature)
        bobDelCap.id = uuid();
        addToLoader({doc: bobDelCap});
        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The invoker should be Carol's ID
        const carolCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invoker: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await jsigs.sign(carolCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id, bobCap.id]
          })
        });
        addToLoader({doc: carolDelCap});
        const result = await jsigs.verify(carolDelCap, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation({
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
      });

      it('should fail to verify a capability chain of depth 3 ' +
        'because of bad last capability', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker and delegator should be Bob's ID
        const bobCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id(),
          delegator: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const bobDelCap = await jsigs.sign(bobCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: bobDelCap});
        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The invoker should be Carol's ID
        const carolCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invoker: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await jsigs.sign(carolCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id, bobCap.id]
          })
        });
        // change ID to something else (breaking signature)
        carolDelCap.id = uuid();
        addToLoader({doc: carolDelCap});
        const result = await jsigs.verify(carolDelCap, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation({
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
      });

      it('should verify a capability chain of depth 3 ' +
        'w/inspectCapabilityChain', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker and delegator should be Bob's ID
        const bobCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id(),
          delegator: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const bobDelCap = await jsigs.sign(bobCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: bobDelCap});
        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The invoker should be Carol's ID
        const carolCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invoker: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await jsigs.sign(carolCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id, bobCap.id]
          })
        });
        addToLoader({doc: carolDelCap});

        const inspectCapabilityChain = async ({
          capabilityChain, invocationTarget
        }) => {
          should.exist(invocationTarget);
          invocationTarget.should.be.a('string');
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(2);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {valid: true};
        };
        const result = await jsigs.verify(carolDelCap, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation({
            suite: new Ed25519Signature2018(),
            inspectCapabilityChain,
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify a capability chain of depth 3 ' +
        'w/inspectCapabilityChain that includes a revoked capability',
        async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker and delegator should be Bob's ID
        const bobCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id(),
          delegator: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const bobDelCap = await jsigs.sign(bobCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: bobDelCap});
        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The invoker should be Carol's ID
        const carolCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invoker: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await jsigs.sign(carolCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id, bobCap.id]
          })
        });
        addToLoader({doc: carolDelCap});

        const inspectCapabilityChain = async ({
          capabilityChain, invocationTarget
        }) => {
          should.exist(invocationTarget);
          invocationTarget.should.be.a('string');
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(2);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {
            error: new Error(`The capability "${capabilityChain[0].id}" ` +
              'has been revoked.'),
            valid: false,
          };
        };
        const result = await jsigs.verify(carolDelCap, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation({
            suite: new Ed25519Signature2018(),
            inspectCapabilityChain,
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        expect(result.error[0]).to.exist;
        result.error[0].message.should.contain('revoked');
      });

      it('should verify invoking a capability chain of depth 3', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker and delegator should be Bob's ID
        const bobCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id(),
          delegator: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const bobDelCap = await jsigs.sign(bobCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: bobDelCap});
        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The invoker should be Carol's ID
        const carolCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invoker: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await jsigs.sign(carolCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id, bobCap.id]
          })
        });
        addToLoader({doc: carolDelCap});
        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The invoker should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(carol.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: carolCap.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify a capability chain of depth 3 w/ multiple delegators',
        async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker and delegator should be Bob's ID
        const bobCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: ['urn:other', bob.id()],
          delegator: ['urn:other', bob.id()]
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const bobDelCap = await jsigs.sign(bobCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: bobDelCap});
        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The invoker should be Carol's ID
        const carolCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invoker: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await jsigs.sign(carolCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id, bobCap.id]
          })
        });
        addToLoader({doc: carolDelCap});
        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The invoker should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(carol.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: carolCap.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify a capability chain of depth 3 when ' +
        'delegation is not permitted', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. Only the invoker should be Bob's ID, no delegator
        const bobCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const bobDelCap = await jsigs.sign(bobCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: bobDelCap});
        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The invoker should be Carol's ID
        const carolCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invoker: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await jsigs.sign(carolCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id, bobCap.id]
          })
        });
        addToLoader({doc: carolDelCap});
        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The invoker should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(carol.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: carolCap.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        // TODO: assert more about result.error
      });

      it('should verify invoking a capability chain of depth 3 ' +
        'w/inspectCapabilityChain', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker and delegator should be Bob's ID
        const bobCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id(),
          delegator: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const bobDelCap = await jsigs.sign(bobCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: bobDelCap});
        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The invoker should be Carol's ID
        const carolCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invoker: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await jsigs.sign(carolCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id, bobCap.id]
          })
        });
        addToLoader({doc: carolDelCap});
        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The invoker should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(carol.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: carolCap.id
          })
        });

        const inspectCapabilityChain = async ({
          capabilityChain, invocationTarget
        }) => {
          should.exist(invocationTarget);
          invocationTarget.should.be.a('string');
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(2);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {valid: true};
        };
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018(),
            inspectCapabilityChain,
          }),
          documentLoader: testLoader
        });

        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail invoking a capability chain of depth 3 ' +
        'w/inspectCapabilityChain and a revoked capability', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker and delegator should be Bob's ID
        const bobCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id(),
          delegator: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const bobDelCap = await jsigs.sign(bobCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice.get('publicKey', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: bobDelCap});
        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The invoker should be Carol's ID
        const carolCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invoker: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await jsigs.sign(carolCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id, bobCap.id]
          })
        });
        addToLoader({doc: carolDelCap});
        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The invoker should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(carol.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: carolCap.id
          })
        });

        const inspectCapabilityChain = async ({
          capabilityChain, invocationTarget
        }) => {
          should.exist(invocationTarget);
          invocationTarget.should.be.a('string');
          should.exist(capabilityChain);
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(2);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {
            error: new Error(`The capability "${capabilityChain[0].id}" ` +
              'has been revoked.'),
            valid: false,
          };
        };
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018(),
            inspectCapabilityChain,
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        expect(result.error[0]).to.exist;
        result.error[0].message.should.contain('revoked');
      });
    });
  });
});

};

function _checkCapabilityChain({capabilityChain}) {
  for(const [i, c] of capabilityChain.entries()) {
    c.should.be.an('object');
    c.should.have.property('id');
    c.should.have.property('invoker');
    // the last capability will not have a delegator field
    if(i < capabilityChain.length - 1) {
      c.should.have.property('delegator');
    }
  }
}

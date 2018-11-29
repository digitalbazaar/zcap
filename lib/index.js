/**
 * Copyright (c) 2018 Digital Bazaar, Inc.
 *
 * @author Christopher Lemmer Webber
 * @author Ganesh Annan <gannan@digitalbazaar.com>
 *
 */
'use strict';

const proofPurposes = {
  capabilityInvocation: require('./CapabilityInvocation'),
  capabilityDelegation: require('./CapabilityDelegation')
};

module.exports = {
  proofPurposes,
  install: jsigs => {
    for(const proofPurpose in proofPurposes) {
      jsigs.proofPurposes.use(proofPurpose, proofPurposes[proofPurpose]);
    }
  }
};

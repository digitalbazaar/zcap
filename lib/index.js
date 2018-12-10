/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
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

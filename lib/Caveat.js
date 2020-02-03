/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

module.exports = class Caveat {
  /**
   * @param {string} type - The type of the caveat (as defined in the
   *   jsigs.constants.SECURITY_CONTEXT_URL JSON-LD context, URIs if
   *   not defined).
   */
  constructor({type} = {}) {
    if(typeof type !== 'string') {
      throw new TypeError('"type" must be a string.');
    }
    this.type = type;
  }

  /**
   * Determines if this caveat has been met.
   *
   * @param {object} caveat - The caveat parameters.
   * @param {object} options.capability - The full capability.
   *
   * @returns {Promise<object>} Resolves to can object with `valid` and `error`.
   */
  async validate(caveat, {capability, documentLoader, expansionMap}) {
    throw new Error('"validate" must be implemented by a derived class.');
  }

  /**
   * Adds this caveat to the given capability.
   *
   * @param {object} capability - The capability to add this caveat to.
   *
   * @return {Promise<object>} Resolves to the capability.
   */
  async update(capability) {
    throw new Error(
      '"update" must be implemented by a derived class.');
  }
};

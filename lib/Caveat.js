/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

module.exports = class Caveat {
  /**
   * @param type {string}: the type of the caveat (as defined in the
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
   * @param caveat {object} the caveat parameters.
   * @param options.capability {object} the full capability.
   *
   * @return {Promise<object>} resolves to can object with `valid` and `error`.
   */
  async validate(caveat, {capability, documentLoader, expansionMap}) {
    throw new Error('"validate" must be implemented by a derived class.');
  }

  /**
   * Adds this caveat to the given capability.
   *
   * @param capability {object} the capability to add this caveat to.
   *
   * @return {Promise<object>} resolves to the capability.
   */
  async update(capability) {
    throw new Error(
      '"update" must be implemented by a derived class.');
  }
};

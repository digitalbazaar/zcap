/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const Caveat = require('./Caveat');
const jsonld = require('jsonld');

module.exports = class ExpirationCaveat extends Caveat {
  /**
   * @param [date] {Date or string or integer} the current date to use to
   *   validate an expiration caveat (defaults to `now`)..
   * @param [expires] {Date or string or integer} the expiration date to
   *   attach to a capability as a caveat.
   */
  constructor({date, expires} = {}) {
    super({type: 'sec:ExpirationCaveat'});
    if(date !== undefined) {
      this.date = new Date(date);
    }
    if(expires !== undefined) {
      this.expires = new Date(expires);
    }
  }

  /**
   * Determines if this caveat has been met.
   *
   * @param caveat {object} the caveat parameters.
   * @param options.capability {object} the full capability.
   *
   * @return {Promise<object>} resolves to can object with `valid` and `error`.
   */
  async validate(caveat) {
    try {
      // default `date` to `now`
      const {date = new Date()} = this;
      const expires = Date.parse(caveat.expires);
      // comparsion performed this way to cover `NaN` cases
      if(!(date < expires)) {
        throw new Error('The capability has expired.');
      }
      return {valid: true};
    } catch(error) {
      return {valid: false, error};
    }
  }

  /**
   * Adds this caveat to the given capability.
   *
   * @param capability {object} the capability to add this caveat to.
   *
   * @return {Promise<object>} resolves to the capability.
   */
  async update(capability) {
    const str = this.expires.toISOString();
    const expires = str.substr(0, str.length - 5) + 'Z';
    jsonld.addValue(capability, 'caveat', {
      type: this.type,
      expires
    });
    return capability;
  }
};

/*!
 * Copyright (c) 2018-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

exports.Controller = class Controller {
  constructor(doc) {
    // doc is the key controller document
    this.doc = doc;
  }

  id() {
    return this.doc.id;
  }

  get(keyType, index) {
    const vm = this.doc[keyType][index];
    if(typeof vm === 'string') {
      // dereference verification method
      return this.doc.verificationMethod.find(({id}) => id === vm);
    }
    return vm;
  }
};

/* eslint-disable */
const b = a=>a?(a^Math.random()*16>>a/4).toString(16):([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,b);
exports.uuid = () => `urn:uuid:${b()}`;
/* eslint-enable */

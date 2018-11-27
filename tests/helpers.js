const api = {};
module.exports = api;

api.addToLoader = ({documentLoader, doc}) => {
  return (url, callback) => {
    if(url === doc.id) {
      return callback(null, {
        contextUrl: null,
        document: doc,
        documentUrl: doc.id
      });
    }
    return documentLoader(url, callback);
  };

};

api.Owner = class Owner {
  constructor(doc) {
    // doc is the key owner document
    this.doc = doc;
  }

  id() {
    return this.doc.id;
  }

  get(keyType, index) {
    return this.doc[keyType][index].publicKey
  }
};

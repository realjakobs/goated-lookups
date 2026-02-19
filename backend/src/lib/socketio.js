'use strict';

let _io = null;

module.exports = {
  setIo(io) { _io = io; },
  getIo()   { return _io; },
};

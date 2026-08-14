'use strict';

/**
 * Envuelve handlers sync/async y reenvía errores a errorHandler.
 */
function asyncHandler(fn) {
  return function wrapped(req, res, next) {
    try {
      Promise.resolve(fn(req, res, next)).catch(next);
    } catch (err) {
      next(err);
    }
  };
}

module.exports = { asyncHandler };

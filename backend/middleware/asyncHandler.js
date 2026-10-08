module.exports = (handler) => (req, res, next) =>
  Promise.resolve().then(() => handler(req, res, next)).catch(next);

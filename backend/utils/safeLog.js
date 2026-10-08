// Database errors can include document values; parser errors include raw bodies.
// Deliberately retain only bounded classification, never error messages/stacks.
const safeError = (err) => ({
  name: /^[a-zA-Z]+Error$/.test(err?.name || '') ? err.name : 'Error',
  code: typeof err?.code === 'number' ? err.code : undefined,
});
const logError = (label, err) => console.error(label, safeError(err));
module.exports = { logError, safeError };

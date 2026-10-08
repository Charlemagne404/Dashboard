module.exports = (req, res, next) => {
  if (req.user?.isOwner) {
    if (process.env.NODE_ENV === 'production' && !req.user.mfaEnabled) {
      return res.status(403).json({ message: 'Owners must enroll MFA before administering accounts.' });
    }
    if (req.method !== 'GET' && new Date(req.user.sessionCreatedAt || 0).getTime() + 10 * 60 * 1000 <= Date.now()) {
      return res.status(403).json({ message: 'Sign in again before performing administrative changes.', reauthenticationRequired: true });
    }
    return next();
  }

  return res.status(403).json({ message: 'Owner access required.' });
};

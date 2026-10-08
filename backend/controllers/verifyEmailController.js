const User = require('../models/User');
const { logError } = require('../utils/safeLog');
const { hashEmailVerificationToken } = require('../utils/emailVerification');

exports.verifyEmail = async (req, res) => {
  const token = String(req.query.token || '').trim();

  if (!token) {
    return res.status(400).json({ message: 'Verification token is required.' });
  }

  try {
    const hashedToken = hashEmailVerificationToken(token);
    const user = await User.findOneAndUpdate({
      verificationToken: hashedToken,
      verificationTokenExpires: { $gt: Date.now() },
    }, {
      $set: { isVerified: true, verificationToken: '', verificationTokenExpires: null },
      $inc: { __v: 1 },
      $push: { auditEvents: { $each: [{
        at: new Date(), type: 'email_verified', message: 'Email verified.',
        ip: String(req.ip || '').slice(0, 80),
        userAgent: String(req.headers['user-agent'] || '').slice(0, 300),
      }], $slice: -120 } },
    }, { new: true });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired verification link.' });
    }

    return res.status(200).json({ message: 'Email verified successfully. You can now log in.' });
  } catch (err) {
    logError('Email verification error:', err);
    return res.status(500).json({ message: 'Email verification failed.' });
  }
};

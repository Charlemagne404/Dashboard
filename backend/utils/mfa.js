const crypto = require('crypto');
const OTPAuth = require('otpauth');
const QRCode = require('qrcode');

const createTotp = ({ secret, digits = 6, period = 30, accountName = 'user', issuer = 'Continental ID' }) =>
  new OTPAuth.TOTP({ algorithm: 'SHA1', digits, period, label: accountName, issuer,
    secret: OTPAuth.Secret.fromBase32(secret) });

const generateMfaSecret = (size = 20) => new OTPAuth.Secret({ size }).base32;
const totp = (options) => createTotp(options).generate({ timestamp: options.timestamp ?? Date.now() });
const getTotpStep = ({ token, timestamp = Date.now(), window = 1, ...options }) => {
  if (typeof token !== 'string' || !/^\d{6}$/.test(token) || !options.secret) return null;
  try {
    const delta = createTotp({ ...options, secret: options.secret }).validate({ token, timestamp, window });
    return delta === null ? null : Math.floor(timestamp / 1000 / (options.period || 30)) + delta;
  } catch {
    return null;
  }
};
const verifyTotp = (options) => getTotpStep(options) !== null;
const buildOtpAuthUrl = (options) => createTotp(options).toString();
const buildOtpAuthQrDataUrl = async (url) => url ? QRCode.toDataURL(url, {
  errorCorrectionLevel: 'M', margin: 1, width: 220,
}) : '';
const generateBackupCodes = (count = 8) => Array.from({ length: count }, () =>
  crypto.randomBytes(8).toString('hex').toUpperCase().match(/.{4}/g).join('-'));

module.exports = { buildOtpAuthQrDataUrl, buildOtpAuthUrl, generateBackupCodes,
  generateMfaSecret, getTotpStep, totp, verifyTotp };

const ms = require('ms');

const isHttpsOrigin = (value) => {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value && !url.username && !url.password;
  } catch { return false; }
};
const assertRuntimeConfig = (env = process.env) => {
  const requireValue = (name) => { if (!env[name]?.trim()) throw new Error(`${name} is required.`); };
  ['MONGO_URI', 'JWT_SECRET', 'REFRESH_TOKEN_SECRET'].forEach(requireValue);
  const numeric = [
    'PORT', 'RATE_LIMIT_WINDOW_MS', 'RATE_LIMIT_MAX', 'LOGIN_RATE_WINDOW_MS', 'LOGIN_RATE_MAX_ATTEMPTS',
    'LOGIN_BLOCK_MS', 'MFA_RATE_WINDOW_MS', 'MFA_RATE_MAX_ATTEMPTS', 'MFA_BLOCK_MS', 'PASSWORD_RESET_TTL_MS',
    'PASSWORD_RESET_EMAIL_COOLDOWN_MS', 'VERIFICATION_EMAIL_COOLDOWN_MS', 'EMAIL_DAILY_LIMIT', 'EMAIL_MONTHLY_LIMIT',
    'EMAIL_VERIFICATION_TTL_MS', 'SESSION_ABSOLUTE_TTL_MS', 'SESSION_IDLE_TTL_MS', 'REFRESH_TOKEN_REPLAY_GRACE_MS',
    'PASSWORD_RESET_RATE_WINDOW_MS', 'PASSWORD_RESET_RATE_MAX_ATTEMPTS', 'PASSWORD_RESET_BLOCK_MS',
    'VERIFICATION_RESEND_RATE_WINDOW_MS', 'VERIFICATION_RESEND_RATE_MAX_ATTEMPTS', 'VERIFICATION_RESEND_BLOCK_MS',
    'LOGIN_ALERT_EMAIL_COOLDOWN_MS', 'DEVICE_ID_TTL_MS',
  ];
  for (const name of numeric) {
    if (env[name] !== undefined && (!Number.isSafeInteger(Number(env[name])) || Number(env[name]) <= 0)) {
      throw new Error(`${name} must be a positive integer.`);
    }
  }
  if (env.PORT && Number(env.PORT) > 65535) throw new Error('PORT is invalid.');
  if (env.HTTPS_MODE && !['off', 'on', 'auto', '0', '1', 'false', 'true', 'disabled', 'enabled', 'https'].includes(env.HTTPS_MODE)) {
    throw new Error('HTTPS_MODE is invalid.');
  }
  for (const [name, fallback, max] of [['JWT_EXPIRES_IN', '15m', '1h'], ['REFRESH_TOKEN_EXPIRES_IN', '7d', '30d']]) {
    const value = env[name] || fallback;
    if (!/^\d+(?:ms|s|m|h|d|w)$/.test(value) || ms(value) < 1000 || ms(value) > ms(max)) {
      throw new Error(`${name} must use an explicit unit and be between 1s and ${max}.`);
    }
  }
  if (env.NODE_ENV !== 'production') return;
  if (env.ALLOW_DEFAULT_TRUSTED_ORIGINS === 'true') throw new Error('Production requires explicit origin lists.');
  for (const name of ['JWT_SECRET', 'REFRESH_TOKEN_SECRET', 'MFA_SECRET_ENCRYPTION_KEY']) {
    requireValue(name);
    if (env[name].length < 32 || /replace-with|example|changeme/i.test(env[name])) throw new Error(`${name} must be a strong secret.`);
  }
  if (new Set([env.JWT_SECRET, env.REFRESH_TOKEN_SECRET, env.MFA_SECRET_ENCRYPTION_KEY]).size !== 3) throw new Error('Access, refresh, and MFA secrets must differ.');
  for (const name of ['ALLOWED_ORIGINS', 'IDENTITY_MANAGEMENT_ORIGINS']) {
    requireValue(name);
    if (!env[name].split(',').every((value) => isHttpsOrigin(value.trim()))) throw new Error(`${name} must contain exact HTTPS origins.`);
  }
  const allowed = env.ALLOWED_ORIGINS.split(',').map((v) => v.trim());
  if (!env.IDENTITY_MANAGEMENT_ORIGINS.split(',').every((v) => allowed.includes(v.trim()))) throw new Error('Management origins must be allowed browser origins.');
  requireValue('PUBLIC_API_ORIGIN');
  if (!isHttpsOrigin(env.PUBLIC_API_ORIGIN)) throw new Error('PUBLIC_API_ORIGIN must be an exact HTTPS origin.');
  for (const name of ['RESEND_API_KEY', 'EMAIL_FROM', 'LOGIN_POPUP_URL']) requireValue(name);
  for (const name of ['LOGIN_POPUP_URL', 'EMAIL_VERIFY_URL', 'PASSWORD_RESET_URL']) {
    if (env[name]) {
      const url = new URL(env[name]);
      if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error(`${name} must be a clean HTTPS URL.`);
    }
  }
  if (env.ALLOW_LOCALHOST_ORIGINS === 'true') throw new Error('Localhost origins are not permitted in production.');
  if (env.TRUST_PROXY === 'true') throw new Error('TRUST_PROXY must identify trusted proxies, not every peer.');
  if (!['1', 'true', 'on', 'enabled', 'https'].includes(env.HTTPS_MODE) && (!env.TRUST_PROXY || env.TRUST_PROXY === 'false' || env.TRUST_PROXY === '0')) {
    throw new Error('Production HTTP requires an explicitly trusted TLS proxy.');
  }
  for (const provider of ['GITHUB', 'GOOGLE', 'DISCORD', 'MICROSOFT']) {
    if (env[`${provider}_CLIENT_ID`] || env[`${provider}_CLIENT_SECRET`]) {
      for (const suffix of ['CLIENT_ID', 'CLIENT_SECRET', 'OAUTH_CALLBACK_URL']) requireValue(`${provider}_${suffix}`);
      const callback = new URL(env[`${provider}_OAUTH_CALLBACK_URL`]);
      if (callback.origin !== env.PUBLIC_API_ORIGIN || callback.pathname !== `/api/auth/oauth/${provider.toLowerCase()}/callback` || callback.search || callback.hash) {
        throw new Error(`${provider}_OAUTH_CALLBACK_URL must match the public auth callback.`);
      }
    }
  }
  if (env.VANGUARD_API_KEY || env.VANGUARD_API_KEYS) {
    const keys = [env.VANGUARD_API_KEY, ...(env.VANGUARD_API_KEYS || '').split(',')].filter(Boolean);
    if (keys.some((key) => key.trim().length < 32)) throw new Error('Vanguard keys must contain at least 32 characters.');
  }
};
module.exports = { assertRuntimeConfig, isHttpsOrigin };

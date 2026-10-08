const isIdentityManagementOrigin = (value) => {
  try {
    const url = new URL(value);
    if (!process.env.IDENTITY_MANAGEMENT_ORIGINS && process.env.NODE_ENV !== 'production' && ['localhost', '127.0.0.1'].includes(url.hostname)) return true;
    const origins = String(process.env.IDENTITY_MANAGEMENT_ORIGINS ||
      'https://dashboard.continental-hub.com,https://login.continental-hub.com').split(',').map((s) => s.trim());
    return origins.includes(url.origin);
  } catch {
    return false;
  }
};
module.exports = { isIdentityManagementOrigin };

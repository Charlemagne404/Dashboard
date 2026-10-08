const ipaddr = require('ipaddr.js');
const getClientIpKey = (req) => {
  const value = String(req.ip || req.socket?.remoteAddress || 'unknown');
  try {
    const parsed = ipaddr.process(value);
    // Rate limits group IPv6 privacy addresses by /64 and normalize mapped IPv4.
    return parsed.kind() === 'ipv6'
      ? `${Buffer.from(parsed.toByteArray().slice(0, 8)).toString('hex')}/64`
      : parsed.toString();
  } catch { return 'unknown'; }
};
module.exports = { getClientIpKey };

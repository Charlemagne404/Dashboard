const ACCOUNT_ROLE_USER = 'user';
const ACCOUNT_ROLE_OWNER = 'owner';
const ACCOUNT_STATUS_ACTIVE = 'active';
const ACCOUNT_STATUS_SUSPENDED = 'suspended';

const OWNER_PERMISSIONS = Object.freeze({
  viewOwnerDashboard: true,
  manageUsers: true,
  manageRoles: true,
  manageSecurity: true,
  manageVanguard: true,
  revokeSessions: true,
  resetMfa: true,
  triggerPasswordResets: true,
  resendVerification: true,
  suspendAccounts: true,
  deleteAccounts: true,
});

const USER_PERMISSIONS = Object.freeze(
  Object.fromEntries(Object.keys(OWNER_PERMISSIONS).map((key) => [key, false]))
);

const normalizeAccountRole = (value) =>
  String(value || '').trim().toLowerCase() === ACCOUNT_ROLE_OWNER
    ? ACCOUNT_ROLE_OWNER
    : ACCOUNT_ROLE_USER;

const normalizeAccountStatus = (value) =>
  String(value || '').trim().toLowerCase() === ACCOUNT_STATUS_SUSPENDED
    ? ACCOUNT_STATUS_SUSPENDED
    : ACCOUNT_STATUS_ACTIVE;

const isOwnerRole = (value) => normalizeAccountRole(value) === ACCOUNT_ROLE_OWNER;
const isSuspendedAccount = (value) => normalizeAccountStatus(value) === ACCOUNT_STATUS_SUSPENDED;

const buildAuthorityPayload = (user = {}) => {
  const role = normalizeAccountRole(user?.accountRole);
  const status = normalizeAccountStatus(user?.accountStatus);
  const isOwner = role === ACCOUNT_ROLE_OWNER;

  return {
    role,
    status,
    statusReason: String(user?.accountStatusReason || '').trim().slice(0, 240),
    isOwner,
    permissions: isOwner ? OWNER_PERMISSIONS : USER_PERMISSIONS,
  };
};

module.exports = {
  ACCOUNT_ROLE_USER,
  ACCOUNT_ROLE_OWNER,
  ACCOUNT_STATUS_ACTIVE,
  ACCOUNT_STATUS_SUSPENDED,
  OWNER_PERMISSIONS,
  USER_PERMISSIONS,
  normalizeAccountRole,
  normalizeAccountStatus,
  isOwnerRole,
  isSuspendedAccount,
  buildAuthorityPayload,
};

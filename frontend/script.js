const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1']);
const HOSTED_STATIC_HOSTS = new Set([
  'blueprint.continental-hub.com',
  'dashboard.continental-hub.com',
  'grimoire.continental-hub.com',
  'login.continental-hub.com',
  'pulse.continental-hub.com',
  'stepcast.continental-hub.com',
  'vanguard.continental-hub.com',
  'charlemagne404.github.io',
  'mpmc.ddns.net',
]);
const PREFERRED_API_BASE_URLS = [
  'https://api.continental-hub.com',
  'https://auth.continental-hub.com',
  'https://id.continental-hub.com',
  'https://backend.continental-hub.com',
  'https://continental-hub.com',
  'https://login.continental-hub.com',
];
const HOSTED_API_BASE_URL = 'https://auth.continental-hub.com';
const API_BASE_STORAGE_KEY = 'continental.authApiBaseUrl';
const REFRESH_INTERVAL_MS = 5 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 15_000;
const ACTIVE_TAB_STORAGE_KEY = 'dashboard.activeTab';
const SERVICE_FAVORITES_STORAGE_KEY = 'dashboard.serviceFavorites';
const FAVORITE_SERVICES_ONLY_STORAGE_KEY = 'dashboard.favoriteServicesOnly';
const SERVICE_RECENT_STORAGE_KEY = 'dashboard.serviceRecent';
const OVERVIEW_ACTIVITY_LIMIT = 4;
const AVATAR_UPLOAD_MAX_FILE_BYTES = 5 * 1024 * 1024;
const AVATAR_UPLOAD_MAX_DIMENSION = 256;
const AVATAR_DATA_URL_MAX_LENGTH = 350000;
const AVATAR_URL_VALIDATION_TIMEOUT_MS = 7000;
const AVATAR_RENDER_TIMEOUT_MS = 10000;
const AVATAR_REMOTE_MAX_DIMENSION = 4096;
const AVATAR_ALLOWED_MIME_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif']);
const OAUTH_PROVIDERS = ['github', 'google', 'discord', 'microsoft'];
const BLOCKED_NAME_FRAGMENTS = [
  'anal',
  'anus',
  'arse',
  'asshole',
  'bastard',
  'beaner',
  'bitch',
  'bollock',
  'boner',
  'boob',
  'buttplug',
  'chink',
  'clit',
  'cock',
  'coon',
  'crackhead',
  'cum',
  'cuck',
  'cunt',
  'deepthroat',
  'dick',
  'dildo',
  'dyke',
  'ejaculate',
  'fag',
  'faggot',
  'felch',
  'fuck',
  'gangbang',
  'genital',
  'gook',
  'handjob',
  'hentai',
  'hitler',
  'jackoff',
  'jizz',
  'kike',
  'kkk',
  'nazi',
  'nigga',
  'nigger',
  'nutsack',
  'orgasm',
  'penis',
  'piss',
  'porn',
  'prick',
  'pussy',
  'queef',
  'rapist',
  'rape',
  'retard',
  'rimjob',
  'scrotum',
  'sex',
  'shit',
  'slut',
  'spic',
  'tit',
  'tranny',
  'twat',
  'vagina',
  'wank',
  'whore',
];

const normalizeForModeration = (value) =>
  safeText(value)
    .toLowerCase()
    .replace(/[0134@5$7+8]/g, (char) => {
      if (char === '0') return 'o';
      if (char === '1') return 'i';
      if (char === '3') return 'e';
      if (char === '4' || char === '@') return 'a';
      if (char === '5' || char === '$') return 's';
      if (char === '7' || char === '+') return 't';
      if (char === '8') return 'b';
      return char;
    })
    .replace(/[^a-z0-9]+/g, '')
    .replace(/(.)\1{2,}/g, '$1');

const buildModerationVariants = (value) => {
  const normalized = normalizeForModeration(value);
  if (!normalized) return [];

  const collapsedPairs = normalized.replace(/(.)\1+/g, '$1');
  return Array.from(new Set([normalized, collapsedPairs])).filter(Boolean);
};

const containsBlockedNameTerm = (value) => {
  const variants = buildModerationVariants(value);
  return variants.some((variant) => BLOCKED_NAME_FRAGMENTS.some((fragment) => variant.includes(fragment)));
};

const dom = {
  skipLink: document.getElementById('skip-link'),
  loadingScreen: document.getElementById('loading-screen'),
  loadingTitle: document.getElementById('loading-title'),
  loadingMessage: document.getElementById('loading-message'),
  loadingDetail: document.getElementById('loading-detail'),
  loadingStatusChip: document.getElementById('loading-status-chip'),
  loadingActions: document.getElementById('loading-actions'),
  loadingSignInBtn: document.getElementById('loading-sign-in-btn'),
  loadingFullLoginLink: document.getElementById('loading-full-login-link'),
  appContent: document.getElementById('app-content'),
  toastRegion: document.getElementById('toast-region'),

  status: document.getElementById('status'),
  connectionStatus: document.getElementById('connection-status'),
  syncStatus: document.getElementById('sync-status'),

  logoutBtn: document.getElementById('logout-btn'),
  refreshDataBtn: document.getElementById('refresh-data-btn'),
  headerExportJsonBtn: document.getElementById('header-export-json-btn'),

  tabButtons: Array.from(document.querySelectorAll('.tab-btn')),
  tabContents: Array.from(document.querySelectorAll('.tab-content')),
  sectionNavButtons: Array.from(document.querySelectorAll('[data-scroll-target], [data-tab-target]')),

  heroInitials: document.getElementById('hero-initials'),
  heroDisplayName: document.getElementById('hero-display-name'),
  heroUsername: document.getElementById('hero-username'),
  heroEmail: document.getElementById('hero-email'),
  heroGreeting: document.getElementById('hero-greeting'),
  heroStatusNote: document.getElementById('hero-status-note'),
  heroFocusTitle: document.getElementById('hero-focus-title'),
  heroFocusCopy: document.getElementById('hero-focus-copy'),
  heroFocusChip: document.getElementById('hero-focus-chip'),
  heroFocusBtn: document.getElementById('hero-focus-btn'),
  healthScoreValue: document.getElementById('health-score-value'),
  healthScoreLabel: document.getElementById('health-score-label'),
  actionCenter: document.getElementById('action-center'),
  overviewActivityList: document.getElementById('overview-activity-list'),
  overviewJumpProfileBtn: document.getElementById('overview-jump-profile-btn'),
  overviewJumpSecurityBtn: document.getElementById('overview-jump-security-btn'),
  overviewJumpActivityBtn: document.getElementById('overview-jump-activity-btn'),
  profileChecklist: document.getElementById('profile-checklist'),
  profileFormState: document.getElementById('profile-form-state'),

  summaryId: document.getElementById('summary-id'),
  summaryUsername: document.getElementById('summary-username'),
  summaryDisplayName: document.getElementById('summary-display-name'),
  summaryHeadline: document.getElementById('summary-headline'),
  summaryLastLogin: document.getElementById('summary-last-login'),
  summaryVerified: document.getElementById('summary-verified'),
  summarySessions: document.getElementById('summary-sessions'),
  summaryCompletion: document.getElementById('summary-completion'),

  insightLast7: document.getElementById('insight-last7'),
  insightLast30: document.getElementById('insight-last30'),
  insightIps: document.getElementById('insight-ips'),
  insightVerified: document.getElementById('insight-verified'),

  profileForm: document.getElementById('profile-form'),
  profileSaveBtn: document.getElementById('profile-save-btn'),
  profileUsername: document.getElementById('profile-username'),
  profileDisplayName: document.getElementById('profile-display-name'),
  profileHeadline: document.getElementById('profile-headline'),
  profileEmail: document.getElementById('profile-email'),
  profileEmailCurrentPassword: document.getElementById('profile-email-current-password'),
  profileAvatarCard: document.getElementById('profile-avatar-card'),
  profileAvatarPreview: document.getElementById('profile-avatar-preview'),
  profileAvatarHelper: document.getElementById('profile-avatar-helper'),
  profileAvatarMeta: document.getElementById('profile-avatar-meta'),
  profileAvatarUrl: document.getElementById('profile-avatar-url'),
  profileAvatarUpload: document.getElementById('profile-avatar-upload'),
  profileAvatarUploadBtn: document.getElementById('profile-avatar-upload-btn'),
  profileAvatarRemoveBtn: document.getElementById('profile-avatar-remove-btn'),
  profileLocation: document.getElementById('profile-location'),
  profileWebsite: document.getElementById('profile-website'),
  profileBio: document.getElementById('profile-bio'),
  profileId: document.getElementById('profile-id'),
  profileCreated: document.getElementById('profile-created'),
  profilePublicLink: document.getElementById('profile-public-link'),
  publicProfileStatusBadge: document.getElementById('public-profile-status-badge'),
  publicProfileDiscoveryBadge: document.getElementById('public-profile-discovery-badge'),
  publicProfileLinkHelper: document.getElementById('public-profile-link-helper'),
  copyPublicProfileLinkBtn: document.getElementById('copy-public-profile-btn'),
  openPublicProfileBtn: document.getElementById('open-public-profile-btn'),
  profilePreviewVisibility: document.getElementById('profile-preview-visibility'),
  profilePreviewAvatar: document.getElementById('profile-preview-avatar'),
  profilePreviewHandle: document.getElementById('profile-preview-handle'),
  profilePreviewName: document.getElementById('profile-preview-name'),
  profilePreviewHeadline: document.getElementById('profile-preview-headline'),
  profilePreviewSummary: document.getElementById('profile-preview-summary'),
  profilePreviewMeta: document.getElementById('profile-preview-meta'),
  profilePreviewVisibleCount: document.getElementById('profile-preview-visible-count'),
  profilePreviewLinkedCount: document.getElementById('profile-preview-linked-count'),
  profilePreviewMemberSince: document.getElementById('profile-preview-member-since'),
  profilePreviewSections: document.getElementById('profile-preview-sections'),
  profilePreviewNote: document.getElementById('profile-preview-note'),
  profileProgressBar: document.getElementById('profile-progress-bar'),
  profileProgressBars: Array.from(document.querySelectorAll('.profile-progress-fill')),
  profileProgressLabel: document.getElementById('profile-progress-label'),
  verificationPanel: document.getElementById('verification-panel'),
  verificationHelper: document.getElementById('verification-helper'),
  verificationResendBtn: document.getElementById('verification-resend-btn'),

  linkedForm: document.getElementById('linked-form'),
  linkedSaveBtn: document.getElementById('linked-save-btn'),
  linkedGoogle: document.getElementById('linked-google'),
  linkedFacebook: document.getElementById('linked-facebook'),
  linkedGithub: document.getElementById('linked-github'),
  linkedTwitter: document.getElementById('linked-twitter'),
  linkedLinkedin: document.getElementById('linked-linkedin'),
  linkedDiscord: document.getElementById('linked-discord'),
  linkedApple: document.getElementById('linked-apple'),
  linkedMicrosoft: document.getElementById('linked-microsoft'),
  oauthGithubStatus: document.getElementById('oauth-github-status'),
  oauthGithubConnectBtn: document.getElementById('oauth-github-connect-btn'),
  oauthGithubUnlinkBtn: document.getElementById('oauth-github-unlink-btn'),
  oauthGoogleStatus: document.getElementById('oauth-google-status'),
  oauthGoogleConnectBtn: document.getElementById('oauth-google-connect-btn'),
  oauthGoogleUnlinkBtn: document.getElementById('oauth-google-unlink-btn'),
  oauthDiscordStatus: document.getElementById('oauth-discord-status'),
  oauthDiscordConnectBtn: document.getElementById('oauth-discord-connect-btn'),
  oauthDiscordUnlinkBtn: document.getElementById('oauth-discord-unlink-btn'),
  oauthMicrosoftStatus: document.getElementById('oauth-microsoft-status'),
  oauthMicrosoftConnectBtn: document.getElementById('oauth-microsoft-connect-btn'),
  oauthMicrosoftUnlinkBtn: document.getElementById('oauth-microsoft-unlink-btn'),
  vanguardIdentityStatus: document.getElementById('vanguard-identity-status'),
  vanguardLinkChip: document.getElementById('vanguard-link-chip'),
  vanguardStandingChip: document.getElementById('vanguard-standing-chip'),
  vanguardIdentityDetail: document.getElementById('vanguard-identity-detail'),
  vanguardOpenDiscordLinkBtn: document.getElementById('vanguard-open-discord-link-btn'),

  passwordForm: document.getElementById('password-form'),
  passwordSaveBtn: document.getElementById('password-save-btn'),
  currentPassword: document.getElementById('current-password'),
  newPassword: document.getElementById('new-password'),
  confirmPassword: document.getElementById('confirm-password'),
  passwordStrengthFill: document.getElementById('password-strength-fill'),
  passwordStrengthText: document.getElementById('password-strength-text'),

  securityForm: document.getElementById('security-form'),
  securitySaveBtn: document.getElementById('security-save-btn'),
  loginAlertsToggle: document.getElementById('login-alerts-toggle'),
  sessionLimitNote: document.getElementById('session-limit-note'),
  securityPostureChip: document.getElementById('security-posture-chip'),
  securityScoreRing: document.getElementById('security-score-ring'),
  securityScoreNumber: document.getElementById('security-score-number'),
  securityScoreSummary: document.getElementById('security-score-summary'),
  securityMetricSessions: document.getElementById('security-metric-sessions'),
  securityMetricDevices: document.getElementById('security-metric-devices'),
  securityMetricTrustedDevices: document.getElementById('security-metric-trusted-devices'),
  securityMetricNewDevices: document.getElementById('security-metric-new-devices'),
  securityBreakdown: document.getElementById('security-breakdown'),
  securityGuidanceTitle: document.getElementById('security-guidance-title'),
  securityGuidanceCopy: document.getElementById('security-guidance-copy'),
  securityGuidanceBtn: document.getElementById('security-guidance-btn'),
  mfaStatusCopy: document.getElementById('mfa-status-copy'),
  mfaSetupBtn: document.getElementById('mfa-setup-btn'),
  mfaDisableBtn: document.getElementById('mfa-disable-btn'),
  mfaBackupBtn: document.getElementById('mfa-backup-btn'),
  mfaSetupPanel: document.getElementById('mfa-setup-panel'),
  mfaCurrentPassword: document.getElementById('mfa-current-password'),
  mfaStartSetupBtn: document.getElementById('mfa-start-setup-btn'),
  mfaCancelSetupBtn: document.getElementById('mfa-cancel-setup-btn'),
  mfaSetupSteps: document.getElementById('mfa-setup-steps'),
  mfaQrShell: document.getElementById('mfa-qr-shell'),
  mfaQrImage: document.getElementById('mfa-qr-image'),
  mfaSecret: document.getElementById('mfa-secret'),
  mfaCopySecretBtn: document.getElementById('mfa-copy-secret-btn'),
  mfaOtpAuthUrl: document.getElementById('mfa-otpauth-url'),
  mfaCopyOtpAuthBtn: document.getElementById('mfa-copy-otpauth-btn'),
  mfaCode: document.getElementById('mfa-code'),
  mfaEnableBtn: document.getElementById('mfa-enable-btn'),
  mfaBackupCodesPanel: document.getElementById('mfa-backup-codes-panel'),
  mfaBackupCodes: document.getElementById('mfa-backup-codes'),
  mfaManagePanel: document.getElementById('mfa-manage-panel'),
  mfaManageTitle: document.getElementById('mfa-manage-title'),
  mfaManageCopy: document.getElementById('mfa-manage-copy'),
  mfaManageCurrentPassword: document.getElementById('mfa-manage-current-password'),
  mfaManageChallenge: document.getElementById('mfa-manage-challenge'),
  mfaManageConfirmBtn: document.getElementById('mfa-manage-confirm-btn'),
  mfaManageCancelBtn: document.getElementById('mfa-manage-cancel-btn'),
  passkeyStatusCopy: document.getElementById('passkey-status-copy'),
  passkeyManageBtn: document.getElementById('passkey-manage-btn'),
  passkeyCurrentPassword: document.getElementById('passkey-current-password'),
  passkeyChallengeRow: document.getElementById('passkey-challenge-row'),
  passkeyChallenge: document.getElementById('passkey-challenge'),
  passkeyRegisterBtn: document.getElementById('passkey-register-btn'),
  passkeyList: document.getElementById('passkey-list'),

  privacyForm: document.getElementById('privacy-form'),
  privacySaveBtn: document.getElementById('privacy-save-btn'),
  privacyPublic: document.getElementById('privacy-public'),
  privacySearchable: document.getElementById('privacy-searchable'),
  publicFieldHeadline: document.getElementById('public-field-headline'),
  publicFieldBio: document.getElementById('public-field-bio'),
  publicFieldLocation: document.getElementById('public-field-location'),
  publicFieldWebsite: document.getElementById('public-field-website'),
  publicFieldLinked: document.getElementById('public-field-linked'),
  publicFieldMemberSince: document.getElementById('public-field-member-since'),
  publicProfileSummary: document.getElementById('public-profile-summary'),
  publicProfileVisibleCount: document.getElementById('public-profile-visible-count'),
  publicProfilePreviewBtn: document.getElementById('public-profile-preview-btn'),
  publicProfileDirectoryBtn: document.getElementById('public-profile-directory-btn'),
  privacyFormState: document.getElementById('privacy-form-state'),

  notificationForm: document.getElementById('notification-form'),
  notificationSaveBtn: document.getElementById('notification-save-btn'),
  notifyEmail: document.getElementById('notify-email'),
  notifySms: document.getElementById('notify-sms'),
  notifyPush: document.getElementById('notify-push'),
  notifyWeeklyDigest: document.getElementById('notify-weekly-digest'),
  notifySecurity: document.getElementById('notify-security'),

  appearanceForm: document.getElementById('appearance-form'),
  appearanceSaveBtn: document.getElementById('appearance-save-btn'),
  appearanceResetBtn: document.getElementById('appearance-reset-btn'),
  appearanceTheme: document.getElementById('appearance-theme'),
  appearanceDensity: document.getElementById('appearance-density'),
  appearanceCompactMode: document.getElementById('appearance-compact-mode'),
  appearanceReducedMotion: document.getElementById('appearance-reduced-motion'),
  appearanceHighContrast: document.getElementById('appearance-high-contrast'),
  dashboardTipsToggle: document.getElementById('dashboard-tips-toggle'),
  linkedFormState: document.getElementById('linked-form-state'),
  notificationFormState: document.getElementById('notification-form-state'),
  appearanceFormState: document.getElementById('appearance-form-state'),

  sessionsList: document.getElementById('sessions-list'),
  sessionsRefreshBtn: document.getElementById('sessions-refresh-btn'),
  sessionsRevokeOthersBtn: document.getElementById('sessions-revoke-others-btn'),
  sessionsRevokeAllBtn: document.getElementById('sessions-revoke-all-btn'),
  devicesList: document.getElementById('devices-list'),
  devicesRefreshBtn: document.getElementById('devices-refresh-btn'),

  activityList: document.getElementById('activity-list'),
  activityKind: document.getElementById('activity-kind'),
  activityFilter: document.getElementById('activity-filter'),
  activityRefreshBtn: document.getElementById('activity-refresh-btn'),
  activityExportBtn: document.getElementById('activity-export-btn'),
  activityBars: document.getElementById('activity-bars'),
  activityTrendChart: document.getElementById('activity-trend-chart'),
  activityTrendSummary: document.getElementById('activity-trend-summary'),
  activityMixRing: document.getElementById('activity-mix-ring'),
  activityMixTotal: document.getElementById('activity-mix-total'),
  activityMixLegend: document.getElementById('activity-mix-legend'),
  activityHighlightGrid: document.getElementById('activity-highlight-grid'),

  ownerTab: document.getElementById('tab-owner'),
  ownerPanel: document.getElementById('owner'),
  ownerAccessChip: document.getElementById('owner-access-chip'),
  ownerSummaryCopy: document.getElementById('owner-summary-copy'),
  ownerTotalUsers: document.getElementById('owner-total-users'),
  ownerTotalOwners: document.getElementById('owner-total-owners'),
  ownerTotalSuspended: document.getElementById('owner-total-suspended'),
  ownerTotalFlagged: document.getElementById('owner-total-flagged'),
  ownerFilterForm: document.getElementById('owner-filter-form'),
  ownerSearch: document.getElementById('owner-search'),
  ownerRoleFilter: document.getElementById('owner-role-filter'),
  ownerStatusFilter: document.getElementById('owner-status-filter'),
  ownerApplyFiltersBtn: document.getElementById('owner-apply-filters-btn'),
  ownerRefreshBtn: document.getElementById('owner-refresh-btn'),
  ownerResultsSummary: document.getElementById('owner-results-summary'),
  ownerUserList: document.getElementById('owner-user-list'),
  ownerSelectedSummary: document.getElementById('owner-selected-summary'),
  ownerSelectedChips: document.getElementById('owner-selected-chips'),
  ownerUserForm: document.getElementById('owner-user-form'),
  ownerUserId: document.getElementById('owner-user-id'),
  ownerUserEmail: document.getElementById('owner-user-email'),
  ownerUserCreated: document.getElementById('owner-user-created'),
  ownerUserLastLogin: document.getElementById('owner-user-last-login'),
  ownerUserDisplayName: document.getElementById('owner-user-display-name'),
  ownerUserUsername: document.getElementById('owner-user-username'),
  ownerUserHeadline: document.getElementById('owner-user-headline'),
  ownerUserProfileRole: document.getElementById('owner-user-profile-role'),
  ownerUserOrganization: document.getElementById('owner-user-organization'),
  ownerUserLocation: document.getElementById('owner-user-location'),
  ownerUserRole: document.getElementById('owner-user-role'),
  ownerUserStatus: document.getElementById('owner-user-status'),
  ownerUserStatusReason: document.getElementById('owner-user-status-reason'),
  ownerUserVerified: document.getElementById('owner-user-verified'),
  ownerUserProfilePublic: document.getElementById('owner-user-profile-public'),
  ownerUserSearchable: document.getElementById('owner-user-searchable'),
  ownerUserVanguardTrusted: document.getElementById('owner-user-vanguard-trusted'),
  ownerUserVanguardStaff: document.getElementById('owner-user-vanguard-staff'),
  ownerUserVanguardFlagged: document.getElementById('owner-user-vanguard-flagged'),
  ownerUserVanguardBanned: document.getElementById('owner-user-vanguard-banned'),
  ownerUserVanguardFlagReason: document.getElementById('owner-user-vanguard-flag-reason'),
  ownerUserSaveBtn: document.getElementById('owner-user-save-btn'),
  ownerUserRevokeSessionsBtn: document.getElementById('owner-user-revoke-sessions-btn'),
  ownerUserResetMfaBtn: document.getElementById('owner-user-reset-mfa-btn'),
  ownerUserResendVerificationBtn: document.getElementById('owner-user-resend-verification-btn'),
  ownerUserSendResetBtn: document.getElementById('owner-user-send-reset-btn'),
  ownerUserDeleteBtn: document.getElementById('owner-user-delete-btn'),

  deleteForm: document.getElementById('delete-form'),
  deleteOpenBtn: document.getElementById('delete-open-btn'),
  deleteAccountBtn: document.getElementById('delete-account-btn'),
  deletePassword: document.getElementById('delete-password'),
  deleteConfirmText: document.getElementById('delete-confirm-text'),
  deleteChallengeRow: document.getElementById('delete-challenge-row'),
  deleteChallenge: document.getElementById('delete-challenge'),

  serviceFilter: document.getElementById('service-filter'),
  serviceList: document.getElementById('service-list'),
  serviceCards: Array.from(document.querySelectorAll('#service-list .card')),
  serviceResultsCount: document.getElementById('service-results-count'),
  serviceEmptyState: document.getElementById('service-empty-state'),
  favoriteFilterBtn: document.getElementById('favorite-filter-btn'),
  pinnedServices: document.getElementById('pinned-services'),
  openLauncherBtn: document.getElementById('open-launcher-btn'),
  serviceLauncherBtn: document.getElementById('service-launcher-btn'),
  jumpUnsavedBtn: document.getElementById('jump-unsaved-btn'),
  saveReminder: document.getElementById('save-reminder'),
  saveReminderText: document.getElementById('save-reminder-text'),
  saveReminderJumpBtn: document.getElementById('save-reminder-jump-btn'),
  securityFormState: document.getElementById('security-form-state'),
  launcherModal: document.getElementById('launcher-modal'),
  launcherOverlay: document.getElementById('launcher-overlay'),
  launcherCloseBtn: document.getElementById('launcher-close-btn'),
  launcherSearch: document.getElementById('launcher-search'),
  launcherList: document.getElementById('launcher-list'),
  launcherResultsCount: document.getElementById('launcher-results-count'),
  launcherEmptyState: document.getElementById('launcher-empty-state'),
  mfaModal: document.getElementById('mfa-modal'),
  mfaOverlay: document.getElementById('mfa-overlay'),
  mfaCloseBtn: document.getElementById('mfa-close-btn'),
  mfaModalTitle: document.getElementById('mfa-modal-title'),
  mfaModalCopy: document.getElementById('mfa-modal-copy'),
  passkeyModal: document.getElementById('passkey-modal'),
  passkeyOverlay: document.getElementById('passkey-overlay'),
  passkeyCloseBtn: document.getElementById('passkey-close-btn'),
  passkeyModalCopy: document.getElementById('passkey-modal-copy'),
  decisionModal: document.getElementById('decision-modal'),
  decisionOverlay: document.getElementById('decision-overlay'),
  decisionTitle: document.getElementById('decision-title'),
  decisionCopy: document.getElementById('decision-copy'),
  decisionForm: document.getElementById('decision-form'),
  decisionFields: document.getElementById('decision-fields'),
  decisionError: document.getElementById('decision-error'),
  decisionConfirmBtn: document.getElementById('decision-confirm-btn'),
  decisionCancelBtn: document.getElementById('decision-cancel-btn'),
  decisionDismissBtn: document.getElementById('decision-dismiss-btn'),
  deleteModal: document.getElementById('delete-modal'),
  deleteOverlay: document.getElementById('delete-overlay'),
  deleteCloseBtn: document.getElementById('delete-close-btn'),
  deleteCancelBtn: document.getElementById('delete-cancel-btn'),

  cookiePopup: document.getElementById('cookie-popup'),
  cookieAcceptBtn: document.getElementById('cookie-accept'),
};

const trimTrailingSlash = (value) => String(value || '').replace(/\/+$/, '');
const safeText = (value) => String(value || '').trim();
const readDraftInputValue = (element, fallback = '') => (element ? element.value : fallback);
const TRUSTED_API_MESSAGE_ORIGINS = new Set([
  'https://api.continental-hub.com',
  'https://auth.continental-hub.com',
  'https://id.continental-hub.com',
  'https://backend.continental-hub.com',
  'https://continental-hub.com',
  'https://login.continental-hub.com',
  'https://mpmc.ddns.net',
]);
const normalizeApiBaseUrl = (value) => {
  if (!value) return '';

  try {
    return trimTrailingSlash(new URL(value, window.location.origin).origin);
  } catch {
    return '';
  }
};
const readStoredApiBaseUrl = () => {
  try {
    return normalizeApiBaseUrl(window.localStorage?.getItem(API_BASE_STORAGE_KEY));
  } catch {
    return '';
  }
};
const rememberApiBaseUrl = (value) => {
  try {
    if (value) {
      window.localStorage?.setItem(API_BASE_STORAGE_KEY, trimTrailingSlash(value));
    }
  } catch {
    // localStorage can be unavailable in some embedded contexts.
  }
};
const readStoredArray = (key) => {
  try {
    const parsed = JSON.parse(localStorage.getItem(key) || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

const writeStoredArray = (key, values) => {
  localStorage.setItem(key, JSON.stringify(values));
};

const normalizeActivitySummary = (summary = {}) => ({
  last7Days: Number(summary?.last7Days || 0),
  last30Days: Number(summary?.last30Days || 0),
  uniqueIps: Number(summary?.uniqueIps || 0),
  recentDays: Array.isArray(summary?.recentDays) ? summary.recentDays : [],
});

const normalizePublicProfileSettings = (settings = {}) => ({
  headline: Boolean(settings?.headline),
  bio: Boolean(settings?.bio),
  location: Boolean(settings?.location),
  website: Boolean(settings?.website),
  linkedAccounts: Boolean(settings?.linkedAccounts),
  memberSince: Boolean(settings?.memberSince),
});

const createEmptyAvatarMeta = () => ({
  kind: '',
  mimeType: '',
  width: 0,
  height: 0,
  updatedAt: '',
});

const normalizeAvatarKind = (value, avatarValue = '') => {
  const normalized = safeText(value).toLowerCase();
  if (['upload', 'url', 'oauth'].includes(normalized)) {
    return normalized;
  }
  if (!safeText(avatarValue)) {
    return '';
  }
  return String(avatarValue).startsWith('data:image/') ? 'upload' : 'url';
};

const normalizeAvatarMeta = (meta = {}, avatarValue = '') => {
  const source = meta && typeof meta === 'object' ? meta : {};
  const width = Math.max(0, Math.min(AVATAR_REMOTE_MAX_DIMENSION, Math.round(Number(source.width) || 0)));
  const height = Math.max(0, Math.min(AVATAR_REMOTE_MAX_DIMENSION, Math.round(Number(source.height) || 0)));
  const normalizedUpdatedAt = safeText(source.updatedAt);

  return {
    kind: normalizeAvatarKind(source.kind, avatarValue),
    mimeType: /^image\/[-+.\w]+$/i.test(safeText(source.mimeType)) ? safeText(source.mimeType).toLowerCase() : '',
    width,
    height,
    updatedAt: normalizedUpdatedAt || '',
  };
};

const normalizeFocusAreas = (value) => {
  const rawValues = Array.isArray(value) ? value : String(value || '').split(/[,\n]/);
  const next = [];
  const seen = new Set();

  for (const entry of rawValues) {
    const cleaned = safeText(entry).slice(0, 32);
    if (!cleaned) continue;

    const key = cleaned.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    next.push(cleaned);

    if (next.length >= 8) {
      break;
    }
  }

  return next;
};

const normalizeMfaState = (mfa = {}) => ({
  enabled: Boolean(mfa?.enabled),
  hasPendingSetup: Boolean(mfa?.hasPendingSetup),
  enrolledAt: mfa?.enrolledAt || null,
  lastUsedAt: mfa?.lastUsedAt || null,
  backupCodesRemaining: Number(mfa?.backupCodesRemaining || 0),
});

const normalizePasskeyState = (passkeys = {}) => ({
  count: Math.max(0, Number(passkeys?.count || 0)),
  lastUsedAt: passkeys?.lastUsedAt || null,
  items: Array.isArray(passkeys?.items)
    ? passkeys.items.map((item) => ({
        credentialId: safeText(item?.credentialId),
        name: safeText(item?.name) || 'Passkey',
        createdAt: item?.createdAt || null,
        lastUsedAt: item?.lastUsedAt || null,
        transports: Array.isArray(item?.transports)
          ? item.transports.map((transport) => safeText(transport)).filter(Boolean)
          : [],
        deviceType: safeText(item?.deviceType) === 'multiDevice' ? 'multiDevice' : 'singleDevice',
        backedUp: Boolean(item?.backedUp),
      }))
    : [],
});

const getDefaultApiBaseUrl = () => {
  if (LOCAL_HOSTS.has(window.location.hostname)) {
    return 'http://localhost:5000';
  }

  if (HOSTED_STATIC_HOSTS.has(window.location.hostname)) {
    return HOSTED_API_BASE_URL;
  }

  return window.location.origin;
};

const getApiBaseCandidates = () => {
  const params = new URLSearchParams(window.location.search);
  const rawCandidates = [params.get('apiBaseUrl'), window.__API_BASE_URL__, readStoredApiBaseUrl()];

  if (LOCAL_HOSTS.has(window.location.hostname)) {
    rawCandidates.push('http://localhost:5000', window.location.origin);
  } else {
    rawCandidates.push(window.location.origin);
    rawCandidates.push(...PREFERRED_API_BASE_URLS);
    if (HOSTED_STATIC_HOSTS.has(window.location.hostname)) {
      rawCandidates.push(HOSTED_API_BASE_URL);
    }
  }

  const uniqueCandidates = [];
  for (const candidate of rawCandidates) {
    const normalized = normalizeApiBaseUrl(candidate);
    if (normalized && !uniqueCandidates.includes(normalized)) {
      uniqueCandidates.push(normalized);
    }
  }

  return uniqueCandidates;
};

let API_BASE_URL = getApiBaseCandidates()[0] || trimTrailingSlash(getDefaultApiBaseUrl());
let apiBaseValidated = false;
let apiBaseResolutionPromise = null;
const getAuthApiBase = () => `${API_BASE_URL}/api/auth`;

const looksLikeAuthHealthPayload = (payload) => {
  const status = safeText(payload?.status).toLowerCase();
  const timestamp = safeText(payload?.timestamp);
  if (!timestamp || !['ok'].includes(status)) {
    return false;
  }

  const service = safeText(payload?.service).toLowerCase();
  return !service || service.includes('auth') || service.includes('continental') || service.includes('id');
};

const probeApiBaseUrl = async (candidate) => {
  try {
    const response = await fetch(`${candidate}/api/health`, {
      cache: 'no-store',
    });
    const payload = await response.json().catch(() => null);
    return looksLikeAuthHealthPayload(payload);
  } catch {
    return false;
  }
};

const ensureApiBaseUrl = async () => {
  if (apiBaseValidated && API_BASE_URL) {
    return API_BASE_URL;
  }

  if (apiBaseResolutionPromise) {
    return apiBaseResolutionPromise;
  }

  apiBaseResolutionPromise = (async () => {
    const candidates = getApiBaseCandidates();
    for (const candidate of candidates) {
      if (await probeApiBaseUrl(candidate)) {
        API_BASE_URL = candidate;
        apiBaseValidated = true;
        rememberApiBaseUrl(candidate);
        return candidate;
      }
    }

    throw new Error(
      candidates.length
        ? `No healthy Continental ID auth API was found. Checked: ${candidates.join(', ')}.`
        : 'No API base URL was configured for Continental ID.'
    );
  })();

  try {
    return await apiBaseResolutionPromise;
  } catch (error) {
    apiBaseResolutionPromise = null;
    throw error;
  }
};

const getDefaultLoginPopupUrl = () => {
  if (LOCAL_HOSTS.has(window.location.hostname)) {
    return new URL('../login popup/popup.html', window.location.href).toString();
  }

  return 'https://login.continental-hub.com/popup.html';
};

const DEFAULT_LOGIN_POPUP_URL = getDefaultLoginPopupUrl();
const LOGIN_POPUP_URL = window.__LOGIN_POPUP_URL__ || DEFAULT_LOGIN_POPUP_URL;

const loginPopupOrigin = (() => {
  try {
    return new URL(LOGIN_POPUP_URL, window.location.href).origin;
  } catch {
    return null;
  }
})();

const getLoginPopupApiBaseUrl = () => {
  if (apiBaseValidated && API_BASE_URL) {
    return API_BASE_URL;
  }

  return trimTrailingSlash(getDefaultApiBaseUrl());
};

const buildLoginPopupUrl = () => {
  const popupUrl = new URL(LOGIN_POPUP_URL, window.location.href);
  popupUrl.searchParams.set('origin', window.location.origin);
  popupUrl.searchParams.set('redirect', window.location.href);
  popupUrl.searchParams.set('apiBaseUrl', getLoginPopupApiBaseUrl());
  return popupUrl;
};

const state = {
  user: null,
  activity: [],
  auditEvents: [],
  activitySummary: {
    last7Days: 0,
    last30Days: 0,
    uniqueIps: 0,
    recentDays: [],
  },
  ownerSummary: {
    totalUsers: 0,
    owners: 0,
    suspended: 0,
    flagged: 0,
  },
  ownerUsers: [],
  ownerSelectedUserId: '',
  ownerSelectedUser: null,
  ownerSelectedAuditEvents: [],
  sessions: [],
  devices: [],
  sessionLimit: null,
  accessToken: '',
  authEpoch: 0,
  loginPopupWindow: null,
  appVisible: false,
  refreshTimer: null,
  refreshPromise: null,
  lastSyncAt: null,
  favoriteServices: new Set(readStoredArray(SERVICE_FAVORITES_STORAGE_KEY)),
  favoriteServicesOnly: localStorage.getItem(FAVORITE_SERVICES_ONLY_STORAGE_KEY) === 'true',
  recentServices: readStoredArray(SERVICE_RECENT_STORAGE_KEY).map((value) => safeText(value).toLowerCase()).filter(Boolean),
  activeTab: 'overview',
  landingPrimaryAction: 'signin',
  profileAvatarDraft: '',
  profileAvatarMetaDraft: createEmptyAvatarMeta(),
  profileAvatarStatus: {
    state: 'empty',
    message: '',
    detail: '',
  },
  profileAvatarValidationId: 0,
  profileAvatarValidationTimer: null,
  mfaSetup: null,
  mfaSetupOpen: false,
  mfaManageMode: '',
  mfaLastFocusedElement: null,
  passkeyModalOpen: false,
  passkeyLastFocusedElement: null,
  deleteModalOpen: false,
  deleteLastFocusedElement: null,
  decisionModalConfig: null,
  decisionModalResolver: null,
  decisionLastFocusedElement: null,
  launcherOpen: false,
  launcherActiveIndex: 0,
  launcherLastFocusedElement: null,
};

const collapsibleSections = new Map();
let collapsibleSectionsFrame = 0;
let collapsibleSectionsObserver = null;

const getCollapsibleSectionMaxHeight = (element) =>
  Math.max(0, Number.parseInt(element?.dataset?.collapsibleMaxHeight || '0', 10) || 0);

const syncCollapsibleSection = (element) => {
  if (!(element instanceof HTMLElement)) return;

  const entry = collapsibleSections.get(element);
  if (!entry?.button) return;

  const maxHeight = getCollapsibleSectionMaxHeight(element);
  const label = safeText(element.dataset.collapsibleLabel).toLowerCase() || 'details';
  const needsClamp = !element.hidden && maxHeight > 0 && element.scrollHeight > maxHeight + 16;

  element.style.setProperty('--collapsed-height', `${maxHeight}px`);
  element.classList.toggle('is-collapsible', needsClamp);
  element.classList.toggle('is-expanded', needsClamp && entry.expanded);

  entry.button.hidden = !needsClamp;
  entry.button.disabled = !needsClamp;
  entry.button.setAttribute('aria-expanded', needsClamp && entry.expanded ? 'true' : 'false');
  entry.button.textContent = needsClamp && entry.expanded ? `Show less ${label}` : `See more ${label}`;

  if (!needsClamp) {
    entry.expanded = false;
    element.classList.remove('is-expanded');
  }
};

const requestCollapsibleSectionsSync = () => {
  if (collapsibleSectionsFrame) return;

  collapsibleSectionsFrame = window.requestAnimationFrame(() => {
    collapsibleSectionsFrame = 0;
    for (const element of collapsibleSections.keys()) {
      syncCollapsibleSection(element);
    }
  });
};

const setupCollapsibleSections = () => {
  const elements = document.querySelectorAll('[data-collapsible-max-height]');
  if (!elements.length) return;

  if (!collapsibleSectionsObserver && 'ResizeObserver' in window) {
    collapsibleSectionsObserver = new ResizeObserver(() => {
      requestCollapsibleSectionsSync();
    });
  }

  for (const element of elements) {
    if (collapsibleSections.has(element)) continue;

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'ghost-btn collapsible-toggle';
    button.hidden = true;
    button.addEventListener('click', () => {
      const entry = collapsibleSections.get(element);
      if (!entry) return;

      entry.expanded = !entry.expanded;
      syncCollapsibleSection(element);
    });

    element.insertAdjacentElement('afterend', button);
    collapsibleSections.set(element, {
      button,
      expanded: false,
    });

    collapsibleSectionsObserver?.observe(element);
  }

  window.addEventListener('resize', requestCollapsibleSectionsSync);
  requestCollapsibleSectionsSync();
};

const requiresSensitiveActionMfa = () => Boolean(state.user?.security?.mfa?.enabled);

const parseSensitiveMfaInput = (value) => {
  const normalized = safeText(value).toUpperCase().replace(/[^A-Z0-9-]/g, '');
  if (!normalized) {
    return { mfaCode: '', backupCode: '' };
  }

  if (/^\d{6,8}$/.test(normalized)) {
    return { mfaCode: normalized, backupCode: '' };
  }

  return { mfaCode: '', backupCode: normalized };
};

const isMfaModalOpen = () => Boolean(state.mfaSetupOpen || state.mfaManageMode);
const isPasskeyModalOpen = () => Boolean(state.passkeyModalOpen);
const isDeleteModalOpen = () => Boolean(state.deleteModalOpen);
const isDecisionModalOpen = () => Boolean(state.decisionModalResolver);
const isAnyOverlayOpen = () =>
  Boolean(state.launcherOpen || isMfaModalOpen() || isPasskeyModalOpen() || isDeleteModalOpen() || isDecisionModalOpen());

const syncOverlayLock = () => {
  document.body.classList.toggle('launcher-open', isAnyOverlayOpen());
};

const clearDecisionError = () => {
  if (!dom.decisionError) return;
  dom.decisionError.hidden = true;
  dom.decisionError.textContent = '';
};

const showDecisionError = (message) => {
  if (!dom.decisionError) {
    showToast(message, 'error');
    return;
  }
  dom.decisionError.hidden = false;
  dom.decisionError.textContent = message;
};

const closeDecisionModal = (result = null, options = {}) => {
  const { skipFocusRestore = false } = options;
  const resolver = state.decisionModalResolver;

  state.decisionModalConfig = null;
  state.decisionModalResolver = null;
  if (dom.decisionModal) dom.decisionModal.hidden = true;
  if (dom.decisionFields) dom.decisionFields.innerHTML = '';
  clearDecisionError();
  syncOverlayLock();

  if (!skipFocusRestore) {
    state.decisionLastFocusedElement?.focus?.();
  }
  state.decisionLastFocusedElement = null;

  resolver?.(result);
};

const submitDecisionModal = () => {
  const config = state.decisionModalConfig;
  if (!config) return;

  const values = {};
  for (const field of config.fields || []) {
    const input = document.getElementById(field.id);
    values[field.name || field.id] = input?.value || '';
  }

  if (typeof config.validate === 'function') {
    const error = config.validate(values);
    if (error) {
      showDecisionError(error);
      return;
    }
  }

  closeDecisionModal(values, { skipFocusRestore: Boolean(config.skipFocusRestoreOnConfirm) });
};

const renderDecisionModal = () => {
  if (!dom.decisionModal || !dom.decisionTitle || !dom.decisionCopy || !dom.decisionFields || !dom.decisionConfirmBtn) return;

  const config = state.decisionModalConfig;
  dom.decisionModal.hidden = !config;
  syncOverlayLock();
  clearDecisionError();

  if (!config) return;

  dom.decisionTitle.textContent = config.title || 'Review this action';
  dom.decisionCopy.textContent = config.copy || 'Continue only if this is what you intended.';
  dom.decisionConfirmBtn.textContent = config.confirmLabel || 'Continue';
  dom.decisionConfirmBtn.className = config.confirmClassName || 'primary-btn';
  dom.decisionConfirmBtn.dataset.defaultLabel = config.confirmLabel || 'Continue';
  if (dom.decisionDismissBtn) dom.decisionDismissBtn.textContent = config.cancelLabel || 'Cancel';
  if (dom.decisionCancelBtn) dom.decisionCancelBtn.textContent = config.closeLabel || 'Close';

  dom.decisionFields.innerHTML = '';
  for (const field of config.fields || []) {
    const label = document.createElement('label');
    if (field.wide) label.className = 'wide-field';
    label.textContent = field.label;

    const input = document.createElement('input');
    input.id = field.id;
    input.type = field.type || 'text';
    input.value = field.value || '';
    if (field.placeholder) input.placeholder = field.placeholder;
    if (field.autocomplete) input.autocomplete = field.autocomplete;
    if (field.inputmode) input.inputMode = field.inputmode;
    if (field.pattern) input.pattern = field.pattern;
    if (field.required) input.required = true;
    if (field.maxlength) input.maxLength = field.maxlength;
    label.appendChild(input);
    dom.decisionFields.appendChild(label);
  }

  window.setTimeout(() => {
    const firstField = config.fields?.length ? document.getElementById(config.fields[0].id) : dom.decisionConfirmBtn;
    firstField?.focus?.();
    if (config.fields?.length && typeof firstField?.select === 'function' && config.fields[0].selectOnFocus) {
      firstField.select();
    }
  }, 0);
};

const openDecisionModal = (config) =>
  new Promise((resolve) => {
    state.decisionModalConfig = {
      confirmLabel: 'Continue',
      cancelLabel: 'Cancel',
      closeLabel: 'Close',
      confirmClassName: 'primary-btn',
      fields: [],
      ...config,
    };
    state.decisionModalResolver = resolve;
    state.decisionLastFocusedElement = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    renderDecisionModal();
  });

const requestSensitiveActionMfa = async (actionLabel) => {
  if (!requiresSensitiveActionMfa()) {
    return { mfaCode: '', backupCode: '' };
  }

  const result = await openDecisionModal({
    title: 'Confirm with MFA',
    copy: `Enter a current authenticator code or backup code to ${actionLabel}.`,
    confirmLabel: 'Continue',
    fields: [
      {
        id: 'decision-mfa-challenge',
        name: 'challenge',
        label: 'Authenticator code or backup code',
        placeholder: '123456 or backup code',
        autocomplete: 'one-time-code',
        inputmode: 'text',
        required: true,
      },
    ],
    validate: (values) => {
      const parsed = parseSensitiveMfaInput(values.challenge);
      return parsed.mfaCode || parsed.backupCode ? '' : 'Enter a current MFA code or backup code.';
    },
  });

  if (!result) {
    return null;
  }

  return parseSensitiveMfaInput(result.challenge);
};

const clearMfaManageInputs = () => {
  if (dom.mfaManageCurrentPassword) dom.mfaManageCurrentPassword.value = '';
  if (dom.mfaManageChallenge) dom.mfaManageChallenge.value = '';
};

const getMfaManageConfig = (mode = state.mfaManageMode) => {
  if (mode === 'disable') {
    return {
      title: 'Disable MFA',
      copy: 'Enter your current password and a current authenticator code or backup code to turn MFA off.',
      confirmLabel: 'Disable MFA',
      confirmClassName: 'danger-btn',
      busyLabel: 'Disabling...',
      endpoint: '/mfa/disable',
      successMessage: 'MFA disabled.',
    };
  }

  if (mode === 'backup') {
    return {
      title: 'Regenerate backup codes',
      copy: 'Enter your current password and a current authenticator code or backup code to create a fresh backup code set.',
      confirmLabel: 'Regenerate Codes',
      confirmClassName: 'primary-btn',
      busyLabel: 'Regenerating...',
      endpoint: '/mfa/regenerate-backup-codes',
      successMessage: 'Backup codes regenerated.',
    };
  }

  return null;
};

const getMfaSetupFocusTarget = () => (state.mfaSetup?.secret ? dom.mfaCode : dom.mfaCurrentPassword);

const renderMfaModal = () => {
  if (!dom.mfaModal) return;

  const isOpen = isMfaModalOpen();
  dom.mfaModal.hidden = !isOpen;
  syncOverlayLock();

  if (!dom.mfaModalTitle || !dom.mfaModalCopy) return;

  if (state.mfaManageMode === 'disable') {
    dom.mfaModalTitle.textContent = 'Disable multi-factor authentication';
    dom.mfaModalCopy.textContent = 'Confirm this sensitive change with your password and a current MFA code or backup code.';
    return;
  }

  if (state.mfaManageMode === 'backup') {
    dom.mfaModalTitle.textContent = 'Regenerate backup codes';
    dom.mfaModalCopy.textContent = 'Create a fresh backup code set without losing your place on the page.';
    return;
  }

  dom.mfaModalTitle.textContent = state.mfaSetup?.secret ? 'Finish MFA setup' : 'Set up multi-factor authentication';
  dom.mfaModalCopy.textContent = state.mfaSetup?.secret
    ? 'Your authenticator is almost connected. Finish the remaining step here.'
    : 'Work through setup in one focused overlay instead of inside the page.';
};

const openMfaSetupPanel = () => {
  state.mfaSetupOpen = true;
  state.mfaManageMode = '';
  state.mfaLastFocusedElement = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  clearMfaManageInputs();
  renderMfaModal();
  renderMfaState(state.user);

  window.setTimeout(() => {
    getMfaSetupFocusTarget()?.focus();
  }, 0);
};

const closeMfaSetupPanel = () => {
  state.mfaSetupOpen = false;
  if (!state.mfaSetup?.secret) {
    if (dom.mfaCurrentPassword) dom.mfaCurrentPassword.value = '';
    if (dom.mfaCode) dom.mfaCode.value = '';
  }
  renderMfaModal();
  renderMfaState(state.user);
  state.mfaLastFocusedElement?.focus?.();
  state.mfaLastFocusedElement = null;
};

const clearPasskeyInputs = () => {
  if (dom.passkeyCurrentPassword) dom.passkeyCurrentPassword.value = '';
  if (dom.passkeyChallenge) dom.passkeyChallenge.value = '';
};

const renderPasskeyModal = () => {
  if (!dom.passkeyModal) return;
  dom.passkeyModal.hidden = !state.passkeyModalOpen;
  syncOverlayLock();
  if (dom.passkeyChallengeRow) dom.passkeyChallengeRow.hidden = !requiresSensitiveActionMfa();
  if (dom.passkeyModalCopy) {
    dom.passkeyModalCopy.textContent = requiresSensitiveActionMfa()
      ? 'Add or remove passkeys here. MFA-protected accounts also need a current authenticator code or backup code.'
      : 'Add or remove passkeys here without stretching the security tab.';
  }
};

const openPasskeyModal = () => {
  state.passkeyModalOpen = true;
  state.passkeyLastFocusedElement = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  renderPasskeyModal();
  renderPasskeys(state.user);
  window.setTimeout(() => {
    dom.passkeyCurrentPassword?.focus();
  }, 0);
};

const closePasskeyModal = () => {
  state.passkeyModalOpen = false;
  clearPasskeyInputs();
  renderPasskeyModal();
  state.passkeyLastFocusedElement?.focus?.();
  state.passkeyLastFocusedElement = null;
};

const getPasskeyModalMfa = () => {
  if (!requiresSensitiveActionMfa()) {
    return { mfaCode: '', backupCode: '' };
  }

  const parsed = parseSensitiveMfaInput(dom.passkeyChallenge?.value || '');
  if (!parsed.mfaCode && !parsed.backupCode) {
    showToast('Enter a current authenticator code or backup code.', 'error');
    dom.passkeyChallenge?.focus();
    return null;
  }

  return parsed;
};

const renderDeleteModal = () => {
  if (!dom.deleteModal) return;
  dom.deleteModal.hidden = !state.deleteModalOpen;
  syncOverlayLock();
  if (dom.deleteChallengeRow) dom.deleteChallengeRow.hidden = !requiresSensitiveActionMfa();
};

const openDeleteModal = () => {
  state.deleteModalOpen = true;
  state.deleteLastFocusedElement = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  renderDeleteModal();
  window.setTimeout(() => {
    dom.deletePassword?.focus();
  }, 0);
};

const closeDeleteModal = () => {
  state.deleteModalOpen = false;
  if (dom.deleteForm) dom.deleteForm.reset();
  renderDeleteModal();
  state.deleteLastFocusedElement?.focus?.();
  state.deleteLastFocusedElement = null;
};

const openMfaManagePanel = (mode) => {
  if (!mode) return;

  state.mfaManageMode = mode;
  state.mfaLastFocusedElement = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  clearMfaManageInputs();
  renderMfaModal();
  renderMfaState(state.user);

  window.setTimeout(() => {
    dom.mfaManageCurrentPassword?.focus();
  }, 0);
};

const closeMfaManagePanel = () => {
  state.mfaManageMode = '';
  clearMfaManageInputs();
  renderMfaModal();
  renderMfaState(state.user);
  state.mfaLastFocusedElement?.focus?.();
  state.mfaLastFocusedElement = null;
};

const openMfaSecuritySection = () => {
  switchTab('security');
  openMfaSetupPanel();
};

const trackedForms = [
  dom.profileForm,
  dom.linkedForm,
  dom.securityForm,
  dom.privacyForm,
  dom.notificationForm,
  dom.appearanceForm,
];

const formatDate = (value) => {
  const date = new Date(value || '');
  if (Number.isNaN(date.getTime())) return 'Unavailable';
  return date.toLocaleString();
};

const formatDateCompact = (value, options = {}) => {
  const date = new Date(value || '');
  if (Number.isNaN(date.getTime())) return 'Unavailable';
  return date.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    ...options,
  });
};

const getOauthProviderLabel = (provider) => {
  const normalized = safeText(provider).toLowerCase();
  if (normalized === 'github') return 'GitHub';
  if (normalized === 'google') return 'Google';
  if (normalized === 'discord') return 'Discord';
  if (normalized === 'microsoft') return 'Microsoft';
  return normalized ? normalized[0].toUpperCase() + normalized.slice(1) : 'Identity provider';
};

const normalizeOauthProviderState = (provider, source = {}) => ({
  provider: safeText(source?.provider || provider).toLowerCase() || safeText(provider).toLowerCase(),
  linked: Boolean(source?.linked),
  available: Boolean(source?.available),
  username: safeText(source?.username),
  email: safeText(source?.email),
  profileUrl: safeText(source?.profileUrl),
  linkedAt: source?.linkedAt || null,
  lastUsedAt: source?.lastUsedAt || null,
});

const normalizeVanguardState = (source = {}) => ({
  linkedDiscord: Boolean(source?.linkedDiscord),
  discordUserId: safeText(source?.discordUserId),
  linkedAt: source?.linkedAt || null,
  lastUsedAt: source?.lastUsedAt || null,
  trusted: Boolean(source?.trusted),
  staff: Boolean(source?.staff),
  flagged: Boolean(source?.flagged),
  bannedFromAi: Boolean(source?.bannedFromAi),
  flagReason: safeText(source?.flagReason, 240),
  flaggedAt: source?.flaggedAt || null,
});

const getVanguardState = (user = state.user) => normalizeVanguardState(user?.vanguard);

const getOauthProviderElements = (provider) => {
  const normalized = safeText(provider).toLowerCase();
  if (normalized === 'github') {
    return {
      status: dom.oauthGithubStatus,
      connectBtn: dom.oauthGithubConnectBtn,
      unlinkBtn: dom.oauthGithubUnlinkBtn,
    };
  }
  if (normalized === 'google') {
    return {
      status: dom.oauthGoogleStatus,
      connectBtn: dom.oauthGoogleConnectBtn,
      unlinkBtn: dom.oauthGoogleUnlinkBtn,
    };
  }
  if (normalized === 'discord') {
    return {
      status: dom.oauthDiscordStatus,
      connectBtn: dom.oauthDiscordConnectBtn,
      unlinkBtn: dom.oauthDiscordUnlinkBtn,
    };
  }
  if (normalized === 'microsoft') {
    return {
      status: dom.oauthMicrosoftStatus,
      connectBtn: dom.oauthMicrosoftConnectBtn,
      unlinkBtn: dom.oauthMicrosoftUnlinkBtn,
    };
  }

  return {
    status: null,
    connectBtn: null,
    unlinkBtn: null,
  };
};

const renderOauthProviders = (user = state.user) => {
  if (!user) {
    for (const provider of OAUTH_PROVIDERS) {
      const elements = getOauthProviderElements(provider);
      if (elements.status) {
        elements.status.textContent = 'Sign in to manage verified identity providers.';
      }
      if (elements.connectBtn) {
        elements.connectBtn.hidden = false;
        elements.connectBtn.disabled = true;
      }
      if (elements.unlinkBtn) {
        elements.unlinkBtn.hidden = true;
        elements.unlinkBtn.disabled = true;
      }
    }
    return;
  }

  for (const provider of OAUTH_PROVIDERS) {
    const oauthProvider = normalizeOauthProviderState(provider, user?.oauthProviders?.[provider]);
    const providerLabel = getOauthProviderLabel(provider);
    const elements = getOauthProviderElements(provider);

    if (elements.status) {
      if (oauthProvider.linked) {
        const identityBits = [
          oauthProvider.username ? `@${oauthProvider.username}` : '',
          oauthProvider.email ? oauthProvider.email : '',
        ].filter(Boolean);
        const identityText =
          identityBits.length ? identityBits.join(' | ') : `${providerLabel} account linked`;
        const activityText = oauthProvider.lastUsedAt
          ? `Last used ${formatDate(oauthProvider.lastUsedAt)}.`
          : 'Ready for sign-in.';
        elements.status.textContent = `${identityText}. ${activityText}`;
      } else if (!oauthProvider.available) {
        elements.status.textContent = `${providerLabel} sign-in is not configured on this deployment yet.`;
      } else {
        elements.status.textContent = `Link ${providerLabel} to add a verified sign-in method and provider-backed identity.`;
      }
    }

    if (elements.connectBtn) {
      elements.connectBtn.hidden = oauthProvider.linked;
      elements.connectBtn.disabled = !oauthProvider.available || oauthProvider.linked;
    }

    if (elements.unlinkBtn) {
      elements.unlinkBtn.hidden = !oauthProvider.linked;
      elements.unlinkBtn.disabled = !oauthProvider.linked;
    }
  }
};

const renderVanguardIdentity = (user = state.user) => {
  if (!dom.vanguardIdentityStatus || !dom.vanguardLinkChip || !dom.vanguardStandingChip) {
    return;
  }

  if (!user) {
    dom.vanguardIdentityStatus.textContent =
      'Sign in to review how this Continental ID account appears to Vanguard-aware services.';
    dom.vanguardLinkChip.textContent = 'Discord not linked';
    dom.vanguardStandingChip.textContent = 'Brand standing unknown';
    if (dom.vanguardIdentityDetail) {
      dom.vanguardIdentityDetail.textContent =
        'This is read-only account status. Vanguard itself is still managed outside this dashboard.';
    }
    if (dom.vanguardOpenDiscordLinkBtn) {
      dom.vanguardOpenDiscordLinkBtn.textContent = 'Review Discord identity';
      dom.vanguardOpenDiscordLinkBtn.disabled = true;
      dom.vanguardOpenDiscordLinkBtn.onclick = null;
    }
    return;
  }

  const discordOauth = normalizeOauthProviderState('discord', user?.oauthProviders?.discord);
  const vanguard = getVanguardState(user);

  dom.vanguardLinkChip.textContent = vanguard.linkedDiscord ? 'Discord linked' : 'Discord not linked';

  let standingLabel = 'Brand standing clear';
  if (vanguard.bannedFromAi) {
    standingLabel = 'Restricted for AI';
  } else if (vanguard.flagged) {
    standingLabel = 'Needs review';
  } else if (vanguard.staff) {
    standingLabel = 'Staff identity';
  } else if (vanguard.trusted) {
    standingLabel = 'Trusted brand standing';
  }
  dom.vanguardStandingChip.textContent = standingLabel;

  if (vanguard.linkedDiscord) {
    const activityText = vanguard.lastUsedAt
      ? `Last recognized ${formatDate(vanguard.lastUsedAt)}.`
      : vanguard.linkedAt
        ? `Linked ${formatDate(vanguard.linkedAt)}.`
        : 'Linked and available for recognition.';
    dom.vanguardIdentityStatus.textContent =
      `This Continental ID account can be recognized by Vanguard-aware services through Discord identity. ${activityText}`;
  } else if (discordOauth.available) {
    dom.vanguardIdentityStatus.textContent =
      'Link Discord sign-in if you want Vanguard-aware services to recognize this Continental ID account.';
  } else {
    dom.vanguardIdentityStatus.textContent =
      'Discord sign-in is not configured on this deployment, so Vanguard-aware recognition is not available here yet.';
  }

  if (dom.vanguardIdentityDetail) {
    const details = [];
    if (vanguard.bannedFromAi) {
      details.push('This account is restricted from Vanguard AI features.');
    } else if (vanguard.flagged) {
      details.push(
        vanguard.flagReason
          ? `Brand standing is under review: ${vanguard.flagReason}.`
          : 'Brand standing is currently marked for review.'
      );
    } else if (vanguard.staff) {
      details.push('This account is marked as staff at the brand identity layer.');
    } else if (vanguard.trusted) {
      details.push('This account is marked as trusted at the brand identity layer.');
    } else {
      details.push('No Vanguard-related restrictions are currently attached to this account.');
    }
    details.push('This dashboard does not control Vanguard itself.');
    dom.vanguardIdentityDetail.textContent = details.join(' ');
  }

  if (dom.vanguardOpenDiscordLinkBtn) {
    dom.vanguardOpenDiscordLinkBtn.textContent = vanguard.linkedDiscord
      ? 'Review Discord identity'
      : 'Connect Discord';
    dom.vanguardOpenDiscordLinkBtn.disabled = !discordOauth.available && !vanguard.linkedDiscord;
    dom.vanguardOpenDiscordLinkBtn.onclick = () => {
      if (vanguard.linkedDiscord) {
        dom.oauthDiscordUnlinkBtn?.focus();
        return;
      }
      handleOauthLink('discord');
    };
  }
};

const getLocalDayKey = (value) => {
  const date = new Date(value || '');
  if (Number.isNaN(date.getTime())) return '';
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
};

const formatTimelineDayHeading = (value) => {
  const date = new Date(value || '');
  if (Number.isNaN(date.getTime())) return 'Earlier';

  const now = new Date();
  const todayKey = getLocalDayKey(now);
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  const yesterdayKey = getLocalDayKey(yesterday);
  const dayKey = getLocalDayKey(date);

  if (dayKey === todayKey) return 'Today';
  if (dayKey === yesterdayKey) return 'Yesterday';

  return date.toLocaleDateString(undefined, {
    weekday: 'long',
    month: 'short',
    day: 'numeric',
  });
};

const formatTrendLabel = (value) => {
  const date = new Date(value || '');
  if (Number.isNaN(date.getTime())) return '--';
  return date.toLocaleDateString(undefined, {
    weekday: 'short',
  });
};

const getInitialsFromSource = (source) => {
  const parts = safeText(source)
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2);

  if (!parts.length) return 'CI';
  return parts.map((part) => part[0].toUpperCase()).join('');
};

const isDashboardTipsEnabled = () => localStorage.getItem('dashboardTipsEnabled') !== 'false';
const persistServicePreferences = () => {
  writeStoredArray(SERVICE_FAVORITES_STORAGE_KEY, Array.from(state.favoriteServices).sort());
  localStorage.setItem(
    FAVORITE_SERVICES_ONLY_STORAGE_KEY,
    state.favoriteServicesOnly ? 'true' : 'false'
  );
};

const persistRecentServices = () => {
  writeStoredArray(SERVICE_RECENT_STORAGE_KEY, state.recentServices.slice(0, 6));
};

const trackServiceLaunch = (key) => {
  const normalizedKey = safeText(key).toLowerCase();
  if (!normalizedKey) return;

  state.recentServices = [normalizedKey, ...state.recentServices.filter((entry) => entry !== normalizedKey)].slice(0, 6);
  persistRecentServices();
};

const getRecentServiceIndex = (key) => {
  const normalizedKey = safeText(key).toLowerCase();
  const index = state.recentServices.indexOf(normalizedKey);
  return index === -1 ? Number.MAX_SAFE_INTEGER : index;
};

const getServiceEntries = () =>
  dom.serviceCards.map((card) => {
    const key = safeText(card.dataset.key).toLowerCase();
    const link = card.querySelector('.service-link');
    return {
      key,
      title: safeText(card.dataset.title),
      category: safeText(card.dataset.category),
      description: safeText(card.dataset.description),
      href: safeText(link?.href),
      card,
      pinned: state.favoriteServices.has(key),
      recentIndex: getRecentServiceIndex(key),
    };
  });

const sortServiceEntries = (entries) =>
  [...entries].sort((left, right) => {
    if (left.pinned !== right.pinned) {
      return left.pinned ? -1 : 1;
    }
    if (left.recentIndex !== right.recentIndex) {
      return left.recentIndex - right.recentIndex;
    }
    return left.title.localeCompare(right.title);
  });

const getActiveSessionCount = () =>
  Number(state.user?.security?.activeSessions ?? state.sessions.length ?? 0);

const updateSessionNote = () => {
  if (!dom.sessionLimitNote) return;

  const limitText = state.sessionLimit ? `${state.sessionLimit}` : '--';
  const knownDevices = Number(state.user?.security?.knownDevices || 0);
  dom.sessionLimitNote.textContent = knownDevices
    ? `Limit: ${limitText} | Devices: ${knownDevices}`
    : `Limit: ${limitText}`;
};

const getUsername = (user = state.user) => safeText(user?.username).toLowerCase();
const getUserHandle = (user = state.user) => {
  const username = getUsername(user);
  return username ? `@${username}` : '';
};
const getAvatarValue = (user = state.user) => safeText(user?.profile?.avatar);
const getAvatarMeta = (user = state.user) => normalizeAvatarMeta(user?.profile?.avatarMeta, getAvatarValue(user));

const getIdentityName = (user = state.user) =>
  safeText(user?.displayName || getUsername(user) || user?.email || user?.continentalId || user?.userId || 'Continental User');

const getIdentityInitials = (user = state.user) => {
  return getInitialsFromSource(getIdentityName(user));
};

const getFirstName = (user = state.user) => {
  const source = safeText(user?.displayName || getUsername(user) || user?.email || 'there');
  return source.split(/[\s@._-]+/).filter(Boolean)[0] || 'there';
};

const getMigrationState = (user = state.user) =>
  user?.migration && typeof user.migration === 'object' ? user.migration : {};

const normalizeOwnerSummary = (summary = {}) => ({
  totalUsers: Math.max(0, Number(summary?.totalUsers || 0)),
  owners: Math.max(0, Number(summary?.owners || 0)),
  suspended: Math.max(0, Number(summary?.suspended || 0)),
  flagged: Math.max(0, Number(summary?.flagged || 0)),
});

const getAuthorityState = (user = state.user) =>
  user?.authority && typeof user.authority === 'object' ? user.authority : {};

const isOwnerUser = (user = state.user) => Boolean(getAuthorityState(user).isOwner);

const getSelectedOwnerUser = () => {
  if (state.ownerSelectedUser && state.ownerSelectedUser.userId === state.ownerSelectedUserId) {
    return state.ownerSelectedUser;
  }
  return state.ownerUsers.find((entry) => entry.userId === state.ownerSelectedUserId) || null;
};

const normalizeAvatarInput = (value) => {
  const raw = safeText(value);
  if (!raw) return '';

  if (/^data:image\/(?:png|jpe?g|gif|webp);base64,[a-z0-9+/=]+$/i.test(raw)) {
    return raw.length <= AVATAR_DATA_URL_MAX_LENGTH ? raw : null;
  }

  const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  try {
    const parsed = new URL(withProtocol);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    return parsed.toString();
  } catch {
    return null;
  }
};

const formatAvatarDimensions = (width, height) => {
  const normalizedWidth = Math.max(0, Number(width) || 0);
  const normalizedHeight = Math.max(0, Number(height) || 0);
  if (!normalizedWidth || !normalizedHeight) {
    return '';
  }
  return `${normalizedWidth} x ${normalizedHeight}`;
};

const guessAvatarMimeTypeFromUrl = (url) => {
  try {
    const pathname = new URL(url).pathname.toLowerCase();
    if (pathname.endsWith('.png')) return 'image/png';
    if (pathname.endsWith('.jpg') || pathname.endsWith('.jpeg')) return 'image/jpeg';
    if (pathname.endsWith('.gif')) return 'image/gif';
    if (pathname.endsWith('.webp')) return 'image/webp';
    if (pathname.endsWith('.avif')) return 'image/avif';
  } catch {
    return '';
  }
  return '';
};

const getAvatarStatusCopy = () => {
  const current = state.profileAvatarStatus || {};
  if (current.state === 'validating') {
    return {
      message: current.message || 'Checking the image URL before saving.',
      detail: current.detail || 'If the image cannot load here, it will not be saved.',
    };
  }
  if (current.state === 'error') {
    return {
      message: current.message || 'Avatar needs attention before it can be saved.',
      detail: current.detail || 'Use an uploaded image or a direct URL the browser can actually load.',
    };
  }
  if (current.state === 'ready') {
    return {
      message: current.message || 'Avatar is ready to save.',
      detail: current.detail || 'Rendering includes live fallback handling if the image breaks later.',
    };
  }
  return {
    message: 'Upload, drag, paste an image, or paste a direct image URL.',
    detail: 'Square crop, live validation, and fallback rendering are built in.',
  };
};

const setAvatarDraftStatus = (nextState = 'empty', message = '', detail = '') => {
  state.profileAvatarStatus = {
    state: nextState,
    message,
    detail,
  };
  if (dom.profileAvatarCard) {
    dom.profileAvatarCard.dataset.avatarStatus = nextState;
  }
  updateProfileAvatarHelper();
};

const clearAvatarValidationTimer = () => {
  if (!state.profileAvatarValidationTimer) return;
  window.clearTimeout(state.profileAvatarValidationTimer);
  state.profileAvatarValidationTimer = null;
};

const loadImageSource = (src, options = {}) =>
  new Promise((resolve, reject) => {
    const image = new Image();
    const timeoutMs = Math.max(1000, Number(options.timeoutMs) || AVATAR_RENDER_TIMEOUT_MS);
    const cleanup = () => {
      window.clearTimeout(timeoutId);
      image.onload = null;
      image.onerror = null;
    };
    const timeoutId = window.setTimeout(() => {
      cleanup();
      reject(new Error('Image request timed out.'));
    }, timeoutMs);

    image.decoding = 'async';
    image.referrerPolicy = 'no-referrer';
    image.onload = () => {
      cleanup();
      resolve({
        image,
        width: Number(image.naturalWidth || image.width || 0),
        height: Number(image.naturalHeight || image.height || 0),
      });
    };
    image.onerror = () => {
      cleanup();
      reject(new Error('Image could not be loaded.'));
    };
    image.src = src;
  });

const setAvatarElement = (element, avatarValue, fallbackText, options = {}) => {
  if (!element) return;

  const normalized = normalizeAvatarInput(avatarValue);
  const altText = safeText(options.altText);

  element.innerHTML = '';
  element.classList.remove('has-image', 'is-loading', 'is-broken');

  const fallback = document.createElement('span');
  fallback.className = 'identity-badge-fallback';
  fallback.textContent = fallbackText;
  element.appendChild(fallback);

  if (!normalized) {
    return;
  }

  const image = document.createElement('img');
  image.className = 'identity-badge-image';
  image.alt = altText;
  image.decoding = 'async';
  image.loading = 'lazy';
  image.referrerPolicy = 'no-referrer';
  image.addEventListener('load', () => {
    element.classList.remove('is-loading', 'is-broken');
    element.classList.add('has-image');
  });
  image.addEventListener('error', () => {
    element.classList.remove('is-loading', 'has-image');
    element.classList.add('is-broken');
  });

  element.classList.add('is-loading');
  element.appendChild(image);
  image.src = normalized;
};

const updateProfileAvatarHelper = () => {
  const copy = getAvatarStatusCopy();
  if (dom.profileAvatarHelper) {
    dom.profileAvatarHelper.textContent = copy.message;
  }
  if (dom.profileAvatarMeta) {
    dom.profileAvatarMeta.textContent = copy.detail;
  }
};

const renderAvatarPreviews = (user = state.user) => {
  const fallbackText = getIdentityInitials(user);
  const heroAvatar = getAvatarValue(user);
  const profileAvatar = state.profileAvatarDraft;
  const identityName = getIdentityName(user);

  setAvatarElement(dom.heroInitials, heroAvatar, fallbackText, {
    altText: `${identityName} avatar`,
  });
  setAvatarElement(dom.profileAvatarPreview, profileAvatar, fallbackText, {
    altText: '',
  });
  updateProfileAvatarHelper();
};

const resetProfileAvatarDraft = (user = state.user) => {
  const avatar = getAvatarValue(user);
  clearAvatarValidationTimer();
  state.profileAvatarDraft = avatar;
  state.profileAvatarMetaDraft = getAvatarMeta(user);
  state.profileAvatarValidationId += 1;

  if (dom.profileAvatarUrl) {
    dom.profileAvatarUrl.value = avatar && !String(avatar).startsWith('data:image/') ? avatar : '';
  }

  if (dom.profileAvatarUpload) {
    dom.profileAvatarUpload.value = '';
  }

  if (!avatar) {
    state.profileAvatarMetaDraft = createEmptyAvatarMeta();
    setAvatarDraftStatus('empty');
  } else {
    const meta = normalizeAvatarMeta(state.profileAvatarMetaDraft, avatar);
    state.profileAvatarMetaDraft = meta;
    const sourceLabel = meta.kind === 'url' ? 'Remote avatar' : 'Uploaded avatar';
    const details = [
      formatAvatarDimensions(meta.width, meta.height),
      meta.mimeType ? meta.mimeType.replace('image/', '').toUpperCase() : '',
    ].filter(Boolean);
    setAvatarDraftStatus(
      'ready',
      `${sourceLabel} loaded.`,
      details.length
        ? `${details.join(' | ')}. Save after changes to keep the latest avatar state.`
        : 'Save after changes to keep the latest avatar state.'
    );
  }

  renderAvatarPreviews(user);
  renderHeroFocus(user);
};

const setProfileProgress = (completion) => {
  const percentage = `${Number(completion || 0)}%`;

  for (const bar of dom.profileProgressBars) {
    if (bar) bar.style.width = percentage;
  }

  if (dom.profileProgressLabel) dom.profileProgressLabel.textContent = percentage;
  if (dom.summaryCompletion) dom.summaryCompletion.textContent = percentage;
};

const getAccountHealthContributors = (user = state.user) => {
  if (!user) return [];
  const completion = Number(user.profile?.completion || 0);
  const activeSessions = Math.max(1, getActiveSessionCount());
  const sessionScore = activeSessions <= 1 ? 10 : Math.max(0, 10 - (activeSessions - 1) * 3);

  return [
    {
      title: 'Profile completion',
      detail: `${completion}% of the profile is filled in.`,
      points: Math.min(45, Math.round(completion * 0.45)),
      max: 45,
    },
    {
      title: 'Verified email',
      detail: user.isVerified ? 'Recovery and trust signals are stronger.' : 'Verification is still pending.',
      points: user.isVerified ? 20 : 0,
      max: 20,
    },
    {
      title: 'Login alerts',
      detail: user.security?.loginAlerts ? 'Suspicious sign-in alerts are enabled.' : 'Alerts are currently off.',
      points: user.security?.loginAlerts ? 15 : 0,
      max: 15,
    },
    {
      title: 'Multi-factor authentication',
      detail: user.security?.mfa?.enabled ? 'Authenticator-based sign-in is active.' : 'Password-only sign-in is still allowed.',
      points: user.security?.mfa?.enabled ? 18 : 0,
      max: 18,
    },
    {
      title: 'Passkeys',
      detail:
        Number(user.security?.passkeys?.count || 0) > 0
          ? `${Number(user.security?.passkeys?.count || 0)} passkey${Number(user.security?.passkeys?.count || 0) === 1 ? '' : 's'} saved for passwordless sign-in.`
          : 'No passkeys are registered yet.',
      points: Number(user.security?.passkeys?.count || 0) > 0 ? 16 : 0,
      max: 16,
    },
    {
      title: 'Claimed username',
      detail: getUsername(user) ? `${getUserHandle(user)} is reserved.` : 'A username is still missing.',
      points: getUsername(user) ? 6 : 0,
      max: 6,
    },
    {
      title: 'Profile photo',
      detail: getAvatarValue(user) ? 'Avatar helps recognize the account quickly.' : 'No avatar is set yet.',
      points: getAvatarValue(user) ? 5 : 0,
      max: 5,
    },
    {
      title: 'Headline',
      detail: safeText(user.profile?.headline) ? 'Public identity tagline is set.' : 'Add a short headline.',
      points: safeText(user.profile?.headline) ? 4 : 0,
      max: 4,
    },
    {
      title: 'Recovery website',
      detail: safeText(user.profile?.website) ? 'A website or portfolio is on file.' : 'No website or portfolio is listed.',
      points: safeText(user.profile?.website) ? 5 : 0,
      max: 5,
    },
    {
      title: 'Session hygiene',
      detail:
        activeSessions <= 1
          ? 'Only one active session is open.'
          : `${activeSessions} sessions are active. Review older ones if they are no longer needed.`,
      points: sessionScore,
      max: 10,
    },
  ];
};

const computeAccountHealth = (user = state.user) => {
  if (!user) {
    return {
      score: 0,
      label: 'Signed out',
      description: 'Sign in to view health.',
    };
  }

  const score = getAccountHealthContributors(user).reduce((sum, item) => sum + Number(item.points || 0), 0);

  const boundedScore = Math.max(0, Math.min(100, score));

  if (boundedScore >= 85) {
    return {
      score: boundedScore,
      label: 'Strong',
      description: 'Looks good.',
    };
  }

  if (boundedScore >= 65) {
    return {
      score: boundedScore,
      label: 'Healthy',
      description: 'A few items to review.',
    };
  }

  if (boundedScore >= 45) {
    return {
      score: boundedScore,
      label: 'Needs review',
      description: 'Review a few items.',
    };
  }

  return {
    score: boundedScore,
    label: 'At risk',
    description: 'Finish setup.',
  };
};

const setButtonBusy = (button, busy, busyLabel) => {
  if (!button) return;

  if (busy) {
    if (!button.dataset.defaultLabel) {
      button.dataset.defaultLabel = button.textContent;
    }
    button.disabled = true;
    if (busyLabel) button.textContent = busyLabel;
    return;
  }

  button.disabled = false;
  if (button.dataset.defaultLabel) {
    button.textContent = button.dataset.defaultLabel;
  }
};

const getFormMeta = (form) => {
  if (form === dom.profileForm) {
    return {
      label: 'Profile basics',
      tabId: 'profile',
      sectionId: 'profile-basics-card',
      statusEl: dom.profileFormState,
      focusEl: dom.profileUsername,
    };
  }
  if (form === dom.privacyForm) {
    return {
      label: 'Public profile',
      tabId: 'profile',
      sectionId: 'profile-visibility-card',
      statusEl: dom.privacyFormState,
      focusEl: dom.privacyPublic,
    };
  }
  if (form === dom.linkedForm) {
    return {
      label: 'Connected identities',
      tabId: 'settings',
      sectionId: 'settings-identities-card',
      statusEl: dom.linkedFormState,
      focusEl: dom.linkedGoogle,
    };
  }
  if (form === dom.notificationForm) {
    return {
      label: 'Notifications',
      tabId: 'settings',
      sectionId: 'settings-notifications-card',
      statusEl: dom.notificationFormState,
      focusEl: dom.notifyEmail,
    };
  }
  if (form === dom.appearanceForm) {
    return {
      label: 'Appearance',
      tabId: 'settings',
      sectionId: 'settings-appearance-card',
      statusEl: dom.appearanceFormState,
      focusEl: dom.appearanceTheme,
    };
  }
  if (form === dom.securityForm) {
    return {
      label: 'Security alerts',
      tabId: 'security',
      sectionId: 'security-advanced-card',
      statusEl: dom.securityFormState,
      focusEl: dom.loginAlertsToggle,
    };
  }

  return null;
};

const getFormStateLabel = (stateName) => {
  if (stateName === 'dirty') return 'Unsaved';
  if (stateName === 'saving') return 'Saving...';
  if (stateName === 'error') return 'Needs review';
  return 'Saved';
};

const setFormState = (form, stateName = 'saved', customLabel = '') => {
  if (!form) return;

  form.dataset.saveState = stateName;
  const meta = getFormMeta(form);
  if (meta?.statusEl) {
    meta.statusEl.dataset.state = stateName;
    meta.statusEl.textContent = customLabel || getFormStateLabel(stateName);
  }
};

const getDirtyForms = () => trackedForms.filter((form) => form?.dataset.dirty === 'true');

const updateSaveReminder = () => {
  const dirtyForms = getDirtyForms();
  const dirtyLabels = dirtyForms
    .map((form) => getFormMeta(form)?.label)
    .filter(Boolean);

  if (dom.saveReminder) {
    dom.saveReminder.hidden = dirtyLabels.length === 0;
  }

  if (dom.saveReminderText) {
    if (!dirtyLabels.length) {
      dom.saveReminderText.textContent = 'All tracked sections are saved.';
    } else if (dirtyLabels.length === 1) {
      dom.saveReminderText.textContent = `${dirtyLabels[0]} has unsaved changes.`;
    } else {
      dom.saveReminderText.textContent = `${dirtyLabels.length} sections have unsaved changes.`;
    }
  }

  if (dom.jumpUnsavedBtn) {
    dom.jumpUnsavedBtn.disabled = dirtyLabels.length === 0;
    dom.jumpUnsavedBtn.textContent = dirtyLabels.length ? 'Review unsaved' : 'All saved';
  }
};

const markFormDirty = (form) => {
  if (!form) return;
  form.dataset.dirty = 'true';
  setFormState(form, 'dirty');
  updateSaveReminder();
};

const markFormClean = (form, label = 'Saved') => {
  if (!form) return;
  form.dataset.dirty = 'false';
  setFormState(form, 'saved', label);
  updateSaveReminder();
};

const setFormError = (form, label = 'Needs review') => {
  if (!form) return;
  setFormState(form, 'error', label);
  updateSaveReminder();
};

const setFormSaving = (form, label = 'Saving...') => {
  if (!form) return;
  setFormState(form, 'saving', label);
  updateSaveReminder();
};

const hasUnsavedChanges = () => trackedForms.some((form) => form?.dataset.dirty === 'true');

const setupUnsavedChangeTracking = () => {
  for (const form of trackedForms) {
    if (!form) continue;

    form.dataset.dirty = 'false';
    setFormState(form, 'saved');

    form.addEventListener('input', () => {
      markFormDirty(form);
    });
    form.addEventListener('change', () => {
      markFormDirty(form);
    });
  }

  updateSaveReminder();
};

const showToast = (message, type = 'success', timeoutMs = 3200) => {
  if (!dom.toastRegion) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  dom.toastRegion.appendChild(toast);

  window.setTimeout(() => {
    toast.remove();
  }, timeoutMs);
};

const setStatus = (text, options = {}) => {
  const { clickable = false, onClick = null } = options;
  if (!dom.status) return;

  dom.status.textContent = text;
  dom.status.style.cursor = clickable ? 'pointer' : 'default';
  dom.status.onclick = clickable ? onClick : null;
};

const setConnectionStatus = () => {
  const online = navigator.onLine;
  if (dom.connectionStatus) {
    dom.connectionStatus.textContent = online ? 'Online' : 'Offline';
    dom.connectionStatus.classList.toggle('offline', !online);
  }
};

const setSyncStatus = (date = null) => {
  if (!dom.syncStatus) return;
  if (!date) {
    dom.syncStatus.textContent = 'Not synced yet';
    return;
  }
  dom.syncStatus.textContent = `Synced ${formatDate(date)}`;
};

const updateSkipLinkTarget = (targetId = 'loading-screen') => {
  if (!dom.skipLink) return;
  dom.skipLink.href = `#${targetId}`;
};

const setLandingState = ({
  stateName = 'loading',
  statusText = 'Checking connection',
  title = 'Checking your workspace',
  message = 'Loading...',
  detail = 'Verifying the account service and refreshing your session.',
  primaryLabel = 'Sign in',
  primaryAction = 'signin',
  showActions = false,
  showFullLogin = true,
} = {}) => {
  state.landingPrimaryAction = primaryAction;

  if (dom.loadingScreen) {
    dom.loadingScreen.dataset.state = stateName;
  }
  if (dom.loadingStatusChip) {
    dom.loadingStatusChip.textContent = statusText;
  }
  if (dom.loadingTitle) {
    dom.loadingTitle.textContent = title;
  }
  if (dom.loadingMessage) {
    dom.loadingMessage.textContent = message;
  }
  if (dom.loadingDetail) {
    dom.loadingDetail.textContent = detail;
  }
  if (dom.loadingActions) {
    dom.loadingActions.hidden = !showActions;
  }
  if (dom.loadingSignInBtn) {
    dom.loadingSignInBtn.textContent = primaryLabel;
    dom.loadingSignInBtn.dataset.defaultLabel = primaryLabel;
    dom.loadingSignInBtn.disabled = false;
    dom.loadingSignInBtn.hidden = !showActions;
  }
  if (dom.loadingFullLoginLink) {
    dom.loadingFullLoginLink.hidden = !showActions || !showFullLogin;
    dom.loadingFullLoginLink.href = buildLoginPopupUrl().toString();
  }

  updateSkipLinkTarget('loading-screen');
};

const getSectionScrollOffset = (section) => {
  const tabPanel = section?.closest('.tab-content');
  const sectionNav = tabPanel?.querySelector('.section-nav');
  const defaultGap = 24;

  if (!sectionNav) return defaultGap;

  const navTop = Number.parseFloat(window.getComputedStyle(sectionNav).top) || 0;
  return Math.ceil(sectionNav.getBoundingClientRect().height + navTop + 16);
};

const scrollToSection = (sectionId, focusEl = null) => {
  const section = document.getElementById(sectionId);
  if (section) {
    const offset = getSectionScrollOffset(section);
    const targetTop = window.scrollY + section.getBoundingClientRect().top - offset;
    window.scrollTo({
      top: Math.max(0, targetTop),
      behavior: 'smooth',
    });
  }

  const target = focusEl || section?.querySelector('input, select, textarea, button, [href]');
  if (target && typeof target.focus === 'function') {
    window.setTimeout(() => {
      target.focus({ preventScroll: true });
    }, 120);
  }
};

const jumpToForm = (form) => {
  const meta = getFormMeta(form);
  if (!meta) return;

  switchTab(meta.tabId);
  window.setTimeout(() => {
    scrollToSection(meta.sectionId, meta.focusEl);
  }, 80);
};

const jumpToFirstDirtyForm = () => {
  const [firstDirtyForm] = getDirtyForms();
  if (firstDirtyForm) {
    jumpToForm(firstDirtyForm);
    return true;
  }

  showToast('All tracked sections are already saved.', 'success', 2200);
  return false;
};

const clearStoredAuth = () => {
  state.accessToken = '';
  state.authEpoch += 1;
};

const stopSessionAutoRefresh = () => {
  if (!state.refreshTimer) return;
  clearInterval(state.refreshTimer);
  state.refreshTimer = null;
};

const handleUnauthenticatedState = ({
  message = 'Your session expired. Please sign in again.',
  notify = true,
} = {}) => {
  const shouldResetUi = Boolean(state.appVisible || state.user || state.accessToken);

  stopSessionAutoRefresh();
  clearStoredAuth();

  if (!shouldResetUi) {
    return;
  }

  setLoggedOutUI();

  if (notify && message && state.appVisible) {
    showToast(message, 'warn', 4200);
  }
};

const storeSession = (data = {}) => {
  const token = data?.accessToken || data?.token;
  state.accessToken = safeText(token);
};

const parseResponseBody = async (res) => {
  const text = await res.text();
  if (!text) return {};

  try {
    return JSON.parse(text);
  } catch {
    return { message: text };
  }
};

const fetchWithTimeout = async (url, options = {}, timeoutMs = REQUEST_TIMEOUT_MS) => {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
    });
  } finally {
    window.clearTimeout(timeoutId);
  }
};

const openPopupWindow = (url, name = 'LoginPopup') => {
  const width = 860;
  const height = 780;
  const left = window.screenX + (window.outerWidth - width) / 2;
  const top = window.screenY + (window.outerHeight - height) / 2;
  const popupUrl = String(url || buildLoginPopupUrl());

  if (state.loginPopupWindow && !state.loginPopupWindow.closed) {
    try {
      state.loginPopupWindow.location.href = popupUrl;
    } catch {
      // Ignore cross-origin navigation access errors and just focus the window.
    }
    state.loginPopupWindow.focus();
    return state.loginPopupWindow;
  }

  state.loginPopupWindow = window.open(
    popupUrl,
    name,
    [
      'popup=yes',
      `width=${width}`,
      `height=${height}`,
      `top=${Math.max(top, 0)}`,
      `left=${Math.max(left, 0)}`,
      'resizable=yes',
      'scrollbars=yes',
    ].join(',')
  );

  return state.loginPopupWindow;
};

const openLoginPopup = () => openPopupWindow(buildLoginPopupUrl().toString(), 'LoginPopup');

const openLoginPage = ({ replace = false } = {}) => {
  const loginUrl = buildLoginPopupUrl().toString();
  if (replace) {
    window.location.replace(loginUrl);
    return;
  }

  window.location.assign(loginUrl);
};

const promptSignIn = () => {
  const popup = openLoginPopup();
  if (popup) {
    if (!state.appVisible) {
      setLandingState({
        stateName: 'signed-out',
        statusText: 'Waiting for sign-in',
        title: 'Finish signing in',
        message: 'The sign-in window is open in a separate popup.',
        detail: 'Complete login there, then return here. This page will update automatically.',
        primaryLabel: 'Sign in',
        primaryAction: 'signin',
        showActions: true,
      });
    }
    return true;
  }

  openLoginPage();
  return false;
};

const closeLoginPopup = () => {
  if (state.loginPopupWindow && !state.loginPopupWindow.closed) {
    state.loginPopupWindow.close();
  }

  state.loginPopupWindow = null;
};

const isTrustedLoginOrigin = (origin) => {
  if (!origin) return false;
  if (origin === window.location.origin) return true;
  if (loginPopupOrigin && origin === loginPopupOrigin) return true;
  if (TRUSTED_API_MESSAGE_ORIGINS.has(origin)) return true;

  try {
    const parsed = new URL(origin);
    return LOCAL_HOSTS.has(window.location.hostname) && LOCAL_HOSTS.has(parsed.hostname);
  } catch {
    return false;
  }
};

const clearDashboardUi = () => {
  closeLauncher();
  state.user = null;
  state.activity = [];
  state.auditEvents = [];
  state.activitySummary = normalizeActivitySummary();
  state.ownerSummary = {
    totalUsers: 0,
    owners: 0,
    suspended: 0,
    flagged: 0,
  };
  state.ownerUsers = [];
  state.ownerSelectedUserId = '';
  state.ownerSelectedUser = null;
  state.ownerSelectedAuditEvents = [];
  state.sessions = [];
  state.devices = [];
  state.sessionLimit = null;
  clearAvatarValidationTimer();
  state.profileAvatarDraft = '';
  state.profileAvatarMetaDraft = createEmptyAvatarMeta();
  state.profileAvatarValidationId += 1;
  state.mfaSetup = null;
  setAvatarDraftStatus('empty');

  if (dom.summaryId) dom.summaryId.textContent = '-';
  if (dom.summaryUsername) dom.summaryUsername.textContent = '-';
  if (dom.summaryDisplayName) dom.summaryDisplayName.textContent = '-';
  if (dom.summaryHeadline) dom.summaryHeadline.textContent = '-';
  if (dom.summaryLastLogin) dom.summaryLastLogin.textContent = '-';
  if (dom.summaryVerified) dom.summaryVerified.textContent = 'Pending';
  if (dom.summarySessions) dom.summarySessions.textContent = '0';
  setProfileProgress(0);
  renderHero(null);
  renderAccountHealth(null);

  if (dom.profileForm) dom.profileForm.reset();
  if (dom.linkedForm) dom.linkedForm.reset();
  if (dom.passwordForm) dom.passwordForm.reset();
  if (dom.securityForm) dom.securityForm.reset();
  if (dom.privacyForm) dom.privacyForm.reset();
  if (dom.notificationForm) dom.notificationForm.reset();
  if (dom.appearanceForm) dom.appearanceForm.reset();
  if (dom.deleteForm) dom.deleteForm.reset();
  if (dom.ownerFilterForm) dom.ownerFilterForm.reset();
  if (dom.ownerUserForm) dom.ownerUserForm.reset();
  for (const form of trackedForms) {
    markFormClean(form);
  }

  if (dom.profileId) dom.profileId.value = '';
  if (dom.profileCreated) dom.profileCreated.value = '';
  if (dom.profilePublicLink) dom.profilePublicLink.value = '';
  if (dom.openPublicProfileBtn) dom.openPublicProfileBtn.disabled = true;
  if (dom.profileAvatarUrl) dom.profileAvatarUrl.value = '';
  if (dom.profileAvatarUpload) dom.profileAvatarUpload.value = '';
  state.mfaSetupOpen = false;
  state.mfaManageMode = '';
  state.mfaLastFocusedElement = null;
  state.passkeyModalOpen = false;
  state.passkeyLastFocusedElement = null;
  state.deleteModalOpen = false;
  state.deleteLastFocusedElement = null;
  state.decisionModalConfig = null;
  state.decisionModalResolver = null;
  state.decisionLastFocusedElement = null;
  if (dom.mfaCurrentPassword) dom.mfaCurrentPassword.value = '';
  if (dom.mfaCode) dom.mfaCode.value = '';
  clearMfaManageInputs();
  if (dom.passkeyCurrentPassword) dom.passkeyCurrentPassword.value = '';
  if (dom.passkeyChallenge) dom.passkeyChallenge.value = '';
  if (dom.deleteChallenge) dom.deleteChallenge.value = '';

  if (dom.activityFilter) dom.activityFilter.value = '';
  if (dom.activityKind) dom.activityKind.value = 'all';
  if (dom.serviceFilter) dom.serviceFilter.value = '';
  if (dom.launcherSearch) dom.launcherSearch.value = '';
  if (dom.activityList) dom.activityList.innerHTML = '<li>No recent activity.</li>';
  if (dom.overviewActivityList) dom.overviewActivityList.innerHTML = '<li>No recent activity.</li>';
  if (dom.sessionsList) dom.sessionsList.innerHTML = '<li>No active sessions found.</li>';
  if (dom.devicesList) dom.devicesList.innerHTML = '<li>No known devices found.</li>';
  if (dom.passkeyList) dom.passkeyList.innerHTML = '<li>No passkeys saved.</li>';
  if (dom.activityBars) dom.activityBars.innerHTML = '';
  renderBackupCodes([]);
  renderMfaState();
  renderPasskeys();
  renderOauthProviders(null);
  renderVanguardIdentity(null);

  if (dom.insightLast7) dom.insightLast7.textContent = '0';
  if (dom.insightLast30) dom.insightLast30.textContent = '0';
  if (dom.insightIps) dom.insightIps.textContent = '0';
  if (dom.sessionLimitNote) dom.sessionLimitNote.textContent = 'Limit: --';
  renderOwnerAccess();
  renderOwnerSummary();
  renderOwnerUserList();
  renderOwnerUserDetail();
  renderVerificationState();
  renderActionCenter(null);
  renderProfileChecklist(null);
  renderSecurityPosture(null);
  renderServices();
  renderLauncher();
  renderMfaModal();
  renderPasskeyModal();
  renderDeleteModal();
  renderDecisionModal();
  renderAvatarPreviews(null);

  applyAppearance({
    theme: 'graphite',
    compactMode: false,
    reducedMotion: false,
    highContrast: false,
    dashboardDensity: 'comfortable',
  });
};

const setLoggedOutUI = () => {
  stopSessionAutoRefresh();
  clearStoredAuth();
  clearDashboardUi();

  setStatus('Signed out. Click here to sign in.', {
    clickable: true,
    onClick: () => {
      promptSignIn();
    },
  });

  if (dom.logoutBtn) {
    dom.logoutBtn.style.display = 'none';
  }

  if (dom.loadingScreen) {
    dom.loadingScreen.style.cursor = 'default';
    dom.loadingScreen.onclick = null;
  }

  if (!state.appVisible) {
    setLandingState({
      stateName: 'signed-out',
      statusText: 'Sign-in required',
      title: 'Sign in to your dashboard',
      message: 'Continue with Continental ID to manage profile visibility, security, and connected services.',
      detail: 'Use the popup sign-in flow or open the full-page login if your browser blocks popups.',
      primaryLabel: 'Sign in',
      primaryAction: 'signin',
      showActions: true,
    });
  }
};

const setServiceUnavailableUI = (result = {}) => {
  const offline = !navigator.onLine || result.reason === 'network';
  const detail = safeText(result.message)
    || (offline
      ? 'Reconnect to the internet, then retry the dashboard.'
      : 'The dashboard could not reach a live Continental ID account service.');

  setStatus(
    offline ? 'You appear to be offline. Click here to retry.' : 'Account service unavailable. Click here to retry.',
    {
      clickable: true,
      onClick: () => {
        retryLandingConnection();
      },
    }
  );

  if (dom.logoutBtn) {
    dom.logoutBtn.style.display = 'none';
  }

  if (!state.appVisible) {
    setLandingState({
      stateName: 'error',
      statusText: offline ? 'Offline' : 'Service unavailable',
      title: offline ? 'You are offline.' : 'We could not reach Continental ID.',
      message: offline
        ? 'Reconnect and retry to continue loading your dashboard.'
        : 'The account service did not respond, so we could not verify your session.',
      detail,
      primaryLabel: 'Retry connection',
      primaryAction: 'retry',
      showActions: true,
    });
  }
};

const classifyStartupFailure = (error) => {
  if (error?.name === 'AbortError') {
    return {
      ok: false,
      reason: 'timeout',
      message: 'The account service took too long to respond.',
    };
  }

  if (error instanceof TypeError) {
    return {
      ok: false,
      reason: 'network',
      message: 'The dashboard could not reach the account service.',
    };
  }

  return {
    ok: false,
    reason: 'error',
    message: safeText(error?.message) || 'Could not load account data.',
  };
};

const stripLegacyAuthParamsFromUrl = () => {
  const params = new URLSearchParams(window.location.search);
  const hadLegacyAuthParams =
    params.has('token') ||
    params.has('userId') ||
    params.has('continentalId') ||
    params.has('email') ||
    params.has('username');

  if (hadLegacyAuthParams) {
    params.delete('token');
    params.delete('userId');
    params.delete('continentalId');
    params.delete('email');
    params.delete('username');
    const nextQuery = params.toString();
    const nextUrl = `${window.location.pathname}${nextQuery ? `?${nextQuery}` : ''}${window.location.hash}`;
    history.replaceState({}, '', nextUrl);
  }

  return hadLegacyAuthParams;
};

const refreshSession = async () => {
  if (state.refreshPromise) {
    return state.refreshPromise;
  }

  state.refreshPromise = (async () => {
    const authEpoch = state.authEpoch;

    try {
      await ensureApiBaseUrl();
      const res = await fetchWithTimeout(`${getAuthApiBase()}/refresh_token`, {
        method: 'POST',
        credentials: 'include',
      });

      const data = await parseResponseBody(res);
      if (!res.ok) {
        return {
          ok: false,
          reason: res.status === 401 ? 'unauthenticated' : 'error',
          message: data.message || 'Session refresh failed.',
        };
      }

      if (!(data.accessToken || data.token)) {
        return {
          ok: false,
          reason: data.authenticated === false ? 'unauthenticated' : 'error',
          message: data.message || 'Session refresh failed.',
        };
      }

      if (state.authEpoch !== authEpoch) {
        return { ok: false, reason: 'stale', message: '' };
      }

      storeSession(data);
      return { ok: true, data };
    } catch (error) {
      return {
        ok: false,
        reason:
          error?.name === 'AbortError'
            ? 'timeout'
            : error instanceof TypeError
              ? 'network'
              : 'error',
        message: safeText(error?.message),
      };
    } finally {
      state.refreshPromise = null;
    }
  })();

  return state.refreshPromise;
};

const toApiError = (err) => {
  if (err?.name === 'AbortError') {
    return new Error('Request timed out. Please try again.');
  }

  if (err instanceof TypeError) {
    return new Error(
      API_BASE_URL
        ? `Could not reach the account service at ${API_BASE_URL}. Check that this origin is serving the Continental ID auth API.`
        : 'Could not determine a live Continental ID auth API.'
    );
  }

  return err instanceof Error ? err : new Error('Unexpected request error.');
};

const apiRequest = async (path, options = {}) => {
  const { method = 'GET', body = undefined, auth = true, retryOn401 = true } = options;

  const headers = {};
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  if (auth) {
    const token = state.accessToken;
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  }

  let response;
  try {
    await ensureApiBaseUrl();
    response = await fetchWithTimeout(`${getAuthApiBase()}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: 'include',
    });
  } catch (error) {
    throw toApiError(error);
  }

  if (response.status === 401 && auth && retryOn401) {
    const refreshed = await refreshSession();
    if (refreshed.ok) {
      return apiRequest(path, { method, body, auth, retryOn401: false });
    }

    if (refreshed.reason === 'unauthenticated') {
      handleUnauthenticatedState({
        message: refreshed.message || 'Your session expired. Please sign in again.',
      });
      throw new Error(refreshed.message || 'Your session expired. Please sign in again.');
    }
  }

  const payload = await parseResponseBody(response);

  if (!response.ok) {
    if (response.status === 401 && auth) {
      handleUnauthenticatedState({
        message: payload.message || 'Your session expired. Please sign in again.',
      });
    }
    throw new Error(payload.message || `Request failed (${response.status})`);
  }

  return payload;
};

const normalizeUserPayload = (payload) => {
  if (!payload) return null;
  return payload.user || payload;
};

const normalizeWebsiteInput = (value) => {
  const raw = safeText(value);
  if (!raw) return '';

  const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  try {
    const parsed = new URL(withProtocol);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    return parsed.toString();
  } catch {
    return null;
  }
};

const evaluatePasswordStrength = (password) => {
  let score = 0;
  if (password.length >= 8) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/[a-z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;

  const percentage = Math.min(100, score * 20);
  let label = 'Very weak';
  let color = '#ff8b7c';

  if (score >= 2) {
    label = 'Weak';
    color = '#ffbe71';
  }
  if (score >= 3) {
    label = 'Moderate';
    color = '#ffe97b';
  }
  if (score >= 4) {
    label = 'Strong';
    color = '#95ebb1';
  }
  if (score >= 5) {
    label = 'Very strong';
    color = '#73e4ab';
  }

  return { score, percentage, label, color };
};

const updatePasswordStrengthUi = () => {
  if (!dom.newPassword || !dom.passwordStrengthFill || !dom.passwordStrengthText) return;

  const value = dom.newPassword.value;
  const strength = evaluatePasswordStrength(value);

  dom.passwordStrengthFill.style.width = `${strength.percentage}%`;
  dom.passwordStrengthFill.style.background = `linear-gradient(120deg, ${strength.color}, #7db4ff)`;

  if (!value) {
    dom.passwordStrengthText.textContent = 'Use 8+ chars, upper/lowercase, and a number.';
    return;
  }

  dom.passwordStrengthText.textContent = `Password strength: ${strength.label}`;
};

const readFileAsDataUrl = (file) =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ''));
    reader.onerror = () => reject(new Error('Selected file could not be read.'));
    reader.readAsDataURL(file);
  });

const buildAvatarCanvas = (image) => {
  const canvas = document.createElement('canvas');
  canvas.width = AVATAR_UPLOAD_MAX_DIMENSION;
  canvas.height = AVATAR_UPLOAD_MAX_DIMENSION;

  const context = canvas.getContext('2d');
  if (!context) {
    throw new Error('Avatar processing is not available in this browser.');
  }

  const sourceWidth = Math.max(1, Number(image.naturalWidth || image.width || 0));
  const sourceHeight = Math.max(1, Number(image.naturalHeight || image.height || 0));
  const sourceSize = Math.max(1, Math.min(sourceWidth, sourceHeight));
  const offsetX = Math.max(0, Math.round((sourceWidth - sourceSize) / 2));
  const offsetY = Math.max(0, Math.round((sourceHeight - sourceSize) / 2));

  context.clearRect(0, 0, canvas.width, canvas.height);
  context.drawImage(
    image,
    offsetX,
    offsetY,
    sourceSize,
    sourceSize,
    0,
    0,
    canvas.width,
    canvas.height
  );

  return canvas;
};

const encodeAvatarCanvas = (canvas, originalMimeType = '') => {
  const attempts = [
    ['image/webp', 0.92],
    ['image/webp', 0.84],
    ['image/webp', 0.76],
    ['image/png'],
    ['image/jpeg', 0.88],
    ['image/jpeg', 0.8],
  ];

  for (const [mimeType, quality] of attempts) {
    const encoded = typeof quality === 'number'
      ? canvas.toDataURL(mimeType, quality)
      : canvas.toDataURL(mimeType);
    if (encoded.length <= AVATAR_DATA_URL_MAX_LENGTH) {
      return {
        dataUrl: encoded,
        meta: normalizeAvatarMeta(
          {
            kind: 'upload',
            mimeType: encoded.slice(5, encoded.indexOf(';')) || originalMimeType,
            width: canvas.width,
            height: canvas.height,
            updatedAt: new Date().toISOString(),
          },
          encoded
        ),
      };
    }
  }

  throw new Error('Avatar image is still too large after resizing. Try a smaller source image.');
};

const compressAvatarFile = async (file) => {
  if (!file) {
    throw new Error('Select an image to upload.');
  }

  if (!AVATAR_ALLOWED_MIME_TYPES.has(file.type)) {
    throw new Error('Avatar must be a PNG, JPG, GIF, or WebP image.');
  }

  if (file.size > AVATAR_UPLOAD_MAX_FILE_BYTES) {
    throw new Error('Avatar image is too large. Use a file under 5 MB.');
  }

  const rawDataUrl = await readFileAsDataUrl(file);
  const { image } = await loadImageSource(rawDataUrl, { timeoutMs: AVATAR_RENDER_TIMEOUT_MS });
  const canvas = buildAvatarCanvas(image);
  return encodeAvatarCanvas(canvas, file.type || '');
};

const applyAppearance = (appearance = {}) => {
  const theme = safeText(appearance.theme || 'graphite').toLowerCase() || 'graphite';
  const density = safeText(appearance.dashboardDensity || 'comfortable').toLowerCase() || 'comfortable';
  const compactMode = Boolean(appearance.compactMode);
  const reducedMotion = Boolean(appearance.reducedMotion);
  const highContrast = Boolean(appearance.highContrast);

  const resolvedTheme = theme === 'system' ? 'graphite' : theme;

  document.documentElement.dataset.theme = resolvedTheme;
  document.documentElement.dataset.density = compactMode ? 'compact' : density;
  document.documentElement.dataset.reducedMotion = reducedMotion ? 'true' : 'false';
  document.documentElement.dataset.highContrast = highContrast ? 'true' : 'false';
};

const renderHero = (user = state.user) => {
  if (dom.heroDisplayName) dom.heroDisplayName.textContent = getIdentityName(user);
  if (dom.heroUsername) dom.heroUsername.textContent = getUserHandle(user) || '@continental';
  if (dom.heroEmail) dom.heroEmail.textContent = safeText(user?.email) || 'Signed-out session';
  if (dom.heroGreeting) {
    dom.heroGreeting.textContent = user ? `Welcome back, ${getFirstName(user)}` : 'Welcome back';
  }

  if (dom.heroStatusNote) {
    if (!user) {
      dom.heroStatusNote.textContent = 'Complete your profile.';
      return;
    }

    const completion = Number(user.profile?.completion || 0);
    const sessionCount = Math.max(0, getActiveSessionCount());
    const migration = getMigrationState(user);
    if (migration.suggested) {
      const inactiveDays = Number.isFinite(Number(migration.inactiveDays))
        ? `${Number(migration.inactiveDays)} days away`
        : 'returning account';
      dom.heroStatusNote.textContent = `${inactiveDays}, ${completion}% complete, ${
        user.isVerified ? 'verified' : 'verification pending'
      }. Review security before relying on this account again.`;
      return;
    }

    dom.heroStatusNote.textContent = `${completion}% complete, ${
      user.isVerified ? 'verified' : 'verification pending'
    }, ${sessionCount} ${sessionCount === 1 ? 'session' : 'sessions'}.`;
  }

  renderAvatarPreviews(user);
};

const renderAccountHealth = (user = state.user) => {
  const health = computeAccountHealth(user);
  if (dom.healthScoreValue) dom.healthScoreValue.textContent = String(health.score);
  if (dom.healthScoreLabel) dom.healthScoreLabel.textContent = `${health.label}. ${health.description}`;
};

const renderInsights = () => {
  if (dom.insightLast7) dom.insightLast7.textContent = String(state.activitySummary.last7Days || 0);
  if (dom.insightLast30) dom.insightLast30.textContent = String(state.activitySummary.last30Days || 0);
  if (dom.insightIps) dom.insightIps.textContent = String(state.activitySummary.uniqueIps || 0);
  if (dom.insightVerified) dom.insightVerified.textContent = state.user?.isVerified ? 'Verified' : 'Pending';
};

const createOwnerChip = (text) => {
  const chip = document.createElement('span');
  chip.className = 'preview-chip';
  chip.textContent = safeText(text);
  return chip;
};

const renderOwnerAccess = () => {
  const hasOwnerAccess = isOwnerUser(state.user);

  if (dom.ownerTab) {
    dom.ownerTab.hidden = !hasOwnerAccess;
  }
  if (dom.ownerPanel && !hasOwnerAccess) {
    dom.ownerPanel.hidden = true;
  }
  if (dom.ownerAccessChip) {
    dom.ownerAccessChip.textContent = hasOwnerAccess ? 'Owner access live' : 'Owner access required';
  }

  if (!hasOwnerAccess && state.activeTab === 'owner') {
    switchTab('overview', { historyMode: 'replace' });
  }
};

const renderOwnerSummary = () => {
  const summary = normalizeOwnerSummary(state.ownerSummary);
  if (dom.ownerTotalUsers) dom.ownerTotalUsers.textContent = String(summary.totalUsers);
  if (dom.ownerTotalOwners) dom.ownerTotalOwners.textContent = String(summary.owners);
  if (dom.ownerTotalSuspended) dom.ownerTotalSuspended.textContent = String(summary.suspended);
  if (dom.ownerTotalFlagged) dom.ownerTotalFlagged.textContent = String(summary.flagged);

  if (dom.ownerSummaryCopy) {
    dom.ownerSummaryCopy.textContent = isOwnerUser(state.user)
      ? `${summary.totalUsers} total accounts, ${summary.owners} owner accounts, ${summary.suspended} suspended accounts, and ${summary.flagged} accounts currently flagged for review.`
      : 'Owner access is hidden for this account.';
  }
};

const renderOwnerUserList = () => {
  if (!dom.ownerUserList || !dom.ownerResultsSummary) return;

  if (!isOwnerUser(state.user)) {
    dom.ownerResultsSummary.textContent = 'Owner access required.';
    dom.ownerUserList.innerHTML = '<li>Owner access required.</li>';
    return;
  }

  const users = Array.isArray(state.ownerUsers) ? state.ownerUsers : [];
  const query = safeText(dom.ownerSearch?.value);
  dom.ownerResultsSummary.textContent = query
    ? `${users.length} matching account${users.length === 1 ? '' : 's'} for "${query}".`
    : `${users.length} account${users.length === 1 ? '' : 's'} loaded.`;

  if (!users.length) {
    dom.ownerUserList.innerHTML = '<li>No matching users found.</li>';
    return;
  }

  dom.ownerUserList.innerHTML = '';
  for (const entry of users) {
    const li = document.createElement('li');
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'owner-user-button';
    if (entry.userId === state.ownerSelectedUserId) {
      button.classList.add('is-selected');
    }

    const meta = document.createElement('div');
    meta.className = 'owner-user-meta';
    const copy = document.createElement('div');
    copy.className = 'owner-user-copy';
    const title = document.createElement('strong');
    title.textContent = safeText(entry.displayName || entry.username || entry.email || entry.userId);
    const subtitle = document.createElement('p');
    subtitle.className = 'helper-line';
    subtitle.textContent = [
      safeText(entry.handle || entry.username),
      safeText(entry.email),
    ].filter(Boolean).join(' • ') || 'No identity data';
    const detail = document.createElement('p');
    detail.className = 'helper-line';
    detail.textContent = [
      safeText(entry.profile?.headline),
      safeText(entry.profile?.role),
      safeText(entry.profile?.organization),
    ].filter(Boolean).join(' • ') || 'No headline, role, or organization saved.';
    copy.append(title, subtitle, detail);

    const time = document.createElement('span');
    time.className = 'mini-label';
    time.textContent = entry.lastLoginAt ? `Last login ${formatDateCompact(entry.lastLoginAt)}` : 'No login yet';
    meta.append(copy, time);

    const badges = document.createElement('div');
    badges.className = 'owner-user-badges';
    badges.append(
      createOwnerChip(entry.authority?.isOwner ? 'Owner' : 'User'),
      createOwnerChip(entry.authority?.status === 'suspended' ? 'Suspended' : 'Active'),
      createOwnerChip(entry.isVerified ? 'Verified' : 'Unverified')
    );
    if (entry.security?.mfaEnabled) badges.append(createOwnerChip('MFA'));
    if (Number(entry.security?.passkeyCount || 0) > 0) badges.append(createOwnerChip('Passkeys'));
    if (entry.vanguard?.flagged) badges.append(createOwnerChip('Flagged'));
    if (entry.vanguard?.bannedFromAi) badges.append(createOwnerChip('AI denied'));

    button.append(meta, badges);
    button.addEventListener('click', () => {
      selectOwnerUser(entry.userId);
    });
    li.appendChild(button);
    dom.ownerUserList.appendChild(li);
  }
};

const renderOwnerUserDetail = () => {
  if (!dom.ownerUserForm || !dom.ownerSelectedSummary || !dom.ownerSelectedChips) return;

  const user = getSelectedOwnerUser();
  const inputs = dom.ownerUserForm.querySelectorAll('input, select, button');
  const disabled = !isOwnerUser(state.user) || !user;
  for (const element of inputs) {
    element.disabled = disabled;
  }

  if (!user) {
    if (dom.ownerSelectedSummary) {
      dom.ownerSelectedSummary.textContent = isOwnerUser(state.user)
        ? 'Select a user from the list to review their account state and run owner-level actions.'
        : 'Owner access required.';
    }
    if (dom.ownerSelectedChips) {
      dom.ownerSelectedChips.innerHTML = '<span class="preview-empty">No user selected.</span>';
    }
    if (dom.ownerUserForm) dom.ownerUserForm.reset();
    return;
  }

  if (dom.ownerUserId) dom.ownerUserId.value = safeText(user.userId);
  if (dom.ownerUserEmail) dom.ownerUserEmail.value = safeText(user.email);
  if (dom.ownerUserCreated) dom.ownerUserCreated.value = formatDate(user.createdAt);
  if (dom.ownerUserLastLogin) dom.ownerUserLastLogin.value = user.lastLoginAt ? formatDate(user.lastLoginAt) : 'No login yet';
  if (dom.ownerUserDisplayName) dom.ownerUserDisplayName.value = safeText(user.displayName);
  if (dom.ownerUserUsername) dom.ownerUserUsername.value = safeText(user.username);
  if (dom.ownerUserHeadline) dom.ownerUserHeadline.value = safeText(user.profile?.headline);
  if (dom.ownerUserProfileRole) dom.ownerUserProfileRole.value = safeText(user.profile?.role);
  if (dom.ownerUserOrganization) dom.ownerUserOrganization.value = safeText(user.profile?.organization);
  if (dom.ownerUserLocation) dom.ownerUserLocation.value = safeText(user.profile?.location);
  if (dom.ownerUserRole) dom.ownerUserRole.value = safeText(user.authority?.role || 'user');
  if (dom.ownerUserStatus) dom.ownerUserStatus.value = safeText(user.authority?.status || 'active');
  if (dom.ownerUserStatusReason) dom.ownerUserStatusReason.value = safeText(user.authority?.statusReason);
  if (dom.ownerUserVerified) dom.ownerUserVerified.checked = Boolean(user.isVerified);
  if (dom.ownerUserProfilePublic) dom.ownerUserProfilePublic.checked = Boolean(user.preferences?.profilePublic);
  if (dom.ownerUserSearchable) dom.ownerUserSearchable.checked = Boolean(user.preferences?.searchable);
  if (dom.ownerUserVanguardTrusted) dom.ownerUserVanguardTrusted.checked = Boolean(user.vanguard?.trusted);
  if (dom.ownerUserVanguardStaff) dom.ownerUserVanguardStaff.checked = Boolean(user.vanguard?.staff);
  if (dom.ownerUserVanguardFlagged) dom.ownerUserVanguardFlagged.checked = Boolean(user.vanguard?.flagged);
  if (dom.ownerUserVanguardBanned) dom.ownerUserVanguardBanned.checked = Boolean(user.vanguard?.bannedFromAi);
  if (dom.ownerUserVanguardFlagReason) dom.ownerUserVanguardFlagReason.value = safeText(user.vanguard?.flagReason);

  if (dom.ownerSelectedSummary) {
    dom.ownerSelectedSummary.textContent = `${safeText(user.email)} • ${
      user.authority?.status === 'suspended' ? 'Suspended account' : 'Active account'
    } • ${Number(user.security?.activeSessions || 0)} active session${
      Number(user.security?.activeSessions || 0) === 1 ? '' : 's'
    }.`;
  }

  dom.ownerSelectedChips.innerHTML = '';
  const chips = [
    user.authority?.isOwner ? 'Owner' : 'User',
    user.isVerified ? 'Verified' : 'Unverified',
    user.security?.mfaEnabled ? 'MFA on' : 'MFA off',
    Number(user.security?.passkeyCount || 0) > 0
      ? `${Number(user.security?.passkeyCount || 0)} passkeys`
      : 'No passkeys',
  ];
  if (user.vanguard?.flagged) chips.push('Vanguard flagged');
  if (user.vanguard?.bannedFromAi) chips.push('AI denied');
  if (user.preferences?.profilePublic) chips.push(user.preferences?.searchable ? 'Public + searchable' : 'Public only');
  for (const text of chips) {
    dom.ownerSelectedChips.appendChild(createOwnerChip(text));
  }

  if (dom.ownerUserResendVerificationBtn) {
    dom.ownerUserResendVerificationBtn.disabled = disabled || Boolean(user.isVerified);
  }
};

const renderVerificationState = (user = state.user) => {
  if (!user) {
    if (dom.summaryVerified) dom.summaryVerified.textContent = 'Pending';
    if (dom.insightVerified) dom.insightVerified.textContent = 'Pending';
    if (dom.verificationPanel) dom.verificationPanel.hidden = true;
    if (dom.verificationHelper) {
      dom.verificationHelper.textContent = 'Email not verified.';
    }
    return;
  }

  const isVerified = Boolean(user?.isVerified);

  if (dom.summaryVerified) dom.summaryVerified.textContent = isVerified ? 'Verified' : 'Pending';
  if (dom.insightVerified) dom.insightVerified.textContent = isVerified ? 'Verified' : 'Pending';

  if (dom.verificationPanel) {
    dom.verificationPanel.hidden = isVerified;
  }

  if (dom.verificationHelper) {
    const email = safeText(user?.email);
    dom.verificationHelper.textContent = isVerified
      ? 'Email verified.'
      : email
        ? `${email} not verified.`
        : 'Email not verified.';
  }
};

const renderProfileChecklist = (user = state.user) => {
  if (!dom.profileChecklist) return;

  dom.profileChecklist.innerHTML = '';

  if (!isDashboardTipsEnabled()) {
    const li = document.createElement('li');
    li.textContent = 'Helpful dashboard tips are hidden in Appearance settings.';
    dom.profileChecklist.appendChild(li);
    return;
  }

  if (!user) {
    const li = document.createElement('li');
    li.textContent = 'Sign in to load checklist items.';
    dom.profileChecklist.appendChild(li);
    return;
  }

  const migration = getMigrationState(user);
  const vanguard = getVanguardState(user);
  const items = [
    {
      title: 'Returning account review',
      detail: migration.suggested
        ? Number.isFinite(Number(migration.inactiveDays))
          ? `This account was inactive for ${Number(migration.inactiveDays)} days. Review profile, recovery, and sign-in settings.`
          : 'This older account should be reviewed against the upgraded identity model.'
        : 'This account has already been reviewed recently.',
      complete: !migration.suggested,
    },
    {
      title: 'Username claimed',
      detail: getUserHandle(user) ? `${getUserHandle(user)} is active.` : 'Choose a sign-in handle.',
      complete: Boolean(getUsername(user)),
    },
    {
      title: 'Display name added',
      detail: safeText(user.displayName) ? 'Looks good.' : 'Add a readable public name.',
      complete: Boolean(safeText(user.displayName)),
    },
    {
      title: 'Profile picture added',
      detail: getAvatarValue(user) ? 'Avatar is set.' : 'Add a picture so your account is easier to recognize.',
      complete: Boolean(getAvatarValue(user)),
    },
    {
      title: 'Headline added',
      detail: safeText(user.profile?.headline) ? 'Headline is set.' : 'Add a short identity tagline.',
      complete: Boolean(safeText(user.profile?.headline)),
    },
    {
      title: 'Email verified',
      detail: user.isVerified ? 'Verification complete.' : 'Verify to reduce lockout risk.',
      complete: Boolean(user.isVerified),
    },
    {
      title: 'Discord identity linked',
      detail: vanguard.linkedDiscord
        ? 'Vanguard-aware services can recognize this account through Discord.'
        : 'Link Discord sign-in if you want brand-aware services to recognize this account.',
      complete: vanguard.linkedDiscord,
    },
    {
      title: 'Location added',
      detail: safeText(user.profile?.location) ? 'Location is on file.' : 'Add a location for context.',
      complete: Boolean(safeText(user.profile?.location)),
    },
    {
      title: 'Public profile ready',
      detail: user.preferences?.profilePublic
        ? user.preferences?.searchable
          ? 'Public page is live and discoverable.'
          : 'Public page is live by direct link only.'
        : 'Enable the public profile once the page is ready to share.',
      complete: Boolean(user.preferences?.profilePublic),
    },
    {
      title: 'Security alerts enabled',
      detail: user.security?.loginAlerts ? 'Login alerts are active.' : 'Turn on suspicious sign-in alerts.',
      complete: Boolean(user.security?.loginAlerts),
    },
    {
      title: 'MFA enabled',
      detail: user.security?.mfa?.enabled ? 'Second-factor protection is active.' : 'Enable MFA to protect sign-in.',
      complete: Boolean(user.security?.mfa?.enabled),
    },
    {
      title: 'Passkey added',
      detail:
        Number(user.security?.passkeys?.count || 0) > 0
          ? 'Passwordless sign-in is ready.'
          : 'Add a passkey for faster sign-in on your devices.',
      complete: Number(user.security?.passkeys?.count || 0) > 0,
    },
    {
      title: 'Brand service standing',
      detail: vanguard.bannedFromAi
        ? 'This account is restricted from Vanguard AI features.'
        : vanguard.flagged
          ? vanguard.flagReason
            ? `This account is under brand review: ${vanguard.flagReason}.`
            : 'This account is currently under brand review.'
          : vanguard.staff
            ? 'This account is marked as staff at the brand identity layer.'
            : vanguard.trusted
              ? 'This account is marked as trusted at the brand identity layer.'
              : 'No Vanguard-related restrictions are attached to this account.',
      complete: !vanguard.flagged && !vanguard.bannedFromAi,
    },
  ];

  for (const item of items) {
    const li = document.createElement('li');
    li.className = item.complete ? 'complete' : 'incomplete';

    const title = document.createElement('strong');
    title.textContent = item.complete ? `${item.title} - done` : item.title;

    const detail = document.createElement('span');
    detail.textContent = item.detail;

    li.appendChild(title);
    li.appendChild(detail);
    dom.profileChecklist.appendChild(li);
  }
};

const createActionItem = ({ tone = 'neutral', title, detail, actionLabel, onAction }) => {
  const item = document.createElement('article');
  item.className = 'action-item';
  item.dataset.tone = tone;

  const content = document.createElement('div');
  const heading = document.createElement('strong');
  heading.textContent = title;
  const body = document.createElement('p');
  body.textContent = detail;

  content.appendChild(heading);
  content.appendChild(body);
  item.appendChild(content);

  if (actionLabel && typeof onAction === 'function') {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = tone === 'danger' ? 'danger-btn' : 'secondary-btn';
    button.textContent = actionLabel;
    button.addEventListener('click', onAction);
    item.appendChild(button);
  }

  return item;
};

const getRecommendedActions = (user = state.user) => {
  if (!user) {
    return [
      {
        tone: 'warn',
        title: 'Sign in required',
        detail: 'Your personalized suggestions will appear once the dashboard loads account data.',
      },
    ];
  }

  const actions = [];
  const completion = Number(user.profile?.completion || 0);
  const activeSessions = Math.max(0, getActiveSessionCount());
  const migration = getMigrationState(user);
  const discordOauth = normalizeOauthProviderState('discord', user?.oauthProviders?.discord);
  const vanguard = getVanguardState(user);

  if (migration.suggested) {
    const migrationDetails = [];
    if (Number.isFinite(Number(migration.inactiveDays))) {
      migrationDetails.push(`Last active about ${Number(migration.inactiveDays)} days ago.`);
    }
    if (migration.shouldResetPassword) migrationDetails.push('Refresh the password for the newer auth flow.');
    if (migration.shouldVerifyEmail) migrationDetails.push('Finish email verification.');
    if (migration.shouldEnableMfa) migrationDetails.push('Turn on MFA.');
    if (migration.shouldAddPasskey) migrationDetails.push('Add a passkey.');

    actions.push({
      tone: 'warn',
      title: 'Review this upgraded account',
      detail:
        migrationDetails.join(' ') ||
        'This returning account should be reviewed against the current sign-in and recovery settings.',
      actionLabel: 'Open security',
      onAction: () => switchTab('security'),
    });
  }

  if (!user.isVerified) {
    actions.push({
      tone: 'warn',
      title: 'Verify your email',
      detail: 'Verification is still pending, so recovery and trust signals are weaker than they should be.',
      actionLabel: 'Resend email',
      onAction: () => handleResendVerification(),
    });
  }

  if (!vanguard.linkedDiscord && discordOauth.available) {
    actions.push({
      tone: 'neutral',
      title: 'Link your Discord identity',
      detail:
        'Connect Discord if you want Vanguard-aware services to recognize this Continental ID account. This dashboard still does not control Vanguard itself.',
      actionLabel: 'Open identities',
      onAction: () => openIdentitySection(dom.oauthDiscordConnectBtn),
    });
  }

  if (completion < 80) {
    actions.push({
      tone: 'neutral',
      title: 'Finish your profile',
      detail: `Your profile is only ${completion}% complete. Fill the remaining details so the account is easier to manage.`,
      actionLabel: 'Open profile',
      onAction: () => switchTab('profile'),
    });
  }

  if (!user.preferences?.profilePublic || !user.preferences?.searchable) {
    actions.push({
      tone: 'neutral',
      title: 'Tune your public profile',
      detail: user.preferences?.profilePublic
        ? 'Your page is live, but directory discovery is off. Turn search on if people should be able to find you.'
        : 'Your public page is still private. Review visibility settings before sharing it.',
      actionLabel: 'Review visibility',
      onAction: () => switchTab('profile'),
    });
  }

  if (!safeText(user.profile?.headline) && !safeText(user.profile?.bio) && !safeText(user.profile?.website)) {
    actions.push({
      tone: 'neutral',
      title: 'Add public context',
      detail: 'A headline, short bio, or website makes the public profile more useful to scan and share.',
      actionLabel: 'Edit profile',
      onAction: () => switchTab('profile'),
    });
  }

  if (!user.security?.loginAlerts) {
    actions.push({
      tone: 'neutral',
      title: 'Enable login alerts',
      detail: 'Get a heads-up when suspicious sign-in activity is detected.',
      actionLabel: 'Open security',
      onAction: () => switchTab('security'),
    });
  }

  if (!user.security?.mfa?.enabled) {
    actions.push({
      tone: 'warn',
      title: 'Turn on MFA',
      detail: 'Password-only sign-in is still enabled. Add an authenticator app before this account is reused elsewhere.',
      actionLabel: 'Set up MFA',
      onAction: () => switchTab('security'),
    });
  }

  if (!Number(user.security?.passkeys?.count || 0)) {
    actions.push({
      tone: 'neutral',
      title: 'Add a passkey',
      detail: 'Use a device passkey for passwordless sign-in and stronger phishing resistance.',
      actionLabel: 'Open security',
      onAction: () => switchTab('security'),
    });
  }

  if (!getAvatarValue(user)) {
    actions.push({
      tone: 'neutral',
      title: 'Add a profile picture',
      detail: 'A custom avatar makes the account easier to recognize across sessions and tools.',
      actionLabel: 'Upload avatar',
      onAction: () => switchTab('profile'),
    });
  }

  if (activeSessions > 1) {
    actions.push({
      tone: 'neutral',
      title: 'Review open sessions',
      detail: `${activeSessions} sessions are active right now. Revoke the ones you no longer recognize or need.`,
      actionLabel: 'Review sessions',
      onAction: () => switchTab('security'),
    });
  }

  if (!actions.length) {
    actions.push({
      tone: 'success',
      title: 'Everything looks tidy',
      detail: 'Profile, verification, and session controls are all in a healthy state.',
      actionLabel: 'View activity',
      onAction: () => switchTab('activity'),
    });
  }

  return actions;
};

const renderHeroFocus = (user = state.user) => {
  const primaryAction = getRecommendedActions(user)[0];
  if (!primaryAction) return;

  if (dom.heroFocusTitle) dom.heroFocusTitle.textContent = primaryAction.title;
  if (dom.heroFocusCopy) dom.heroFocusCopy.textContent = primaryAction.detail;
  if (dom.heroFocusChip) {
    const chipLabel = primaryAction.tone === 'warn'
      ? 'Needs attention'
      : primaryAction.tone === 'success'
        ? 'On track'
        : primaryAction.tone === 'danger'
          ? 'Important'
          : 'Recommended';
    dom.heroFocusChip.textContent = chipLabel;
  }
  if (dom.heroFocusBtn) {
    dom.heroFocusBtn.hidden = !(primaryAction.actionLabel && typeof primaryAction.onAction === 'function');
    dom.heroFocusBtn.textContent = primaryAction.actionLabel || 'Open';
    dom.heroFocusBtn.onclick = typeof primaryAction.onAction === 'function' ? primaryAction.onAction : null;
  }
};

const renderActionCenter = (user = state.user) => {
  if (!dom.actionCenter) return;

  dom.actionCenter.innerHTML = '';

  const secondaryActions = getRecommendedActions(user).slice(1, 4);
  const actionsToRender = secondaryActions.length ? secondaryActions : getRecommendedActions(user).slice(0, 1);

  for (const action of actionsToRender) {
    dom.actionCenter.appendChild(createActionItem(action));
  }
};

const getPublicProfileUrl = (username = state.user?.username) => {
  const handle = safeText(username);
  if (!handle) return '';

  const url = new URL('profile.html', window.location.href);
  url.searchParams.set('u', handle);
  return url.toString();
};

const getPublicVisibilityInputs = () =>
  [
    dom.publicFieldHeadline,
    dom.publicFieldBio,
    dom.publicFieldLocation,
    dom.publicFieldWebsite,
    dom.publicFieldLinked,
    dom.publicFieldMemberSince,
  ].filter(Boolean);

const getDraftPublicProfileState = (user = state.user) => {
  const username = safeText(dom.profileUsername?.value || user?.username).toLowerCase();
  const savedUsername = safeText(user?.username).toLowerCase();
  const url = getPublicProfileUrl(username);
  const isPublic = dom.privacyPublic
    ? Boolean(dom.privacyPublic.checked)
    : Boolean(user?.preferences?.profilePublic);
  const searchable = dom.privacySearchable
    ? Boolean(dom.privacySearchable.checked)
    : Boolean(user?.preferences?.searchable);
  const visibleCount = getPublicVisibilityInputs().filter((input) => Boolean(input?.checked)).length;
  const hasPendingLinkChange = Boolean(username && savedUsername && username !== savedUsername);
  const hasPendingVisibilityChange = Boolean(
    user &&
      dom.privacyPublic &&
      Boolean(dom.privacyPublic.checked) !== Boolean(user?.preferences?.profilePublic)
  );

  return {
    username,
    url,
    isPublic,
    searchable,
    visibleCount,
    hasPendingLinkChange,
    hasPendingVisibilityChange,
  };
};

const updatePublicProfileLink = (user = state.user) => {
  const { url, isPublic, searchable, visibleCount, hasPendingLinkChange, hasPendingVisibilityChange } =
    getDraftPublicProfileState(user);
  const savedUrl = getPublicProfileUrl(user?.username);

  if (dom.profilePublicLink) {
    if (!url) {
      dom.profilePublicLink.value = 'Set a username to generate a public profile link.';
    } else if (isPublic) {
      dom.profilePublicLink.value = url;
    } else {
      dom.profilePublicLink.value = `${url} (currently private)`;
    }
  }

  if (dom.publicProfileStatusBadge) {
    dom.publicProfileStatusBadge.textContent = isPublic ? 'Public' : 'Private';
  }

  if (dom.publicProfileDiscoveryBadge) {
    dom.publicProfileDiscoveryBadge.textContent = searchable ? 'Directory enabled' : 'Hidden from search';
  }

  if (dom.publicProfileVisibleCount) {
    dom.publicProfileVisibleCount.textContent = `${visibleCount} sections visible`;
  }

  const helperMessage = !url
    ? 'Choose a username to generate a shareable public link.'
    : hasPendingLinkChange || hasPendingVisibilityChange
      ? 'Save your latest username or visibility changes before sharing or opening the live public page.'
    : !isPublic
      ? 'Your profile link is reserved, but the page stays private until public mode is enabled and saved.'
      : !searchable
        ? 'Your public page is live through its direct link, but it will not appear in directory search.'
        : 'Your public page is live and discoverable in the public directory.';

  if (dom.publicProfileLinkHelper) {
    dom.publicProfileLinkHelper.textContent = helperMessage;
  }

  if (dom.publicProfileSummary) {
    dom.publicProfileSummary.textContent = isPublic
      ? searchable
        ? `People can find this profile in search, and ${visibleCount} sections are ready to show.`
        : `The profile is public by direct link only, with ${visibleCount} visible sections configured.`
      : 'Keep your profile private until the public version is ready to share.';
  }

  if (dom.openPublicProfileBtn) {
    dom.openPublicProfileBtn.disabled =
      !savedUrl ||
      !Boolean(user?.preferences?.profilePublic) ||
      hasPendingLinkChange ||
      hasPendingVisibilityChange;
  }

  if (dom.copyPublicProfileLinkBtn) {
    dom.copyPublicProfileLinkBtn.disabled = !url;
  }
};

const getDraftLinkedAccounts = (user = state.user) =>
  [
    ['Google', readDraftInputValue(dom.linkedGoogle, user?.linkedAccounts?.google || '')],
    ['Facebook', readDraftInputValue(dom.linkedFacebook, user?.linkedAccounts?.facebook || '')],
    ['GitHub', readDraftInputValue(dom.linkedGithub, user?.linkedAccounts?.github || '')],
    ['Twitter/X', readDraftInputValue(dom.linkedTwitter, user?.linkedAccounts?.twitter || '')],
    ['LinkedIn', readDraftInputValue(dom.linkedLinkedin, user?.linkedAccounts?.linkedin || '')],
    ['Discord', readDraftInputValue(dom.linkedDiscord, user?.linkedAccounts?.discord || '')],
    ['Apple', readDraftInputValue(dom.linkedApple, user?.linkedAccounts?.apple || '')],
    ['Microsoft', readDraftInputValue(dom.linkedMicrosoft, user?.linkedAccounts?.microsoft || '')],
  ]
    .map(([label, value]) => ({ label, value: safeText(value) }))
    .filter((entry) => Boolean(entry.value));

const createPreviewSection = (title, body, tone = 'neutral') => {
  const card = document.createElement('article');
  card.className = 'preview-section-card';
  card.dataset.tone = tone;

  const heading = document.createElement('strong');
  heading.textContent = title;
  card.appendChild(heading);

  if (body instanceof Node) {
    card.appendChild(body);
  } else {
    const copy = document.createElement('p');
    copy.textContent = safeText(body) || 'Nothing to show yet.';
    card.appendChild(copy);
  }

  return card;
};

const getDraftPublicProfilePreview = (user = state.user) => {
  const visible = {
    headline: Boolean(dom.publicFieldHeadline?.checked),
    bio: Boolean(dom.publicFieldBio?.checked),
    location: Boolean(dom.publicFieldLocation?.checked),
    website: Boolean(dom.publicFieldWebsite?.checked),
    linkedAccounts: Boolean(dom.publicFieldLinked?.checked),
    memberSince: Boolean(dom.publicFieldMemberSince?.checked),
  };

  const username = safeText(readDraftInputValue(dom.profileUsername, user?.username || '')).toLowerCase();
  const displayName = safeText(readDraftInputValue(dom.profileDisplayName, user?.displayName || ''));
  const headline = safeText(readDraftInputValue(dom.profileHeadline, user?.profile?.headline || ''));
  const location = safeText(readDraftInputValue(dom.profileLocation, user?.profile?.location || ''));
  const website = safeText(readDraftInputValue(dom.profileWebsite, user?.profile?.website || ''));
  const bio = safeText(readDraftInputValue(dom.profileBio, user?.profile?.bio || ''));
  const linkedAccounts = getDraftLinkedAccounts(user);
  const { isPublic, searchable, visibleCount } = getDraftPublicProfileState(user);

  return {
    avatar: state.profileAvatarDraft || getAvatarValue(user),
    username,
    handle: username ? `@${username}` : 'No public handle yet',
    displayName: displayName || getIdentityName(user),
    headline,
    location,
    website,
    bio,
    linkedAccounts,
    isPublic,
    searchable,
    visibleCount,
    visible,
    memberSince: user?.createdAt || null,
  };
};

const renderPublicProfilePreview = (user = state.user) => {
  if (!dom.profilePreviewSections) return;

  const draft = getDraftPublicProfilePreview(user);
  const previewIdentity = draft.displayName || draft.username || user?.email || 'Continental User';

  setAvatarElement(dom.profilePreviewAvatar, draft.avatar, getInitialsFromSource(previewIdentity), {
    altText: '',
  });

  if (dom.profilePreviewVisibility) {
    dom.profilePreviewVisibility.textContent = draft.isPublic
      ? draft.searchable
        ? 'Public & searchable'
        : 'Public by direct link'
      : 'Private draft';
  }

  if (dom.profilePreviewHandle) dom.profilePreviewHandle.textContent = draft.handle;
  if (dom.profilePreviewName) dom.profilePreviewName.textContent = draft.displayName;
  if (dom.profilePreviewHeadline) {
    dom.profilePreviewHeadline.textContent =
      draft.visible.headline && draft.headline
        ? draft.headline
        : draft.isPublic
          ? 'Headline is hidden or not set.'
          : 'Add a headline and choose whether it should appear publicly.';
  }

  if (dom.profilePreviewSummary) {
    dom.profilePreviewSummary.textContent =
      draft.visible.bio && draft.bio
        ? draft.bio.slice(0, 140)
        : draft.visible.location && draft.location
          ? draft.location
          : 'Bio, location, and links will appear here when those public fields are enabled.';
  }

  if (dom.profilePreviewMeta) {
    dom.profilePreviewMeta.innerHTML = '';
    const metaValues = [
      draft.visible.location && draft.location ? draft.location : '',
      draft.isPublic ? 'Public page ready' : 'Private preview',
    ].filter(Boolean);

    for (const value of metaValues) {
      const chip = document.createElement('span');
      chip.className = 'inline-chip';
      chip.textContent = value;
      dom.profilePreviewMeta.appendChild(chip);
    }
  }

  if (dom.profilePreviewVisibleCount) {
    dom.profilePreviewVisibleCount.textContent = String(draft.visibleCount);
  }

  if (dom.profilePreviewLinkedCount) {
    dom.profilePreviewLinkedCount.textContent = String(draft.visible.linkedAccounts ? draft.linkedAccounts.length : 0);
  }

  if (dom.profilePreviewMemberSince) {
    dom.profilePreviewMemberSince.textContent =
      draft.visible.memberSince && draft.memberSince ? formatDateCompact(draft.memberSince, { year: 'numeric' }) : 'Hidden';
  }

  dom.profilePreviewSections.innerHTML = '';
  const sections = [];

  if (draft.visible.bio && draft.bio) {
    sections.push(createPreviewSection('Bio', draft.bio));
  }

  if (draft.visible.website && draft.website) {
    const link = document.createElement('a');
    link.href = /^https?:\/\//i.test(draft.website) ? draft.website : `https://${draft.website}`;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.textContent = link.href;
    sections.push(createPreviewSection('Website', link));
  }

  if (draft.visible.linkedAccounts && draft.linkedAccounts.length) {
    const list = document.createElement('div');
    list.className = 'preview-linked-list';
    for (const entry of draft.linkedAccounts) {
      const row = document.createElement('div');
      row.className = 'preview-linked-item';
      const label = document.createElement('strong');
      label.textContent = entry.label;
      const value = document.createElement('span');
      value.textContent = entry.value;
      row.appendChild(label);
      row.appendChild(value);
      list.appendChild(row);
    }
    sections.push(createPreviewSection('External profiles', list));
  }

  if (draft.visible.memberSince && draft.memberSince) {
    sections.push(
      createPreviewSection(
        'Member since',
        `Joined ${formatDateCompact(draft.memberSince, { year: 'numeric' })}`
      )
    );
  }

  if (!sections.length) {
    const empty = document.createElement('div');
    empty.className = 'preview-empty';
    empty.textContent = 'No public sections are visible yet. Toggle on fields in Preferences to shape the page.';
    dom.profilePreviewSections.appendChild(empty);
  } else {
    for (const section of sections) {
      dom.profilePreviewSections.appendChild(section);
    }
  }

  if (dom.profilePreviewNote) {
    dom.profilePreviewNote.textContent = draft.isPublic
      ? draft.searchable
        ? `This profile is ready for direct links and directory search with ${draft.visibleCount} visible fields.`
        : `This profile is ready by direct link only with ${draft.visibleCount} visible fields.`
      : `This is still a private draft. ${draft.visibleCount} public fields are currently enabled.`;
  }
};

const refreshDraftPublicProfileUi = () => {
  updatePublicProfileLink(state.user);
  renderPublicProfilePreview(state.user);
};

const renderSecurityPosture = (user = state.user) => {
  if (!dom.securityBreakdown) return;
  renderSecurityGuidance(user);

  const health = computeAccountHealth(user);
  const contributors = getAccountHealthContributors(user);
  const trustedDevices = state.devices.filter((device) => device.trusted).length;
  const newDevices = state.sessions.filter((session) => session.newDevice).length;
  const activeSessions = Math.max(0, getActiveSessionCount());

  if (dom.securityPostureChip) dom.securityPostureChip.textContent = health.label;
  if (dom.securityScoreNumber) dom.securityScoreNumber.textContent = String(health.score);
  if (dom.securityScoreRing) {
    dom.securityScoreRing.style.setProperty('--score', `${Math.max(0, Math.min(100, health.score))}%`);
  }

  if (dom.securityScoreSummary) {
    dom.securityScoreSummary.textContent = user
      ? `${health.label}. ${health.description} ${activeSessions} active session${activeSessions === 1 ? '' : 's'} across ${state.devices.length} known device${state.devices.length === 1 ? '' : 's'}.`
      : 'Sign in to review session, device, and protection signals.';
  }

  if (dom.securityMetricSessions) dom.securityMetricSessions.textContent = String(activeSessions);
  if (dom.securityMetricDevices) dom.securityMetricDevices.textContent = String(state.devices.length);
  if (dom.securityMetricTrustedDevices) dom.securityMetricTrustedDevices.textContent = String(trustedDevices);
  if (dom.securityMetricNewDevices) dom.securityMetricNewDevices.textContent = String(newDevices);

  dom.securityBreakdown.innerHTML = '';
  if (!contributors.length) {
    const empty = document.createElement('p');
    empty.className = 'helper-line';
    empty.textContent = 'Security breakdown unavailable until account data loads.';
    dom.securityBreakdown.appendChild(empty);
    return;
  }

  for (const item of contributors) {
    const card = document.createElement('article');
    card.className = 'score-breakdown-item';
    card.dataset.tone = item.points >= item.max ? 'success' : item.points > 0 ? 'neutral' : 'warn';

    const head = document.createElement('div');
    head.className = 'score-breakdown-head';

    const title = document.createElement('strong');
    title.textContent = item.title;
    head.appendChild(title);

    const chip = document.createElement('span');
    chip.className = 'inline-chip';
    chip.textContent = `+${item.points} / ${item.max}`;
    head.appendChild(chip);

    const meter = document.createElement('div');
    meter.className = 'bar-meter';
    const fill = document.createElement('div');
    fill.className = 'bar-meter-fill';
    fill.style.width = item.points
      ? `${Math.max(8, Math.round((item.points / Math.max(1, item.max)) * 100))}%`
      : '0%';
    meter.appendChild(fill);

    const detail = document.createElement('p');
    detail.textContent = item.detail;

    card.appendChild(head);
    card.appendChild(meter);
    card.appendChild(detail);
    dom.securityBreakdown.appendChild(card);
  }
};

const openSecuritySection = (sectionId, focusEl = null) => {
  switchTab('security');
  window.setTimeout(() => {
    scrollToSection(sectionId, focusEl);
  }, 80);
};

const openIdentitySection = (focusEl = null) => {
  switchTab('settings');
  window.setTimeout(() => {
    scrollToSection('settings-identities-card', focusEl);
  }, 80);
};

const getSecurityGuidance = (user = state.user) => {
  if (!user) {
    return {
      title: 'Sign in to review security',
      detail: 'Your priority security recommendation appears after the dashboard loads account, session, and device data.',
      actionLabel: '',
      onAction: null,
    };
  }

  const migration = getMigrationState(user);
  const activeSessions = Math.max(0, getActiveSessionCount());

  if (migration.shouldResetPassword) {
    return {
      title: 'Rotate the password for this returning account',
      detail: 'This account has older sign-in history. Refresh the password before relying on it again.',
      actionLabel: 'Open password',
      onAction: () => openSecuritySection('security-password-card', dom.currentPassword),
    };
  }

  if (!user.security?.mfa?.enabled) {
    return {
      title: state.mfaSetup?.secret ? 'Finish MFA setup' : 'Turn on MFA',
      detail: state.mfaSetup?.secret
        ? 'Your authenticator secret is ready. Confirm the current 6-digit code to finish setup.'
        : 'Add an authenticator app so password-only sign-in is no longer the weakest point on this account.',
      actionLabel: state.mfaSetup?.secret ? 'Finish MFA' : 'Set up MFA',
      onAction: () => openMfaSecuritySection(),
    };
  }

  if (!Number(user.security?.passkeys?.count || 0)) {
    return {
      title: 'Add a passkey',
      detail: 'A passkey gives you faster sign-in and better phishing resistance than passwords alone.',
      actionLabel: 'Open passkeys',
      onAction: () => {
        switchTab('security');
        openPasskeyModal();
      },
    };
  }

  if (!user.security?.loginAlerts) {
    return {
      title: 'Enable suspicious sign-in alerts',
      detail: 'Turn on alerts so you get notified when unusual sign-in activity is detected.',
      actionLabel: 'Open alerts',
      onAction: () => openSecuritySection('security-advanced-card', dom.loginAlertsToggle),
    };
  }

  if (activeSessions > 1) {
    return {
      title: 'Review active sessions',
      detail: `${activeSessions} sessions are currently open. Revoke any device you no longer recognize or use.`,
      actionLabel: 'Review sessions',
      onAction: () => openSecuritySection('security-advanced-card', dom.sessionsRevokeOthersBtn),
    };
  }

  return {
    title: 'Security looks healthy',
    detail: 'MFA, passkeys, alerts, and session hygiene are all in a solid state. Use advanced controls only when something changes.',
    actionLabel: 'View advanced controls',
    onAction: () => openSecuritySection('security-advanced-card', dom.loginAlertsToggle),
  };
};

const renderSecurityGuidance = (user = state.user) => {
  const guidance = getSecurityGuidance(user);

  if (dom.securityGuidanceTitle) dom.securityGuidanceTitle.textContent = guidance.title;
  if (dom.securityGuidanceCopy) dom.securityGuidanceCopy.textContent = guidance.detail;
  if (dom.securityGuidanceBtn) {
    const actionable = Boolean(guidance.actionLabel && typeof guidance.onAction === 'function');
    dom.securityGuidanceBtn.hidden = !actionable;
    dom.securityGuidanceBtn.textContent = guidance.actionLabel || 'Open';
    dom.securityGuidanceBtn.onclick = actionable ? guidance.onAction : null;
  }
};

const copyTextToClipboard = async (value) => {
  const text = safeText(value);
  if (!text) {
    throw new Error('Nothing to copy yet.');
  }

  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const input = document.createElement('input');
  input.value = text;
  document.body.appendChild(input);
  input.select();
  document.execCommand('copy');
  input.remove();
};

const handleCopyPublicProfileLink = async () => {
  const { url } = getDraftPublicProfileState(state.user);
  if (!url) {
    showToast('Set a username before copying your public profile link.', 'error');
    return;
  }

  try {
    await copyTextToClipboard(url);
    showToast('Public profile link copied.', 'success');
  } catch (err) {
    showToast(err.message || 'Failed to copy the public profile link.', 'error');
  }
};

const fillSummary = (user) => {
  if (dom.summaryId) dom.summaryId.textContent = user.continentalId || user.userId || '-';
  if (dom.summaryUsername) dom.summaryUsername.textContent = getUserHandle(user) || '-';
  if (dom.summaryDisplayName) dom.summaryDisplayName.textContent = user.displayName || '-';
  if (dom.summaryHeadline) dom.summaryHeadline.textContent = safeText(user.profile?.headline) || '-';
  if (dom.summaryLastLogin) dom.summaryLastLogin.textContent = formatDate(user.lastLoginAt);
  if (dom.summarySessions) {
    dom.summarySessions.textContent = String(user.security?.activeSessions ?? state.sessions.length ?? 0);
  }

  const completion = Number(user.profile?.completion || 0);
  setProfileProgress(completion);
  renderHero(user);
  renderAccountHealth(user);
  renderActionCenter(user);
  renderProfileChecklist(user);
  renderSecurityPosture(user);
};

const fillProfile = (user) => {
  if (dom.profileUsername) dom.profileUsername.value = user.username || '';
  if (dom.profileDisplayName) dom.profileDisplayName.value = user.displayName || '';
  if (dom.profileHeadline) dom.profileHeadline.value = user.profile?.headline || '';
  if (dom.profileEmail) dom.profileEmail.value = user.email || '';
  if (dom.profileEmailCurrentPassword) dom.profileEmailCurrentPassword.value = '';
  if (dom.profileLocation) dom.profileLocation.value = user.profile?.location || '';
  if (dom.profileWebsite) dom.profileWebsite.value = user.profile?.website || '';
  if (dom.profileBio) dom.profileBio.value = user.profile?.bio || '';
  if (dom.profileId) dom.profileId.value = user.continentalId || user.userId || '';
  if (dom.profileCreated) dom.profileCreated.value = formatDate(user.createdAt);

  const completion = Number(user.profile?.completion || 0);
  setProfileProgress(completion);
  resetProfileAvatarDraft(user);
  updatePublicProfileLink(user);
  renderPublicProfilePreview(user);
};

const fillLinkedAccounts = (user) => {
  const linked = user.linkedAccounts || {};
  if (dom.linkedGoogle) dom.linkedGoogle.value = linked.google || '';
  if (dom.linkedFacebook) dom.linkedFacebook.value = linked.facebook || '';
  if (dom.linkedGithub) dom.linkedGithub.value = linked.github || '';
  if (dom.linkedTwitter) dom.linkedTwitter.value = linked.twitter || '';
  if (dom.linkedLinkedin) dom.linkedLinkedin.value = linked.linkedin || '';
  if (dom.linkedDiscord) dom.linkedDiscord.value = linked.discord || '';
  if (dom.linkedApple) dom.linkedApple.value = linked.apple || '';
  if (dom.linkedMicrosoft) dom.linkedMicrosoft.value = linked.microsoft || '';
  renderOauthProviders(user);
  renderVanguardIdentity(user);
  renderPublicProfilePreview(user);
};

const fillPreferences = (user) => {
  const prefs = user.preferences || {};
  const notifications = prefs.notifications || {};
  const appearance = prefs.appearance || {};
  const publicProfile = normalizePublicProfileSettings(prefs.publicProfile);

  if (dom.privacyPublic) dom.privacyPublic.checked = Boolean(prefs.profilePublic);
  if (dom.privacySearchable) dom.privacySearchable.checked = Boolean(prefs.searchable);
  if (dom.publicFieldHeadline) dom.publicFieldHeadline.checked = publicProfile.headline;
  if (dom.publicFieldBio) dom.publicFieldBio.checked = publicProfile.bio;
  if (dom.publicFieldLocation) dom.publicFieldLocation.checked = publicProfile.location;
  if (dom.publicFieldWebsite) dom.publicFieldWebsite.checked = publicProfile.website;
  if (dom.publicFieldLinked) dom.publicFieldLinked.checked = publicProfile.linkedAccounts;
  if (dom.publicFieldMemberSince) dom.publicFieldMemberSince.checked = publicProfile.memberSince;

  if (dom.notifyEmail) dom.notifyEmail.checked = Boolean(notifications.email);
  if (dom.notifySms) dom.notifySms.checked = Boolean(notifications.sms);
  if (dom.notifyPush) dom.notifyPush.checked = Boolean(notifications.push);
  if (dom.notifyWeeklyDigest) dom.notifyWeeklyDigest.checked = Boolean(notifications.weeklyDigest);
  if (dom.notifySecurity) dom.notifySecurity.checked = Boolean(notifications.security);

  if (dom.appearanceTheme) {
    const themeValue = safeText(appearance.theme || 'graphite').toLowerCase();
    dom.appearanceTheme.value = themeValue === 'system' ? 'graphite' : themeValue;
  }
  if (dom.appearanceDensity) dom.appearanceDensity.value = appearance.dashboardDensity || 'comfortable';
  if (dom.appearanceCompactMode) dom.appearanceCompactMode.checked = Boolean(appearance.compactMode);
  if (dom.appearanceReducedMotion) dom.appearanceReducedMotion.checked = Boolean(appearance.reducedMotion);
  if (dom.appearanceHighContrast) dom.appearanceHighContrast.checked = Boolean(appearance.highContrast);
  if (dom.dashboardTipsToggle) dom.dashboardTipsToggle.checked = isDashboardTipsEnabled();

  applyAppearance(appearance);
  updatePublicProfileLink(user);
  renderPublicProfilePreview(user);
};

const fillSecurity = (user) => {
  if (dom.loginAlertsToggle) dom.loginAlertsToggle.checked = Boolean(user.security?.loginAlerts);
  renderMfaState(user);
  renderPasskeys(user);
  renderAccountHealth(user);
  renderActionCenter(user);
  renderProfileChecklist(user);
  renderSecurityPosture(user);
};

const normalizeAuditEvent = (event = {}) => ({
  at: event?.at || null,
  type: safeText(event?.type),
  message: safeText(event?.message),
  ip: safeText(event?.ip),
  userAgent: safeText(event?.userAgent),
  meta:
    event?.meta && typeof event.meta === 'object' && !Array.isArray(event.meta)
      ? event.meta
      : {},
});

const prettifyAuditType = (type) =>
  safeText(type)
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase()) || 'Account event';

const getAuditBucket = (event = {}) => {
  const type = safeText(event?.type).toLowerCase();
  if (
    type.includes('password') ||
    type.includes('security') ||
    type.includes('session') ||
    type.includes('login') ||
    type.includes('email') ||
    type.includes('verification')
  ) {
    return 'security';
  }

  return 'account';
};

const formatActivityLine = (entry) => {
  const at = formatDate(entry.at);
  const ip = safeText(entry.ip) || 'Unknown IP';
  const ua = safeText(entry.userAgent) || 'Unknown browser/device';
  return `${at} - Login from ${ip} (${ua})`;
};

const formatAuditLine = (event) => {
  const auditEvent = normalizeAuditEvent(event);
  const metaText = Object.entries(auditEvent.meta)
    .map(([key, value]) => `${safeText(key)} ${safeText(value)}`)
    .join(' ');

  return [
    formatDate(auditEvent.at),
    auditEvent.type,
    auditEvent.message,
    auditEvent.ip,
    auditEvent.userAgent,
    metaText,
  ]
    .join(' ')
    .toLowerCase();
};

const createLoginActivityListItem = (entry) => {
  const li = document.createElement('li');
  li.className = 'activity-item';

  const head = document.createElement('div');
  head.className = 'activity-head';

  const title = document.createElement('p');
  title.className = 'activity-title';
  title.textContent = `Login from ${safeText(entry.ip) || 'Unknown IP'}`;

  const chip = document.createElement('span');
  chip.className = 'inline-chip';
  chip.textContent = formatDate(entry.at);

  const meta = document.createElement('div');
  meta.className = 'activity-meta';
  meta.textContent = safeText(entry.userAgent) || 'Unknown browser or device';

  head.appendChild(title);
  head.appendChild(chip);
  li.appendChild(head);
  li.appendChild(meta);
  return li;
};

const buildTimelineItems = () => {
  const loginItems = state.activity.map((entry) => ({
    bucket: 'logins',
    chip: 'Login',
    title: `Login from ${safeText(entry.ip) || 'Unknown IP'}`,
    detail: safeText(entry.userAgent) || 'Unknown browser or device',
    at: entry.at,
    searchLine: formatActivityLine(entry).toLowerCase(),
  }));

  const auditItems = state.auditEvents.map((event) => {
    const auditEvent = normalizeAuditEvent(event);
    const metaParts = Object.entries(auditEvent.meta)
      .map(([key, value]) => `${safeText(key)}: ${safeText(value)}`)
      .filter(Boolean);
    const bucket = getAuditBucket(auditEvent);

    return {
      bucket,
      chip: bucket === 'security' ? 'Security' : 'Account',
      title: auditEvent.message || prettifyAuditType(auditEvent.type),
      detail: [auditEvent.ip, auditEvent.userAgent, ...metaParts].filter(Boolean).join(' | '),
      at: auditEvent.at,
      searchLine: formatAuditLine(auditEvent),
    };
  });

  return [...loginItems, ...auditItems].sort((left, right) => {
    const leftTime = new Date(left.at || 0).getTime();
    const rightTime = new Date(right.at || 0).getTime();
    return rightTime - leftTime;
  });
};

const getFilteredTimelineItems = () => {
  const query = safeText(dom.activityFilter?.value).toLowerCase();
  const kind = safeText(dom.activityKind?.value).toLowerCase() || 'all';

  return buildTimelineItems().filter((item) => {
    const matchesKind = kind === 'all' ? true : item.bucket === kind;
    const matchesQuery = !query || item.searchLine.includes(query);
    return matchesKind && matchesQuery;
  });
};

const createTimelineListItem = (item) => {
  const li = document.createElement('li');
  li.className = 'activity-item';

  const head = document.createElement('div');
  head.className = 'activity-head';

  const title = document.createElement('p');
  title.className = 'activity-title';
  title.textContent = item.title;

  const chip = document.createElement('span');
  chip.className = 'inline-chip';
  chip.textContent = item.chip;

  const meta = document.createElement('div');
  meta.className = 'activity-meta';
  meta.textContent = [formatDate(item.at), item.detail].filter(Boolean).join(' | ');

  head.appendChild(title);
  head.appendChild(chip);
  li.appendChild(head);
  li.appendChild(meta);
  return li;
};

const createTimelineDayHeader = (value, count) => {
  const li = document.createElement('li');
  li.className = 'activity-day-header';

  const title = document.createElement('strong');
  title.textContent = formatTimelineDayHeading(value);
  li.appendChild(title);

  const chip = document.createElement('span');
  chip.className = 'inline-chip';
  chip.textContent = `${count} event${count === 1 ? '' : 's'}`;
  li.appendChild(chip);

  return li;
};

const renderActivityBars = () => {
  if (!dom.activityBars) return;

  dom.activityBars.innerHTML = '';

  const days = Array.isArray(state.activitySummary.recentDays) ? state.activitySummary.recentDays : [];
  if (!days.length) return;

  const max = Math.max(...days.map((item) => Number(item.count || 0)), 1);

  for (const item of days) {
    const bar = document.createElement('div');
    bar.className = 'mini-bar';

    const fill = document.createElement('div');
    fill.className = 'mini-bar-fill';
    fill.style.height = `${Math.max(8, Math.round((Number(item.count || 0) / max) * 42))}px`;
    fill.title = `${item.day}: ${item.count}`;

    const label = document.createElement('span');
    label.className = 'mini-bar-label';
    label.textContent = safeText(item.day).slice(5);

    bar.appendChild(fill);
    bar.appendChild(label);
    dom.activityBars.appendChild(bar);
  }
};

const renderOverviewActivity = () => {
  if (!dom.overviewActivityList) return;

  dom.overviewActivityList.innerHTML = '';

  const previewItems = state.activity.slice(0, OVERVIEW_ACTIVITY_LIMIT);
  if (!previewItems.length) {
    const li = document.createElement('li');
    li.textContent = 'No recent activity.';
    dom.overviewActivityList.appendChild(li);
    return;
  }

  for (const entry of previewItems) {
    dom.overviewActivityList.appendChild(createLoginActivityListItem(entry));
  }
};

const renderActivityAnalytics = () => {
  if (!dom.activityTrendChart || !dom.activityMixRing || !dom.activityHighlightGrid) return;

  const items = getFilteredTimelineItems();
  const bucketCounts = {
    logins: 0,
    security: 0,
    account: 0,
  };
  const dayCounts = new Map();
  const recentDays = [];
  const now = new Date();

  for (let offset = 6; offset >= 0; offset -= 1) {
    const day = new Date(now);
    day.setHours(12, 0, 0, 0);
    day.setDate(now.getDate() - offset);
    recentDays.push({
      key: getLocalDayKey(day),
      label: formatTrendLabel(day),
      count: 0,
    });
  }

  for (const item of items) {
    if (bucketCounts[item.bucket] !== undefined) {
      bucketCounts[item.bucket] += 1;
    }

    const key = getLocalDayKey(item.at);
    if (key) {
      dayCounts.set(key, (dayCounts.get(key) || 0) + 1);
    }
  }

  for (const day of recentDays) {
    day.count = dayCounts.get(day.key) || 0;
  }

  dom.activityTrendChart.innerHTML = '';
  const maxCount = Math.max(...recentDays.map((day) => day.count), 1);
  let weeklyTotal = 0;
  let peakDay = recentDays[0] || null;

  for (const day of recentDays) {
    weeklyTotal += day.count;
    if (!peakDay || day.count > peakDay.count) peakDay = day;

    const bar = document.createElement('div');
    bar.className = 'trend-bar';

    const fill = document.createElement('div');
    fill.className = 'trend-fill';
    fill.style.height = `${Math.max(12, Math.round((day.count / maxCount) * 120))}px`;
    fill.title = `${day.label}: ${day.count} event${day.count === 1 ? '' : 's'}`;

    const count = document.createElement('span');
    count.className = 'trend-count';
    count.textContent = String(day.count);

    const label = document.createElement('span');
    label.className = 'trend-label';
    label.textContent = day.label;

    bar.appendChild(count);
    bar.appendChild(fill);
    bar.appendChild(label);
    dom.activityTrendChart.appendChild(bar);
  }

  if (dom.activityTrendSummary) {
    dom.activityTrendSummary.textContent = weeklyTotal
      ? `${weeklyTotal} event${weeklyTotal === 1 ? '' : 's'} in the last 7 days. Peak ${peakDay?.label || '--'} with ${peakDay?.count || 0}.`
      : 'No recent events in the last 7 days for this filter.';
  }

  const total = items.length;
  if (dom.activityMixTotal) dom.activityMixTotal.textContent = String(total);

  const mixSegments = [
    { key: 'logins', label: 'Logins', count: bucketCounts.logins, color: 'var(--primary)' },
    { key: 'security', label: 'Security', count: bucketCounts.security, color: 'var(--secondary)' },
    { key: 'account', label: 'Account', count: bucketCounts.account, color: 'var(--success)' },
  ];

  let offset = 0;
  const gradientStops = [];
  for (const segment of mixSegments) {
    const ratio = total ? segment.count / total : 0;
    const start = Math.round(offset * 360);
    offset += ratio;
    const end = Math.round(offset * 360);
    gradientStops.push(`${segment.color} ${start}deg ${end}deg`);
  }
  if (dom.activityMixRing) {
    dom.activityMixRing.style.background = total
      ? `conic-gradient(${gradientStops.join(', ')})`
      : 'conic-gradient(color-mix(in srgb, var(--line) 72%, transparent) 0deg 360deg)';
  }

  if (dom.activityMixLegend) {
    dom.activityMixLegend.innerHTML = '';
    for (const segment of mixSegments) {
      const row = document.createElement('div');
      row.className = 'chart-legend-row';

      const left = document.createElement('div');
      left.className = 'chart-legend-label';
      const swatch = document.createElement('span');
      swatch.className = 'chart-swatch';
      swatch.style.background = segment.color;
      const label = document.createElement('span');
      label.textContent = segment.label;
      left.appendChild(swatch);
      left.appendChild(label);

      const right = document.createElement('strong');
      right.textContent = `${segment.count}`;

      row.appendChild(left);
      row.appendChild(right);
      dom.activityMixLegend.appendChild(row);
    }
  }

  if (dom.activityHighlightGrid) {
    dom.activityHighlightGrid.innerHTML = '';
    const highlightItems = [
      {
        label: 'Security events',
        value: String(bucketCounts.security),
        detail: bucketCounts.security ? 'Password, session, verification, and alert events.' : 'No recent security-side changes.',
      },
      {
        label: 'Unique IPs',
        value: String(state.activitySummary.uniqueIps || 0),
        detail: 'Unique login locations across the recent summary window.',
      },
      {
        label: 'Active days',
        value: String(recentDays.filter((day) => day.count > 0).length),
        detail: 'Days with at least one event in the last week.',
      },
      {
        label: 'Latest event',
        value: items[0]?.chip || 'None',
        detail: items[0] ? `${items[0].title} on ${formatDate(items[0].at)}.` : 'No events match the current filter.',
      },
    ];

    for (const highlight of highlightItems) {
      const card = document.createElement('article');
      card.className = 'activity-highlight-card';

      const label = document.createElement('span');
      label.textContent = highlight.label;
      const value = document.createElement('strong');
      value.textContent = highlight.value;
      const detail = document.createElement('p');
      detail.textContent = highlight.detail;

      card.appendChild(label);
      card.appendChild(value);
      card.appendChild(detail);
      dom.activityHighlightGrid.appendChild(card);
    }
  }
};

const renderActivity = () => {
  if (!dom.activityList) return;
  dom.activityList.innerHTML = '';
  const filtered = getFilteredTimelineItems();

  if (filtered.length === 0) {
    const li = document.createElement('li');
    const query = safeText(dom.activityFilter?.value).toLowerCase();
    const kind = safeText(dom.activityKind?.value).toLowerCase() || 'all';
    li.textContent = query || kind !== 'all'
      ? 'No activity items match this filter.'
      : 'No recent activity found.';
    dom.activityList.appendChild(li);
    renderActivityAnalytics();
    requestCollapsibleSectionsSync();
    return;
  }

  let currentDay = '';
  const dayCounts = new Map();

  for (const item of filtered) {
    const key = getLocalDayKey(item.at);
    dayCounts.set(key, (dayCounts.get(key) || 0) + 1);
  }

  for (let index = 0; index < filtered.length; index += 1) {
    const item = filtered[index];
    const dayKey = getLocalDayKey(item.at);

    if (dayKey !== currentDay) {
      currentDay = dayKey;
      dom.activityList.appendChild(createTimelineDayHeader(item.at, dayCounts.get(dayKey) || 0));
    }

    dom.activityList.appendChild(createTimelineListItem(item));
  }

  renderActivityAnalytics();
  requestCollapsibleSectionsSync();
};

const renderSessions = () => {
  if (!dom.sessionsList) return;

  dom.sessionsList.innerHTML = '';

  if (!state.sessions.length) {
    const li = document.createElement('li');
    li.textContent = 'No active sessions found.';
    dom.sessionsList.appendChild(li);
    requestCollapsibleSectionsSync();
    return;
  }

  for (const session of state.sessions) {
    const li = document.createElement('li');
    li.className = 'session-row';

    const head = document.createElement('div');
    head.className = 'session-head';

    const left = document.createElement('div');
    const label = document.createElement('strong');
    label.textContent = safeText(session.label) || 'Browser session';
    left.appendChild(label);

    if (session.newDevice || session.recognized) {
      left.appendChild(document.createTextNode(' '));
      const deviceChip = document.createElement('span');
      deviceChip.className = 'inline-chip';
      deviceChip.textContent = session.newDevice ? 'New device' : 'Recognized';
      left.appendChild(deviceChip);
    }

    const right = document.createElement('div');
    right.className = 'session-actions';

    if (session.current) {
      const chip = document.createElement('span');
      chip.className = 'inline-chip';
      chip.textContent = 'Current';
      right.appendChild(chip);
    }

    const revokeBtn = document.createElement('button');
    revokeBtn.type = 'button';
    revokeBtn.className = 'secondary-btn';
    revokeBtn.textContent = session.current ? 'Revoke Current Session' : 'Revoke';
    revokeBtn.addEventListener('click', async () => {
      const decision = await openDecisionModal({
        title: session.current ? 'Revoke current session' : 'Revoke session',
        copy: session.current
          ? 'Revoking the session you are using now may require you to sign in again immediately.'
          : 'This ends the selected session on that device.',
        confirmLabel: session.current ? 'Revoke current session' : 'Revoke session',
        confirmClassName: session.current ? 'danger-btn' : 'primary-btn',
      });
      if (!decision) return;

      setButtonBusy(revokeBtn, true, 'Revoking...');
      try {
        const data = await apiRequest(`/sessions/${encodeURIComponent(session.sid)}`, {
          method: 'DELETE',
          body: {},
        });

        showToast(data.message || 'Session revoked.', 'success');

        if (data.forceRelogin) {
          clearStoredAuth();
          stopSessionAutoRefresh();
          setLoggedOutUI();
          return;
        }

        await Promise.all([loadSessions(), loadCurrentUser()]);
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(revokeBtn, false);
      }
    });
    right.appendChild(revokeBtn);

    head.appendChild(left);
    head.appendChild(right);

    const meta = document.createElement('div');
    meta.className = 'session-meta';
    meta.textContent = `Last used: ${formatDate(session.lastUsedAt)} | Created: ${formatDate(session.createdAt)}`;

    const details = document.createElement('div');
    details.className = 'session-meta';
    details.textContent = [
      `IP: ${safeText(session.ip) || 'Unknown'}`,
      safeText(session.userAgent) || 'Unknown device',
      session.newDevice ? 'First seen on this device' : session.recognized ? 'Known device' : '',
      session.deviceTrusted ? 'Trusted device' : '',
    ]
      .filter(Boolean)
      .join(' | ');

    li.appendChild(head);
    li.appendChild(meta);
    li.appendChild(details);
    dom.sessionsList.appendChild(li);
  }

  requestCollapsibleSectionsSync();
};

const renderBackupCodes = (codes = []) => {
  if (!dom.mfaBackupCodes) return;

  dom.mfaBackupCodes.innerHTML = '';
  if (dom.mfaBackupCodesPanel) dom.mfaBackupCodesPanel.hidden = true;
  if (!Array.isArray(codes) || !codes.length) return;

  for (const code of codes) {
    const item = document.createElement('div');
    item.className = 'backup-code-item';
    item.textContent = safeText(code);
    dom.mfaBackupCodes.appendChild(item);
  }

  if (dom.mfaBackupCodesPanel) dom.mfaBackupCodesPanel.hidden = false;
};

const renderMfaState = (user = state.user) => {
  const mfa = normalizeMfaState(user?.security?.mfa);
  const showSetupPanel = !mfa.enabled && state.mfaSetupOpen;
  const showSetupSteps = Boolean(state.mfaSetup?.secret);
  const manageConfig = getMfaManageConfig();
  renderMfaModal();
  renderDeleteModal();

  if (dom.mfaStatusCopy) {
    if (mfa.enabled) {
      dom.mfaStatusCopy.textContent = `MFA on. Backup codes: ${mfa.backupCodesRemaining}. Last used: ${formatDate(mfa.lastUsedAt)}.`;
    } else if (state.mfaSetup?.secret) {
      dom.mfaStatusCopy.textContent = 'Setup in progress. Scan the QR code or use the setup key below, then enter the 6-digit code from your app.';
    } else if (showSetupPanel) {
      dom.mfaStatusCopy.textContent = 'Start by entering your current password below. The QR code appears right after that.';
    } else {
      dom.mfaStatusCopy.textContent = 'MFA off.';
    }
  }

  if (dom.mfaSetupBtn) dom.mfaSetupBtn.disabled = mfa.enabled;
  if (dom.mfaSetupBtn && !mfa.enabled) {
    dom.mfaSetupBtn.textContent = state.mfaSetup?.secret ? 'Resume Setup' : 'Set Up MFA';
  }
  if (dom.mfaDisableBtn) dom.mfaDisableBtn.disabled = !mfa.enabled;
  if (dom.mfaBackupBtn) dom.mfaBackupBtn.disabled = !mfa.enabled;
  if (dom.mfaSetupPanel) dom.mfaSetupPanel.hidden = !showSetupPanel;
  if (dom.mfaSetupSteps) dom.mfaSetupSteps.hidden = !showSetupSteps;
  if (dom.mfaStartSetupBtn) {
    const setupLabel = showSetupSteps ? 'Refresh setup' : 'Continue';
    dom.mfaStartSetupBtn.textContent = setupLabel;
    dom.mfaStartSetupBtn.dataset.defaultLabel = setupLabel;
  }
  if (dom.mfaCurrentPassword && !showSetupPanel) dom.mfaCurrentPassword.value = '';
  if (dom.mfaCode && !showSetupSteps) dom.mfaCode.value = '';
  if (dom.mfaQrShell) dom.mfaQrShell.hidden = !state.mfaSetup?.qrCodeDataUrl;
  if (dom.mfaQrImage) {
    if (state.mfaSetup?.qrCodeDataUrl) {
      dom.mfaQrImage.src = state.mfaSetup.qrCodeDataUrl;
    } else {
      dom.mfaQrImage.removeAttribute('src');
    }
  }
  if (dom.mfaSecret) dom.mfaSecret.value = safeText(state.mfaSetup?.secret);
  if (dom.mfaOtpAuthUrl) dom.mfaOtpAuthUrl.value = safeText(state.mfaSetup?.otpAuthUrl);
  if (dom.mfaManagePanel) dom.mfaManagePanel.hidden = !mfa.enabled || !manageConfig;
  if (dom.mfaManageTitle && manageConfig) dom.mfaManageTitle.textContent = manageConfig.title;
  if (dom.mfaManageCopy && manageConfig) dom.mfaManageCopy.textContent = manageConfig.copy;
  if (dom.mfaManageConfirmBtn && manageConfig) {
    dom.mfaManageConfirmBtn.textContent = manageConfig.confirmLabel;
    dom.mfaManageConfirmBtn.className = manageConfig.confirmClassName;
    dom.mfaManageConfirmBtn.dataset.defaultLabel = manageConfig.confirmLabel;
  }
  requestCollapsibleSectionsSync();
};

const renderPasskeys = (user = state.user) => {
  const passkeys = normalizePasskeyState(user?.security?.passkeys);
  const supported = Boolean(window.WebAuthnJson?.isSupported?.());
  renderPasskeyModal();

  if (dom.passkeyStatusCopy) {
    if (!supported) {
      dom.passkeyStatusCopy.textContent = 'This browser does not support passkeys.';
    } else if (passkeys.count > 0) {
      dom.passkeyStatusCopy.textContent = `${passkeys.count} passkey${
        passkeys.count === 1 ? '' : 's'
      } saved. Last used: ${formatDate(passkeys.lastUsedAt)}.`;
    } else {
      dom.passkeyStatusCopy.textContent = 'No passkeys saved.';
    }
  }

  if (dom.passkeyRegisterBtn) dom.passkeyRegisterBtn.disabled = !supported;
  if (dom.passkeyManageBtn) dom.passkeyManageBtn.disabled = !supported;
  if (dom.passkeyManageBtn) {
    dom.passkeyManageBtn.textContent = passkeys.count > 0 ? 'Manage Passkeys' : 'Set Up Passkey';
  }
  if (dom.passkeyChallengeRow) dom.passkeyChallengeRow.hidden = !requiresSensitiveActionMfa();
  if (!dom.passkeyList) return;

  dom.passkeyList.innerHTML = '';
  if (!passkeys.items.length) {
    const li = document.createElement('li');
    li.textContent = supported ? 'No passkeys saved.' : 'Passkeys are unavailable in this browser.';
    dom.passkeyList.appendChild(li);
    requestCollapsibleSectionsSync();
    return;
  }

  for (const passkey of passkeys.items) {
    const li = document.createElement('li');
    li.className = 'passkey-card';

    const head = document.createElement('div');
    head.className = 'session-head';

    const left = document.createElement('div');
    const title = document.createElement('strong');
    title.textContent = passkey.name || 'Passkey';
    left.appendChild(title);

    const chipRow = document.createElement('div');
    chipRow.className = 'session-actions';

    const typeChip = document.createElement('span');
    typeChip.className = 'inline-chip';
    typeChip.textContent = passkey.deviceType === 'multiDevice' ? 'Synced passkey' : 'Device passkey';
    chipRow.appendChild(typeChip);

    if (passkey.backedUp) {
      const backupChip = document.createElement('span');
      backupChip.className = 'inline-chip';
      backupChip.textContent = 'Backed up';
      chipRow.appendChild(backupChip);
    }

    left.appendChild(chipRow);

    const actions = document.createElement('div');
    actions.className = 'session-actions';

    const removeBtn = document.createElement('button');
    removeBtn.type = 'button';
    removeBtn.className = 'danger-btn';
    removeBtn.textContent = 'Remove';
    removeBtn.addEventListener('click', async () => {
      const currentPassword = dom.passkeyCurrentPassword?.value || '';
      if (!currentPassword) {
        showToast('Enter your current password before removing a passkey.', 'error');
        dom.passkeyCurrentPassword?.focus();
        return;
      }
      const decision = await openDecisionModal({
        title: 'Remove passkey',
        copy: `Remove ${passkey.name || 'this passkey'} from your account?`,
        confirmLabel: 'Remove passkey',
        confirmClassName: 'danger-btn',
      });
      if (!decision) return;
      const passkeyRemovalMfa = getPasskeyModalMfa();
      if (!passkeyRemovalMfa) return;

      setButtonBusy(removeBtn, true, 'Removing...');
      try {
        const data = await apiRequest(`/passkeys/${encodeURIComponent(passkey.credentialId)}`, {
          method: 'DELETE',
          auth: true,
          body: { currentPassword, ...passkeyRemovalMfa },
        });
        if (!state.user) state.user = {};
        state.user.security = data.security || data.user?.security || state.user.security || {};
        clearPasskeyInputs();
        fillSecurity(state.user);
        showToast(data.message || 'Passkey removed.', 'success');
      } catch (error) {
        showToast(error.message || 'Failed to remove the passkey.', 'error');
      } finally {
        setButtonBusy(removeBtn, false);
      }
    });

    actions.appendChild(removeBtn);
    head.appendChild(left);
    head.appendChild(actions);

    const meta = document.createElement('p');
    meta.className = 'session-meta';
    meta.textContent = `Created: ${formatDate(passkey.createdAt)} | Last used: ${formatDate(
      passkey.lastUsedAt
    )}`;

    const detail = document.createElement('p');
    detail.className = 'session-meta';
    detail.textContent = passkey.transports.length
      ? `Transports: ${passkey.transports.join(', ')}`
      : 'Transports: Not reported by the authenticator';

    li.appendChild(head);
    li.appendChild(meta);
    li.appendChild(detail);
    dom.passkeyList.appendChild(li);
  }

  requestCollapsibleSectionsSync();
};

const renderDevices = () => {
  if (!dom.devicesList) return;

  dom.devicesList.innerHTML = '';
  if (!state.devices.length) {
    const li = document.createElement('li');
    li.textContent = 'No known devices found.';
    dom.devicesList.appendChild(li);
    requestCollapsibleSectionsSync();
    return;
  }

  for (const device of state.devices) {
    const li = document.createElement('li');
    li.className = 'device-card';

    const head = document.createElement('div');
    head.className = 'session-head';

    const title = document.createElement('strong');
    title.textContent = safeText(device.label) || 'Browser device';
    head.appendChild(title);

    const right = document.createElement('div');
    right.className = 'session-actions';

    if (device.current) {
      const currentChip = document.createElement('span');
      currentChip.className = 'inline-chip';
      currentChip.textContent = 'Current device';
      right.appendChild(currentChip);
    }

    const trustBtn = document.createElement('button');
    trustBtn.type = 'button';
    trustBtn.className = 'secondary-btn';
    trustBtn.textContent = device.trusted ? 'Mark Untrusted' : 'Trust Device';
    trustBtn.addEventListener('click', async () => {
      setButtonBusy(trustBtn, true, 'Saving...');
      try {
        await apiRequest(`/devices/${encodeURIComponent(device.fingerprint)}`, {
          method: 'PATCH',
          body: { trusted: !device.trusted },
        });
        await loadDevices();
        await loadCurrentUser();
        showToast(device.trusted ? 'Device marked untrusted.' : 'Device trusted.', 'success');
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(trustBtn, false);
      }
    });
    right.appendChild(trustBtn);

    const renameBtn = document.createElement('button');
    renameBtn.type = 'button';
    renameBtn.className = 'secondary-btn';
    renameBtn.textContent = 'Rename';
    renameBtn.addEventListener('click', async () => {
      const decision = await openDecisionModal({
        title: 'Rename device',
        copy: 'Use a short label that makes this device easy to recognize later.',
        confirmLabel: 'Save label',
        fields: [
          {
            id: 'decision-device-label',
            name: 'label',
            label: 'Device label',
            value: safeText(device.label) || 'Browser device',
            required: true,
            maxlength: 80,
            selectOnFocus: true,
          },
        ],
        validate: (values) => (safeText(values.label) ? '' : 'Enter a device label before saving.'),
      });
      if (!decision) return;

      setButtonBusy(renameBtn, true, 'Saving...');
      try {
        await apiRequest(`/devices/${encodeURIComponent(device.fingerprint)}`, {
          method: 'PATCH',
          body: { label: decision.label },
        });
        await Promise.all([loadDevices(), loadSessions()]);
        showToast('Device label updated.', 'success');
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(renameBtn, false);
      }
    });
    right.appendChild(renameBtn);

    const forgetBtn = document.createElement('button');
    forgetBtn.type = 'button';
    forgetBtn.className = 'danger-btn';
    forgetBtn.textContent = device.current ? 'Remove Device' : 'Forget Device';
    forgetBtn.addEventListener('click', async () => {
      const decision = await openDecisionModal({
        title: device.current ? 'Remove current device' : 'Forget device',
        copy: 'This removes the saved device record and revokes any sessions tied to it.',
        confirmLabel: device.current ? 'Remove device' : 'Forget device',
        confirmClassName: 'danger-btn',
      });
      if (!decision) return;

      setButtonBusy(forgetBtn, true, 'Removing...');
      try {
        const data = await apiRequest(`/devices/${encodeURIComponent(device.fingerprint)}`, {
          method: 'DELETE',
          body: { revokeSessions: true },
        });
        showToast(data.message || 'Device removed.', 'success');

        if (data.forceRelogin) {
          clearStoredAuth();
          stopSessionAutoRefresh();
          setLoggedOutUI();
          return;
        }

        await Promise.all([loadDevices(), loadSessions(), loadCurrentUser()]);
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(forgetBtn, false);
      }
    });
    right.appendChild(forgetBtn);

    head.appendChild(right);

    const meta = document.createElement('div');
    meta.className = 'session-meta';
    meta.textContent = [
      `Last seen: ${formatDate(device.lastSeenAt)}`,
      `First seen: ${formatDate(device.firstSeenAt)}`,
      device.trusted ? 'Trusted' : 'Untrusted',
      `${Number(device.activeSessions || 0)} active session${Number(device.activeSessions || 0) === 1 ? '' : 's'}`,
    ].join(' | ');

    const detail = document.createElement('div');
    detail.className = 'session-meta';
    detail.textContent = [
      `IP: ${safeText(device.lastIp) || 'Unknown'}`,
      safeText(device.userAgent) || 'Unknown device',
    ]
      .filter(Boolean)
      .join(' | ');

    li.appendChild(head);
    li.appendChild(meta);
    li.appendChild(detail);
    dom.devicesList.appendChild(li);
  }

  requestCollapsibleSectionsSync();
};

const launchService = (entry) => {
  if (!entry?.href) return;
  trackServiceLaunch(entry.key);
  renderServices();
  renderLauncher();
  window.open(entry.href, '_blank', 'noopener');
  closeLauncher();
};

const renderPinnedServices = (entries) => {
  if (!dom.pinnedServices) return;

  dom.pinnedServices.innerHTML = '';
  const pinnedEntries = entries.filter((entry) => entry.pinned);
  dom.pinnedServices.hidden = pinnedEntries.length === 0;

  for (const entry of pinnedEntries) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'pinned-service-pill';
    button.textContent = entry.title;
    button.addEventListener('click', () => launchService(entry));
    dom.pinnedServices.appendChild(button);
  }
};

const setLauncherActiveIndex = (nextIndex) => {
  if (!dom.launcherList) return;

  const items = Array.from(dom.launcherList.querySelectorAll('.launcher-item'));
  if (!items.length) {
    state.launcherActiveIndex = 0;
    return;
  }

  state.launcherActiveIndex = (nextIndex + items.length) % items.length;
  items.forEach((item, index) => {
    const active = index === state.launcherActiveIndex;
    item.classList.toggle('active', active);
    item.setAttribute('aria-selected', active ? 'true' : 'false');
  });
};

const renderLauncher = () => {
  if (!dom.launcherList) return;

  const query = safeText(dom.launcherSearch?.value).toLowerCase();
  const entries = sortServiceEntries(getServiceEntries()).filter((entry) => {
    const searchText = `${entry.title} ${entry.category} ${entry.description}`.toLowerCase();
    return !query || searchText.includes(query);
  });

  dom.launcherList.innerHTML = '';
  state.launcherActiveIndex = 0;

  if (dom.launcherResultsCount) {
    dom.launcherResultsCount.textContent = `${entries.length} service${entries.length === 1 ? '' : 's'} available`;
  }

  if (dom.launcherEmptyState) {
    dom.launcherEmptyState.hidden = entries.length !== 0;
  }

  for (const entry of entries) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'launcher-item';

    const head = document.createElement('div');
    head.className = 'launcher-item-head';

    const title = document.createElement('strong');
    title.textContent = entry.title;
    head.appendChild(title);

    const chip = document.createElement('span');
    chip.className = 'inline-chip';
    chip.textContent = entry.pinned ? 'Pinned' : entry.category || 'Service';
    head.appendChild(chip);

    const detail = document.createElement('p');
    detail.textContent = entry.description || 'Open service.';

    button.appendChild(head);
    button.appendChild(detail);
    button.addEventListener('mouseenter', () => {
      const items = Array.from(dom.launcherList.querySelectorAll('.launcher-item'));
      setLauncherActiveIndex(items.indexOf(button));
    });
    button.addEventListener('click', () => launchService(entry));
    dom.launcherList.appendChild(button);
  }

  setLauncherActiveIndex(0);
};

const openLauncher = () => {
  if (!dom.launcherModal) return;

  state.launcherOpen = true;
  state.launcherLastFocusedElement = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  dom.launcherModal.hidden = false;
  syncOverlayLock();
  if (dom.launcherSearch) {
    dom.launcherSearch.value = safeText(dom.serviceFilter?.value);
  }
  renderLauncher();
  window.setTimeout(() => dom.launcherSearch?.focus(), 40);
};

const closeLauncher = () => {
  if (!dom.launcherModal) return;

  state.launcherOpen = false;
  dom.launcherModal.hidden = true;
  syncOverlayLock();
  state.launcherLastFocusedElement?.focus?.();
};

const renderServices = () => {
  if (!dom.serviceList || !dom.serviceCards.length) return;

  const query = safeText(dom.serviceFilter?.value).toLowerCase();
  const entries = sortServiceEntries(getServiceEntries());
  let visibleCount = 0;

  for (const entry of entries) {
    const searchText = `${entry.title} ${entry.category} ${entry.description}`.toLowerCase();
    const visible = (!query || searchText.includes(query)) && (!state.favoriteServicesOnly || entry.pinned);

    entry.card.classList.toggle('hidden', !visible);
    entry.card.classList.toggle('pinned', entry.pinned);

    const pinButton = entry.card.querySelector('.service-pin-btn');
    if (pinButton) {
      pinButton.textContent = entry.pinned ? 'Pinned' : 'Pin';
      pinButton.setAttribute('aria-pressed', entry.pinned ? 'true' : 'false');
    }

    dom.serviceList.appendChild(entry.card);
    if (visible) visibleCount += 1;
  }

  renderPinnedServices(entries.filter((entry) => {
    const searchText = `${entry.title} ${entry.category} ${entry.description}`.toLowerCase();
    return (!query || searchText.includes(query)) && (!state.favoriteServicesOnly || entry.pinned);
  }));

  if (dom.favoriteFilterBtn) {
    dom.favoriteFilterBtn.classList.toggle('active', state.favoriteServicesOnly);
    dom.favoriteFilterBtn.textContent = state.favoriteServicesOnly ? 'Show all' : 'Pinned only';
  }

  if (dom.serviceResultsCount) {
    if (query) {
      dom.serviceResultsCount.textContent = `${visibleCount} result${visibleCount === 1 ? '' : 's'} for "${query}"`;
    } else if (state.favoriteServicesOnly) {
      dom.serviceResultsCount.textContent = `${visibleCount} pinned service${visibleCount === 1 ? '' : 's'}`;
    } else {
      dom.serviceResultsCount.textContent = `${visibleCount} service${visibleCount === 1 ? '' : 's'} available`;
    }
  }

  if (dom.serviceEmptyState) {
    dom.serviceEmptyState.hidden = visibleCount !== 0;
  }

  if (state.launcherOpen) {
    renderLauncher();
  }
};

const syncUiWithUser = (user) => {
  if (!user) return;

  state.user = user;
  state.activity = Array.isArray(user.recentLogins) ? user.recentLogins : [];
  state.auditEvents = Array.isArray(user.auditEvents) ? user.auditEvents.map((event) => normalizeAuditEvent(event)) : [];
  state.activitySummary = normalizeActivitySummary(user.activitySummary);

  fillSummary(user);
  fillProfile(user);
  fillLinkedAccounts(user);
  fillPreferences(user);
  fillSecurity(user);
  renderActivity();
  renderOverviewActivity();
  renderActivityBars();
  renderInsights();
  renderOwnerAccess();
  if (!isOwnerUser(user)) {
    state.ownerSummary = normalizeOwnerSummary();
    state.ownerUsers = [];
    state.ownerSelectedUserId = '';
    state.ownerSelectedUser = null;
    state.ownerSelectedAuditEvents = [];
  }
  renderOwnerSummary();
  renderOwnerUserList();
  renderOwnerUserDetail();
  renderVerificationState(user);
  renderDevices();
  renderServices();
  renderAvatarPreviews(user);
  renderPublicProfilePreview(user);
  renderSecurityPosture(user);

  const statusText = `Workspace ready for ${getUserHandle(user) || user.email || user.displayName || user.userId}`;
  setStatus(statusText, { clickable: false });

  if (dom.logoutBtn) {
    dom.logoutBtn.style.display = 'inline-flex';
  }
};

const loadCurrentUser = async () => {
  const payload = await apiRequest('/me', { method: 'GET', auth: true });
  const user = normalizeUserPayload(payload);

  syncUiWithUser(user);
  return user;
};

const loadActivity = async () => {
  const data = await apiRequest('/activity', { method: 'GET', auth: true });
  state.activity = Array.isArray(data.recentLogins) ? data.recentLogins : [];
  state.auditEvents = Array.isArray(data.auditEvents) ? data.auditEvents.map((event) => normalizeAuditEvent(event)) : [];
  state.activitySummary = normalizeActivitySummary(data.summary);

  renderActivity();
  renderOverviewActivity();
  renderActivityBars();
  renderInsights();
  renderSecurityPosture(state.user);
};

const loadPreferences = async () => {
  const data = await apiRequest('/preferences', { method: 'GET', auth: true });
  if (!state.user) state.user = {};
  state.user.preferences = data.preferences || state.user.preferences || {};
  fillPreferences(state.user);
};

const loadLinkedAccounts = async () => {
  const data = await apiRequest('/linked', { method: 'GET', auth: true });
  if (!state.user) state.user = {};
  state.user.linkedAccounts = data.linkedAccounts || state.user.linkedAccounts || {};
  state.user.oauthProviders = data.oauthProviders || state.user.oauthProviders || {};
  fillLinkedAccounts(state.user);
};

const loadSecurity = async () => {
  const data = await apiRequest('/security', { method: 'GET', auth: true });
  if (!state.user) state.user = {};
  state.user.security = data.security || state.user.security || {};
  state.sessionLimit = data.sessionLimit || state.sessionLimit;
  fillSecurity(state.user);

  updateSessionNote();
};

const loadDevices = async () => {
  const data = await apiRequest('/devices', { method: 'GET', auth: true });
  state.devices = Array.isArray(data.devices) ? data.devices : [];

  if (!state.user) state.user = {};
  if (!state.user.security) state.user.security = {};
  state.user.security.knownDevices = state.devices.length;

  renderDevices();
  updateSessionNote();
  renderSecurityPosture(state.user);
};

const loadSessions = async () => {
  const data = await apiRequest('/sessions', { method: 'GET', auth: true });
  state.sessions = Array.isArray(data.sessions) ? data.sessions : [];
  state.sessionLimit = data.sessionLimit || state.sessionLimit;

  if (!state.user) state.user = {};
  if (!state.user.security) state.user.security = {};
  state.user.security.activeSessions = state.sessions.length;

  if (dom.summarySessions) {
    dom.summarySessions.textContent = String(state.sessions.length);
  }

  if (state.user) {
    fillSummary(state.user);
  }

  renderSessions();

  updateSessionNote();
  renderSecurityPosture(state.user);
};

const loadOwnerSummary = async () => {
  if (!isOwnerUser(state.user)) {
    state.ownerSummary = normalizeOwnerSummary();
    renderOwnerSummary();
    return null;
  }

  const data = await apiRequest('/owner/summary', { method: 'GET', auth: true });
  state.ownerSummary = normalizeOwnerSummary(data.summary);
  renderOwnerSummary();
  return data.summary;
};

const loadOwnerUser = async (userId) => {
  if (!isOwnerUser(state.user) || !safeText(userId)) {
    state.ownerSelectedUserId = '';
    state.ownerSelectedUser = null;
    state.ownerSelectedAuditEvents = [];
    renderOwnerUserDetail();
    return null;
  }

  const data = await apiRequest(`/owner/users/${encodeURIComponent(userId)}`, {
    method: 'GET',
    auth: true,
  });
  state.ownerSelectedUserId = safeText(userId);
  state.ownerSelectedUser = data.ownerUser || null;
  state.ownerSelectedAuditEvents = Array.isArray(data.auditEvents)
    ? data.auditEvents.map((event) => normalizeAuditEvent(event))
    : [];
  state.ownerUsers = state.ownerUsers.map((entry) =>
    entry.userId === state.ownerSelectedUserId ? { ...entry, ...(data.ownerUser || {}) } : entry
  );
  renderOwnerUserList();
  renderOwnerUserDetail();
  return data.ownerUser;
};

const loadOwnerUsers = async ({ preserveSelection = true, selectedUserId = '' } = {}) => {
  if (!isOwnerUser(state.user)) {
    state.ownerUsers = [];
    state.ownerSelectedUserId = '';
    state.ownerSelectedUser = null;
    state.ownerSelectedAuditEvents = [];
    renderOwnerUserList();
    renderOwnerUserDetail();
    return [];
  }

  const params = new URLSearchParams();
  const query = safeText(dom.ownerSearch?.value);
  const role = safeText(dom.ownerRoleFilter?.value).toLowerCase();
  const status = safeText(dom.ownerStatusFilter?.value).toLowerCase();
  if (query) params.set('q', query);
  if (role) params.set('role', role);
  if (status) params.set('status', status);
  params.set('limit', '80');

  const data = await apiRequest(`/owner/users?${params.toString()}`, { method: 'GET', auth: true });
  state.ownerUsers = Array.isArray(data.users) ? data.users : [];

  const preferredUserId = safeText(selectedUserId)
    || (preserveSelection ? safeText(state.ownerSelectedUserId) : '')
    || safeText(state.ownerUsers[0]?.userId);
  const hasPreferredUser = state.ownerUsers.some((entry) => entry.userId === preferredUserId);

  state.ownerSelectedUserId = hasPreferredUser ? preferredUserId : '';
  state.ownerSelectedUser = state.ownerUsers.find((entry) => entry.userId === state.ownerSelectedUserId) || null;
  renderOwnerUserList();
  renderOwnerUserDetail();

  if (state.ownerSelectedUserId) {
    await loadOwnerUser(state.ownerSelectedUserId);
  }

  return state.ownerUsers;
};

const loadOwnerData = async ({ preserveSelection = true } = {}) => {
  if (!isOwnerUser(state.user)) {
    renderOwnerAccess();
    renderOwnerSummary();
    renderOwnerUserList();
    renderOwnerUserDetail();
    return;
  }

  await Promise.all([loadOwnerSummary(), loadOwnerUsers({ preserveSelection })]);
};

const loadDashboardData = async ({ silent = false } = {}) => {
  if (!silent && dom.loadingMessage) {
    dom.loadingMessage.textContent = 'Loading dashboard...';
  }

  const user = await loadCurrentUser();
  let sessionsError = null;

  try {
    await loadSessions();
  } catch (error) {
    sessionsError = error;
  }

  try {
    await loadDevices();
  } catch (error) {
    if (state.appVisible) {
      showToast('Account loaded, but devices could not be refreshed.', 'warn', 3600);
    }
  }

  if (sessionsError && !state.user) {
    throw sessionsError;
  }

  try {
    await loadOwnerData();
  } catch (error) {
    if (state.appVisible && isOwnerUser(state.user)) {
      showToast('Account loaded, but owner tools could not be refreshed.', 'warn', 3600);
    }
  }

  for (const form of trackedForms) {
    markFormClean(form);
  }
  state.lastSyncAt = new Date();
  setSyncStatus(state.lastSyncAt);

  if (sessionsError && state.appVisible) {
    showToast('Account loaded, but active sessions could not be refreshed.', 'warn', 3600);
  }

  return user;
};

const showApp = () => {
  if (state.appVisible) return;
  state.appVisible = true;

  if (!dom.loadingScreen || !dom.appContent) return;

  if (dom.loadingActions) {
    dom.loadingActions.hidden = true;
  }

  updateSkipLinkTarget('dashboard-main');

  dom.appContent.style.display = 'grid';
  dom.appContent.offsetWidth;
  dom.appContent.classList.add('fade-in');

  dom.loadingScreen.style.pointerEvents = 'none';
  dom.loadingScreen.style.opacity = '0';
  setTimeout(() => {
    dom.loadingScreen.style.display = 'none';

    if (dom.cookiePopup && dom.cookieAcceptBtn) {
      if (!localStorage.getItem('cookiesAccepted')) {
        dom.cookiePopup.classList.remove('hide');
      }

      dom.cookieAcceptBtn.onclick = () => {
        localStorage.setItem('cookiesAccepted', 'true');
        dom.cookiePopup.classList.add('hide');
      };
    }
  }, 650);
};

const initializeSession = async () => {
  const strippedLegacyParams = stripLegacyAuthParamsFromUrl();

  const refreshed = await refreshSession();
  if (!refreshed.ok) return refreshed;

  try {
    await loadDashboardData();
    if (strippedLegacyParams) {
      showToast('Old sign-in parameters were removed from the URL. The current session flow is now in use.', 'info', 5000);
    }
    return { ok: true };
  } catch (error) {
    const retry = await refreshSession();
    if (!retry.ok) return retry;

    try {
      await loadDashboardData();
      if (strippedLegacyParams) {
        showToast('Old sign-in parameters were removed from the URL. The current session flow is now in use.', 'info', 5000);
      }
      return { ok: true };
    } catch (retryError) {
      return classifyStartupFailure(retryError || error);
    }
  }
};

const bootstrapSession = async ({ busyButton = null, busyLabel = 'Checking...' } = {}) => {
  if (busyButton) {
    setButtonBusy(busyButton, true, busyLabel);
  }

  setLandingState({
    stateName: 'loading',
    statusText: 'Checking connection',
    title: 'Checking your workspace',
    message: 'Loading your dashboard...',
    detail: 'Verifying the account service and refreshing your session.',
    showActions: false,
  });

  try {
    const result = await initializeSession();

    if (result.ok) {
      showApp();
      startSessionAutoRefresh();
      return result;
    }

    if (result.reason === 'unauthenticated') {
      setLoggedOutUI();
    } else {
      setServiceUnavailableUI(result);
    }

    return result;
  } finally {
    if (busyButton) {
      setButtonBusy(busyButton, false);
    }
  }
};

const retryLandingConnection = async () => {
  await bootstrapSession({
    busyButton: dom.loadingSignInBtn,
    busyLabel: 'Retrying...',
  });
};

const doLogout = async () => {
  try {
    await apiRequest('/logout', { method: 'POST', auth: false });
  } catch {
    // local logout proceeds even if API logout fails
  }

  clearStoredAuth();
  stopSessionAutoRefresh();
  closeLoginPopup();
  openLoginPage({ replace: true });
};

const exportActivityCsv = () => {
  const items = getFilteredTimelineItems();

  if (!items.length) {
    showToast('No activity to export.', 'warn');
    return;
  }

  const header = ['Timestamp', 'Category', 'Title', 'Detail'];
  const rows = items.map((item) => [
    formatDate(item.at),
    item.chip,
    item.title,
    safeText(item.detail).replace(/\n/g, ' '),
  ]);

  const toCsvCell = (value) => `"${String(value || '').replaceAll('"', '""')}"`;
  const csvLines = [header, ...rows].map((line) => line.map(toCsvCell).join(','));
  const csv = csvLines.join('\n');

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  link.download = `continental-activity-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();

  URL.revokeObjectURL(url);
  showToast('Activity exported.', 'success');
};

const downloadJsonFile = (filename, data) => {
  const json = JSON.stringify(data, null, 2);
  const blob = new Blob([json], { type: 'application/json;charset=utf-8;' });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();

  URL.revokeObjectURL(url);
};

const exportAccountJson = async () => {
  const data = await apiRequest('/export', { method: 'GET', auth: true });
  const fileName = `continental-account-export-${new Date().toISOString().slice(0, 10)}.json`;
  downloadJsonFile(fileName, data);
  showToast('Account export downloaded.', 'success');
};

const getSelectedOwnerUserOrThrow = () => {
  const user = getSelectedOwnerUser();
  if (!user) {
    throw new Error('Select a user from the owner list first.');
  }
  return user;
};

const buildOwnerUserUpdatePayload = () => {
  const selectedUser = getSelectedOwnerUserOrThrow();
  const username = safeText(dom.ownerUserUsername?.value).toLowerCase();
  const displayName = safeText(dom.ownerUserDisplayName?.value);
  const status = safeText(dom.ownerUserStatus?.value).toLowerCase() || 'active';
  const statusReason = safeText(dom.ownerUserStatusReason?.value);
  const flagged = Boolean(dom.ownerUserVanguardFlagged?.checked);
  const flagReason = safeText(dom.ownerUserVanguardFlagReason?.value);

  if (!/^[a-z0-9](?:[a-z0-9._-]{1,28}[a-z0-9])?$/.test(username)) {
    throw new Error('Username must be 3-30 characters and can only use letters, numbers, dots, hyphens, or underscores.');
  }
  if (containsBlockedNameTerm(username)) {
    throw new Error('Choose a different username. Usernames cannot contain offensive or hateful language.');
  }
  if (displayName.length < 2) {
    throw new Error('Display name must be at least 2 characters.');
  }
  if (containsBlockedNameTerm(displayName)) {
    throw new Error('Choose a different display name. Display names cannot contain offensive or hateful language.');
  }
  if (status === 'suspended' && !statusReason) {
    throw new Error('Add a suspension reason before saving this owner update.');
  }
  if (flagged && !flagReason) {
    throw new Error('Add a Vanguard flag reason before saving a flagged account.');
  }

  return {
    displayName,
    username,
    isVerified: Boolean(dom.ownerUserVerified?.checked),
    profile: {
      headline: safeText(dom.ownerUserHeadline?.value),
      role: safeText(dom.ownerUserProfileRole?.value),
      organization: safeText(dom.ownerUserOrganization?.value),
      location: safeText(dom.ownerUserLocation?.value),
    },
    authority: {
      role: safeText(dom.ownerUserRole?.value).toLowerCase() || 'user',
      status,
      statusReason,
    },
    preferences: {
      profilePublic: Boolean(dom.ownerUserProfilePublic?.checked),
      searchable: Boolean(dom.ownerUserSearchable?.checked),
    },
    vanguard: {
      trusted: Boolean(dom.ownerUserVanguardTrusted?.checked),
      staff: Boolean(dom.ownerUserVanguardStaff?.checked),
      flagged,
      bannedFromAi: Boolean(dom.ownerUserVanguardBanned?.checked),
      flagReason,
    },
    selectedUserId: selectedUser.userId,
  };
};

const refreshOwnerWorkspace = async (selectedUserId = state.ownerSelectedUserId) => {
  const currentUserId = safeText(state.user?.userId || state.user?.continentalId);
  if (selectedUserId && currentUserId && selectedUserId === currentUserId) {
    await loadCurrentUser();
  }

  if (isOwnerUser(state.user)) {
    await loadOwnerData({ preserveSelection: true });
  }
};

const selectOwnerUser = async (userId) => {
  const nextUserId = safeText(userId);
  if (!nextUserId || !isOwnerUser(state.user)) return;

  state.ownerSelectedUserId = nextUserId;
  state.ownerSelectedUser = state.ownerUsers.find((entry) => entry.userId === nextUserId) || null;
  renderOwnerUserList();
  renderOwnerUserDetail();

  try {
    await loadOwnerUser(nextUserId);
  } catch (err) {
    showToast(err.message, 'error');
  }
};

const handleOwnerSave = async (event) => {
  event.preventDefault();

  let payload;
  try {
    payload = buildOwnerUserUpdatePayload();
  } catch (err) {
    showToast(err.message, 'error');
    return;
  }

  setButtonBusy(dom.ownerUserSaveBtn, true, 'Saving...');
  try {
    const result = await apiRequest(`/owner/users/${encodeURIComponent(payload.selectedUserId)}`, {
      method: 'PATCH',
      body: {
        displayName: payload.displayName,
        username: payload.username,
        isVerified: payload.isVerified,
        profile: payload.profile,
        authority: payload.authority,
        preferences: payload.preferences,
        vanguard: payload.vanguard,
      },
    });
    showToast(result.message || 'Owner changes saved.', 'success');
    await refreshOwnerWorkspace(payload.selectedUserId);
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.ownerUserSaveBtn, false);
  }
};

const runOwnerUserAction = async ({
  button,
  userId,
  endpoint,
  method = 'POST',
  body,
  busyLabel = 'Saving...',
  successMessage = 'Owner action completed.',
  confirmConfig = null,
}) => {
  const selectedUser = getSelectedOwnerUserOrThrow();
  const targetUserId = safeText(userId || selectedUser.userId);
  if (!targetUserId) {
    throw new Error('Select a user from the owner list first.');
  }

  if (confirmConfig) {
    const result = await openDecisionModal(confirmConfig);
    if (!result) {
      return null;
    }
  }

  setButtonBusy(button, true, busyLabel);
  try {
    const result = await apiRequest(endpoint(targetUserId), {
      method,
      body,
    });

    if (result.deletedOwnAccount) {
      handleUnauthenticatedState({
        message: result.message || 'Your account was deleted.',
      });
      return result;
    }

    if (result.forceRelogin && targetUserId === safeText(state.user?.userId || state.user?.continentalId)) {
      handleUnauthenticatedState({
        message: result.message || 'Your session is no longer valid. Please sign in again.',
      });
      return result;
    }

    showToast(result.message || successMessage, 'success');
    await refreshOwnerWorkspace(targetUserId);
    return result;
  } finally {
    setButtonBusy(button, false);
  }
};

const handleProfileSave = async (event) => {
  event.preventDefault();

  const username = safeText(dom.profileUsername?.value).toLowerCase();
  const displayName = safeText(dom.profileDisplayName?.value);
  const headline = safeText(dom.profileHeadline?.value);
  const email = safeText(dom.profileEmail?.value).toLowerCase();
  const avatar = normalizeAvatarInput(state.profileAvatarDraft || dom.profileAvatarUrl?.value);
  const avatarMeta = avatar ? normalizeAvatarMeta(state.profileAvatarMetaDraft, avatar) : createEmptyAvatarMeta();
  const website = normalizeWebsiteInput(dom.profileWebsite?.value);
  const currentEmail = safeText(state.user?.email).toLowerCase();
  const emailChanged = email !== currentEmail;
  const currentPassword = dom.profileEmailCurrentPassword?.value || '';

  if (!/^[a-z0-9](?:[a-z0-9._-]{1,28}[a-z0-9])?$/.test(username)) {
    showToast('Username must be 3-30 characters and can only use letters, numbers, dots, hyphens, or underscores.', 'error');
    return;
  }

  if (containsBlockedNameTerm(username)) {
    showToast('Choose a different username. Usernames cannot contain offensive or hateful language.', 'error');
    return;
  }

  if (displayName.length < 2) {
    showToast('Display name must be at least 2 characters.', 'error');
    return;
  }

  if (containsBlockedNameTerm(displayName)) {
    showToast('Choose a different display name. Display names cannot contain offensive or hateful language.', 'error');
    return;
  }

  if ((state.profileAvatarDraft || dom.profileAvatarUrl?.value) && avatar === null) {
    showToast('Avatar must be a direct image URL or an uploaded image.', 'error');
    return;
  }

  if (state.profileAvatarStatus?.state === 'validating') {
    showToast('Wait for avatar validation to finish before saving.', 'warn');
    return;
  }

  if (state.profileAvatarStatus?.state === 'error') {
    showToast(state.profileAvatarStatus.message || 'Avatar needs attention before saving.', 'error');
    return;
  }

  if (website === null) {
    showToast('Website URL is invalid.', 'error');
    return;
  }

  if (emailChanged && !currentPassword) {
    showToast('Current password is required to change your email.', 'error');
    return;
  }

  const emailChangeMfa = emailChanged ? await requestSensitiveActionMfa('change your email') : { mfaCode: '', backupCode: '' };
  if (emailChanged && !emailChangeMfa) {
    return;
  }

  setFormSaving(dom.profileForm);
  setButtonBusy(dom.profileSaveBtn, true, 'Saving...');

  try {
    const profilePayload = {
      username,
      displayName,
      headline,
      pronouns: '',
      role: '',
      organization: '',
      email,
      currentPassword,
      mfaCode: emailChangeMfa.mfaCode,
      backupCode: emailChangeMfa.backupCode,
      avatar: avatar || '',
      avatarMeta,
      location: safeText(dom.profileLocation?.value),
      website,
      timezone: '',
      language: '',
      currentFocus: '',
      focusAreas: [],
      bio: safeText(dom.profileBio?.value),
    };

    const profileResult = await apiRequest('/profile', {
      method: 'PATCH',
      body: profilePayload,
    });
    syncUiWithUser(normalizeUserPayload(profileResult));

    if (dom.profileEmailCurrentPassword) dom.profileEmailCurrentPassword.value = '';
    markFormClean(dom.profileForm, 'Saved just now');
    showToast(
      profileResult.message || 'Profile updated.',
      profileResult.verificationEmail?.sent === false ? 'warn' : 'success'
    );

    if (profileResult.forceRelogin) {
      clearStoredAuth();
      stopSessionAutoRefresh();
      setTimeout(() => setLoggedOutUI(), 450);
      return;
    }

    setSyncStatus(new Date());
  } catch (err) {
    setFormError(dom.profileForm);
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.profileSaveBtn, false);
  }
};

const handleResendVerification = async () => {
  if (!state.user || state.user.isVerified) {
    return;
  }

  setButtonBusy(dom.verificationResendBtn, true, 'Sending...');

  try {
    const result = await apiRequest('/resend-verification', {
      method: 'POST',
    });

    syncUiWithUser(normalizeUserPayload(result));
    showToast(
      result.message || 'Verification email sent.',
      result.verificationEmail?.sent ? 'success' : 'warn'
    );
    setSyncStatus(new Date());
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.verificationResendBtn, false);
  }
};

const handleLinkedSave = async (event) => {
  event.preventDefault();

  setFormSaving(dom.linkedForm);
  setButtonBusy(dom.linkedSaveBtn, true, 'Saving...');

  try {
    const data = await apiRequest('/linked', {
      method: 'PATCH',
      body: {
        google: safeText(dom.linkedGoogle?.value),
        facebook: safeText(dom.linkedFacebook?.value),
        github: safeText(dom.linkedGithub?.value),
        twitter: safeText(dom.linkedTwitter?.value),
        linkedin: safeText(dom.linkedLinkedin?.value),
        discord: safeText(dom.linkedDiscord?.value),
        apple: safeText(dom.linkedApple?.value),
        microsoft: safeText(dom.linkedMicrosoft?.value),
      },
    });

    syncUiWithUser(normalizeUserPayload(data));
    markFormClean(dom.linkedForm, 'Saved just now');
    showToast('External profiles updated.', 'success');
    setSyncStatus(new Date());
  } catch (err) {
    setFormError(dom.linkedForm);
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.linkedSaveBtn, false);
  }
};

const handleOauthLink = async (provider) => {
  const normalizedProvider = safeText(provider).toLowerCase();
  const providerLabel = getOauthProviderLabel(normalizedProvider);
  const elements = getOauthProviderElements(normalizedProvider);

  setButtonBusy(elements.connectBtn, true, `Opening ${providerLabel}...`);

  try {
    const data = await apiRequest(`/oauth/${encodeURIComponent(normalizedProvider)}/link-start`, {
      method: 'POST',
      body: {
        origin: window.location.origin,
        redirect: window.location.href,
        returnTo: window.location.href,
      },
    });

    const popup = openPopupWindow(data.url, 'IdentityProviderPopup');
    if (!popup) {
      window.location.assign(data.url);
      return;
    }

    popup.focus();
    showToast(`${providerLabel} authorization opened in a new window.`, 'success');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(elements.connectBtn, false);
    renderOauthProviders(state.user);
  }
};

const handleOauthUnlink = async (provider) => {
  const normalizedProvider = safeText(provider).toLowerCase();
  const providerLabel = getOauthProviderLabel(normalizedProvider);
  const elements = getOauthProviderElements(normalizedProvider);
  const decision = await openDecisionModal({
    title: `Unlink ${providerLabel}`,
    copy: `This disconnects ${providerLabel} from this Continental ID account.`,
    confirmLabel: `Unlink ${providerLabel}`,
    confirmClassName: 'danger-btn',
  });
  if (!decision) {
    return;
  }

  setButtonBusy(elements.unlinkBtn, true, 'Unlinking...');

  try {
    const data = await apiRequest(`/oauth/${encodeURIComponent(normalizedProvider)}`, {
      method: 'DELETE',
      body: {},
    });

    syncUiWithUser(normalizeUserPayload(data));
    showToast(data.message || `${providerLabel} unlinked.`, 'success');
    setSyncStatus(new Date());
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(elements.unlinkBtn, false);
    renderOauthProviders(state.user);
  }
};

const handlePasswordSave = async (event) => {
  event.preventDefault();

  const currentPassword = dom.currentPassword?.value || '';
  const newPassword = dom.newPassword?.value || '';
  const confirmPassword = dom.confirmPassword?.value || '';

  if (newPassword !== confirmPassword) {
    showToast('New password and confirmation do not match.', 'error');
    return;
  }

  const passwordChangeMfa = await requestSensitiveActionMfa('update your password');
  if (!passwordChangeMfa) {
    return;
  }

  setButtonBusy(dom.passwordSaveBtn, true, 'Updating...');

  try {
    const result = await apiRequest('/password', {
      method: 'PATCH',
      body: { currentPassword, newPassword, ...passwordChangeMfa },
    });

    if (dom.passwordForm) dom.passwordForm.reset();
    updatePasswordStrengthUi();
    showToast(result.message || 'Password updated.', 'success');

    if (result.forceRelogin) {
      clearStoredAuth();
      stopSessionAutoRefresh();
      setTimeout(() => setLoggedOutUI(), 450);
    }
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.passwordSaveBtn, false);
  }
};

const handleSecuritySave = async (event) => {
  event.preventDefault();

  setFormSaving(dom.securityForm);
  setButtonBusy(dom.securitySaveBtn, true, 'Saving...');

  try {
    const data = await apiRequest('/security', {
      method: 'PATCH',
      body: {
        loginAlerts: Boolean(dom.loginAlertsToggle?.checked),
      },
    });

    syncUiWithUser(normalizeUserPayload(data));
    markFormClean(dom.securityForm, 'Saved just now');
    showToast('Security settings updated.', 'success');
    setSyncStatus(new Date());
  } catch (err) {
    setFormError(dom.securityForm);
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.securitySaveBtn, false);
  }
};

const handlePasskeyRegister = async () => {
  if (!window.WebAuthnJson?.isSupported?.()) {
    showToast('This browser does not support passkeys.', 'error');
    return;
  }

  const currentPassword = dom.passkeyCurrentPassword?.value || '';
  if (!currentPassword) {
    showToast('Enter your current password before adding a passkey.', 'error');
    dom.passkeyCurrentPassword?.focus();
    return;
  }

  const passkeyRegistrationMfa = getPasskeyModalMfa();
  if (!passkeyRegistrationMfa) {
    return;
  }

  setButtonBusy(dom.passkeyRegisterBtn, true, 'Adding...');

  try {
    await ensureApiBaseUrl();
    const headers = {
      'Content-Type': 'application/json',
    };
    if (state.accessToken) {
      headers.Authorization = `Bearer ${state.accessToken}`;
    }

    const optionsResponse = await fetchWithTimeout(`${getAuthApiBase()}/passkeys/register/options`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({ currentPassword, ...passkeyRegistrationMfa }),
    });
    const optionsPayload = await parseResponseBody(optionsResponse);
    if (!optionsResponse.ok) {
      if (optionsResponse.status === 401) {
        handleUnauthenticatedState({ message: optionsPayload.message || 'Your session expired. Please sign in again.' });
      }
      throw new Error(optionsPayload.message || 'Failed to start passkey registration.');
    }

    const credential = await window.WebAuthnJson.create(optionsPayload.options);

    const verifyResponse = await fetchWithTimeout(`${getAuthApiBase()}/passkeys/register/verify`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({ credential }),
    });
    const verifyPayload = await parseResponseBody(verifyResponse);
    if (!verifyResponse.ok) {
      if (verifyResponse.status === 401) {
        handleUnauthenticatedState({ message: verifyPayload.message || 'Your session expired. Please sign in again.' });
      }
      throw new Error(verifyPayload.message || 'Failed to verify the new passkey.');
    }

    syncUiWithUser(normalizeUserPayload(verifyPayload));
    clearPasskeyInputs();
    showToast(verifyPayload.message || 'Passkey added.', 'success');
    setSyncStatus(new Date());
  } catch (error) {
    if (error?.name === 'NotAllowedError') {
      showToast('Passkey registration was cancelled or timed out.', 'warn');
      return;
    }
    showToast(error.message || 'Failed to add the passkey.', 'error');
  } finally {
    setButtonBusy(dom.passkeyRegisterBtn, false);
  }
};

const handleMfaSetup = async () => {
  const currentPassword = dom.mfaCurrentPassword?.value || '';
  if (!currentPassword) {
    showToast('Enter your current password to start MFA setup.', 'error');
    dom.mfaCurrentPassword?.focus();
    return;
  }

  setButtonBusy(dom.mfaStartSetupBtn, true, 'Preparing...');

  try {
    const data = await apiRequest('/mfa/setup', {
      method: 'POST',
      body: { currentPassword },
    });

    state.mfaSetup = data.setup || null;
    state.mfaSetupOpen = true;
    renderBackupCodes(data.setup?.backupCodes || []);
    renderMfaState(state.user);
    showToast('Authenticator setup ready. Scan the QR code to continue.', 'success');
    dom.mfaCode?.focus();
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.mfaStartSetupBtn, false);
  }
};

const handleMfaEnable = async () => {
  const currentPassword = dom.mfaCurrentPassword?.value || '';
  const code = safeText(dom.mfaCode?.value);
  if (!currentPassword) {
    showToast('Enter your current password to enable MFA.', 'error');
    dom.mfaCurrentPassword?.focus();
    return;
  }
  if (!code) {
    showToast('Enter the MFA code from your authenticator app.', 'error');
    dom.mfaCode?.focus();
    return;
  }

  setButtonBusy(dom.mfaEnableBtn, true, 'Enabling...');

  try {
    const data = await apiRequest('/mfa/enable', {
      method: 'POST',
      body: { currentPassword, code },
    });

    state.user = normalizeUserPayload(data);
    state.mfaSetup = null;
    state.mfaSetupOpen = false;
    if (dom.mfaCurrentPassword) dom.mfaCurrentPassword.value = '';
    if (dom.mfaCode) dom.mfaCode.value = '';
    renderBackupCodes([]);
    syncUiWithUser(state.user);
    state.mfaLastFocusedElement?.focus?.();
    state.mfaLastFocusedElement = null;
    showToast('MFA enabled.', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.mfaEnableBtn, false);
  }
};

const handleCopyMfaSecret = async () => {
  try {
    await copyTextToClipboard(state.mfaSetup?.secret);
    showToast('Setup key copied.', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
};

const handleCopyMfaOtpAuthUrl = async () => {
  try {
    await copyTextToClipboard(state.mfaSetup?.otpAuthUrl);
    showToast('OTPAuth URL copied.', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
};

const handleMfaManageConfirm = async () => {
  const actionMode = state.mfaManageMode;
  const config = getMfaManageConfig(actionMode);
  if (!config) return;

  const currentPassword = dom.mfaManageCurrentPassword?.value || '';
  if (!currentPassword) {
    showToast('Enter your current password to continue.', 'error');
    dom.mfaManageCurrentPassword?.focus();
    return;
  }

  const sensitiveMfa = parseSensitiveMfaInput(dom.mfaManageChallenge?.value || '');
  if (!sensitiveMfa.mfaCode && !sensitiveMfa.backupCode) {
    showToast('Enter a current authenticator code or backup code.', 'error');
    dom.mfaManageChallenge?.focus();
    return;
  }

  setButtonBusy(dom.mfaManageConfirmBtn, true, config.busyLabel);

  try {
    const data = await apiRequest(config.endpoint, {
      method: 'POST',
      body: { currentPassword, ...sensitiveMfa },
    });

    if (actionMode === 'disable') {
      state.user = normalizeUserPayload(data);
      state.mfaSetup = null;
      state.mfaSetupOpen = false;
      renderBackupCodes([]);
      syncUiWithUser(state.user);
    } else {
      if (!state.user) state.user = {};
      if (!state.user.security) state.user.security = {};
      state.user.security.mfa = normalizeMfaState(data.mfa || state.user.security.mfa);
      renderBackupCodes(data.backupCodes || []);
      renderMfaState(state.user);
    }

    closeMfaManagePanel();
    showToast(config.successMessage, 'success', actionMode === 'backup' ? 4200 : 3200);
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.mfaManageConfirmBtn, false);
  }
};

const openPublicProfileDirectory = () => {
  const url = new URL('profile.html', window.location.href);
  window.open(url.toString(), '_blank', 'noopener');
};

const buildPreferencesPayload = () => ({
  profilePublic: Boolean(dom.privacyPublic?.checked),
  searchable: Boolean(dom.privacySearchable?.checked),
  publicProfile: {
    headline: Boolean(dom.publicFieldHeadline?.checked),
    role: false,
    organization: false,
    bio: Boolean(dom.publicFieldBio?.checked),
    currentFocus: false,
    focusAreas: false,
    pronouns: false,
    location: Boolean(dom.publicFieldLocation?.checked),
    website: Boolean(dom.publicFieldWebsite?.checked),
    timezone: false,
    language: false,
    linkedAccounts: Boolean(dom.publicFieldLinked?.checked),
    memberSince: Boolean(dom.publicFieldMemberSince?.checked),
  },
  notifications: {
    email: Boolean(dom.notifyEmail?.checked),
    sms: Boolean(dom.notifySms?.checked),
    push: Boolean(dom.notifyPush?.checked),
    weeklyDigest: Boolean(dom.notifyWeeklyDigest?.checked),
    security: Boolean(dom.notifySecurity?.checked),
  },
  appearance: {
    theme: safeText(dom.appearanceTheme?.value || 'graphite'),
    compactMode: Boolean(dom.appearanceCompactMode?.checked),
    reducedMotion: Boolean(dom.appearanceReducedMotion?.checked),
    highContrast: Boolean(dom.appearanceHighContrast?.checked),
    dashboardDensity: safeText(dom.appearanceDensity?.value || 'comfortable'),
  },
});

const savePreferences = async (button, successMessage = 'Preferences saved.') => {
  const allPreferenceForms = [dom.privacyForm, dom.notificationForm, dom.appearanceForm].filter(Boolean);
  const dirtyPreferenceForms = allPreferenceForms.filter((form) => form?.dataset.dirty === 'true');
  const relatedForm = button === dom.privacySaveBtn
    ? dom.privacyForm
    : button === dom.notificationSaveBtn
      ? dom.notificationForm
      : dom.appearanceForm;
  const formsToSave = dirtyPreferenceForms.length ? dirtyPreferenceForms : [relatedForm].filter(Boolean);
  for (const form of formsToSave) {
    setFormSaving(form);
  }
  setButtonBusy(button, true, 'Saving...');

  try {
    const data = await apiRequest('/preferences', {
      method: 'PATCH',
      body: buildPreferencesPayload(),
    });

    syncUiWithUser(normalizeUserPayload(data));
    setDashboardTipsEnabled(Boolean(dom.dashboardTipsToggle?.checked));
    for (const form of formsToSave) {
      markFormClean(form, 'Saved just now');
    }
    showToast(successMessage, 'success');
    setSyncStatus(new Date());
  } catch (err) {
    for (const form of formsToSave) {
      setFormError(form);
    }
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(button, false);
  }
};

const setDashboardTipsEnabled = (enabled) => {
  localStorage.setItem('dashboardTipsEnabled', enabled ? 'true' : 'false');
  renderProfileChecklist(state.user);
};

const handleAppearanceReset = async () => {
  if (dom.appearanceTheme) dom.appearanceTheme.value = 'graphite';
  if (dom.appearanceDensity) dom.appearanceDensity.value = 'comfortable';
  if (dom.appearanceCompactMode) dom.appearanceCompactMode.checked = false;
  if (dom.appearanceReducedMotion) dom.appearanceReducedMotion.checked = false;
  if (dom.appearanceHighContrast) dom.appearanceHighContrast.checked = false;
  if (dom.dashboardTipsToggle) dom.dashboardTipsToggle.checked = true;

  await savePreferences(dom.appearanceResetBtn, 'Appearance reset to defaults.');
};

const handleDeleteAccount = async (event) => {
  event.preventDefault();

  const currentPassword = dom.deletePassword?.value || '';
  const confirmText = safeText(dom.deleteConfirmText?.value).toUpperCase();

  if (confirmText !== 'DELETE') {
    showToast('Type DELETE exactly to confirm account removal.', 'error');
    return;
  }

  let deleteAccountMfa = { mfaCode: '', backupCode: '' };
  if (requiresSensitiveActionMfa()) {
    deleteAccountMfa = parseSensitiveMfaInput(dom.deleteChallenge?.value || '');
    if (!deleteAccountMfa.mfaCode && !deleteAccountMfa.backupCode) {
      showToast('Enter a current authenticator code or backup code.', 'error');
      dom.deleteChallenge?.focus();
      return;
    }
  }

  setButtonBusy(dom.deleteAccountBtn, true, 'Deleting...');

  try {
    await apiRequest('/account', {
      method: 'DELETE',
      body: { currentPassword, confirmText: 'DELETE', ...deleteAccountMfa },
    });

    if (dom.deleteForm) dom.deleteForm.reset();
    clearStoredAuth();
    stopSessionAutoRefresh();
    setLoggedOutUI();
    showToast('Account deleted.', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.deleteAccountBtn, false);
  }
};

const renderAvatarDraft = () => {
  renderAvatarPreviews(state.user);
  renderPublicProfilePreview(state.user);
};

const syncProfileAvatarDraft = (value, options = {}) => {
  const normalizedValue = safeText(value);
  clearAvatarValidationTimer();
  const nextMeta = normalizedValue
    ? normalizeAvatarMeta(options.meta, normalizedValue)
    : createEmptyAvatarMeta();

  state.profileAvatarDraft = normalizedValue;
  state.profileAvatarMetaDraft = nextMeta;
  state.profileAvatarValidationId += 1;

  if (!normalizedValue) {
    setAvatarDraftStatus('empty');
    renderAvatarDraft();
    return;
  }

  const normalizedAvatar = normalizeAvatarInput(normalizedValue);
  if (!normalizedAvatar) {
    setAvatarDraftStatus(
      'error',
      'Avatar format is invalid.',
      'Use an uploaded image or a direct HTTP/HTTPS image URL.'
    );
    renderAvatarDraft();
    return;
  }

  if (String(normalizedAvatar).startsWith('data:image/')) {
    const meta = normalizeAvatarMeta(
      {
        ...nextMeta,
        kind: 'upload',
        mimeType: nextMeta.mimeType || normalizedAvatar.slice(5, normalizedAvatar.indexOf(';')),
        updatedAt: nextMeta.updatedAt || new Date().toISOString(),
      },
      normalizedAvatar
    );
    state.profileAvatarDraft = normalizedAvatar;
    state.profileAvatarMetaDraft = meta;
    const dimensions = formatAvatarDimensions(meta.width, meta.height) || '256 x 256';
    setAvatarDraftStatus(
      'ready',
      'Uploaded avatar is ready to save.',
      `${dimensions}. Center-cropped and optimized for stable rendering.`
    );
    renderAvatarDraft();
    return;
  }

  state.profileAvatarDraft = normalizedAvatar;
  state.profileAvatarMetaDraft = normalizeAvatarMeta(
    {
      ...nextMeta,
      kind: 'url',
      mimeType: nextMeta.mimeType || guessAvatarMimeTypeFromUrl(normalizedAvatar),
    },
    normalizedAvatar
  );

  const validationId = state.profileAvatarValidationId;
  setAvatarDraftStatus(
    'validating',
    'Checking the remote avatar URL.',
    'The browser is loading the image now so broken URLs get caught before save.'
  );
  renderAvatarDraft();

  state.profileAvatarValidationTimer = window.setTimeout(() => {
    state.profileAvatarValidationTimer = null;

    loadImageSource(normalizedAvatar, { timeoutMs: AVATAR_URL_VALIDATION_TIMEOUT_MS })
      .then(({ width, height }) => {
        if (validationId !== state.profileAvatarValidationId) {
          return;
        }
        if (Math.max(width, height) > AVATAR_REMOTE_MAX_DIMENSION) {
          setAvatarDraftStatus(
            'error',
            'The remote avatar is too large to trust as a profile picture.',
            `Use an image under ${AVATAR_REMOTE_MAX_DIMENSION}px on its longest side, or upload the file so it can be optimized locally.`
          );
          renderAvatarDraft();
          return;
        }

        const meta = normalizeAvatarMeta(
          {
            ...state.profileAvatarMetaDraft,
            kind: 'url',
            mimeType: state.profileAvatarMetaDraft.mimeType || guessAvatarMimeTypeFromUrl(normalizedAvatar),
            width,
            height,
            updatedAt: new Date().toISOString(),
          },
          normalizedAvatar
        );
        state.profileAvatarMetaDraft = meta;
        const details = [
          formatAvatarDimensions(width, height),
          meta.mimeType ? meta.mimeType.replace('image/', '').toUpperCase() : '',
        ].filter(Boolean);
        setAvatarDraftStatus(
          'ready',
          'Remote avatar is reachable and ready to save.',
          details.length
            ? `${details.join(' | ')}. Fallback initials stay in place if the source fails later.`
            : 'Fallback initials stay in place if the source fails later.'
        );
        renderAvatarDraft();
      })
      .catch((error) => {
        if (validationId !== state.profileAvatarValidationId) {
          return;
        }
        setAvatarDraftStatus(
          'error',
          'The remote avatar could not be loaded.',
          error.message || 'Use a different image URL or upload the file directly.'
        );
        renderAvatarDraft();
      });
  }, 260);
};

const handleProfileAvatarUrlInput = () => {
  syncProfileAvatarDraft(dom.profileAvatarUrl?.value || '', {
    meta: {
      kind: 'url',
    },
  });
};

const applyAvatarFileToDraft = async (file, successMessage = 'Avatar image ready to save.') => {
  const { dataUrl, meta } = await compressAvatarFile(file);
  state.profileAvatarDraft = dataUrl;
  state.profileAvatarMetaDraft = meta;
  state.profileAvatarValidationId += 1;
  if (dom.profileAvatarUpload) {
    dom.profileAvatarUpload.value = '';
  }
  if (dom.profileAvatarUrl) {
    dom.profileAvatarUrl.value = '';
  }
  setAvatarDraftStatus(
    'ready',
    'Uploaded avatar is ready to save.',
    `${formatAvatarDimensions(meta.width, meta.height) || '256 x 256'}. Center-cropped and optimized for consistent profile rendering.`
  );
  renderAvatarDraft();
  markFormDirty(dom.profileForm);
  showToast(successMessage, 'success');
};

const handleProfileAvatarUpload = async (event) => {
  const file = event.target?.files?.[0];
  if (!file) return;

  try {
    await applyAvatarFileToDraft(file);
  } catch (err) {
    if (dom.profileAvatarUpload) {
      dom.profileAvatarUpload.value = '';
    }
    setAvatarDraftStatus('error', 'Avatar upload failed.', err.message || 'Choose a different image.');
    showToast(err.message, 'error');
  }
};

const handleProfileAvatarPaste = async (event) => {
  const files = Array.from(event.clipboardData?.files || []).filter((file) => AVATAR_ALLOWED_MIME_TYPES.has(file.type));
  if (files[0]) {
    event.preventDefault();
    try {
      await applyAvatarFileToDraft(files[0], 'Avatar pasted and ready to save.');
    } catch (err) {
      setAvatarDraftStatus('error', 'Avatar paste failed.', err.message || 'Choose a different image.');
      showToast(err.message, 'error');
    }
    return;
  }

  const pastedText = safeText(event.clipboardData?.getData('text/plain') || '');
  if (pastedText && !dom.profileAvatarUrl?.matches(':focus')) {
    if (dom.profileAvatarUrl) {
      dom.profileAvatarUrl.value = pastedText;
    }
    handleProfileAvatarUrlInput();
    markFormDirty(dom.profileForm);
  }
};

const handleProfileAvatarDragState = (active) => {
  if (!dom.profileAvatarCard) return;
  dom.profileAvatarCard.classList.toggle('drag-active', active);
};

const handleProfileAvatarDragOver = (event) => {
  event.preventDefault();
  handleProfileAvatarDragState(true);
};

const handleProfileAvatarDragLeave = (event) => {
  if (!dom.profileAvatarCard?.contains(event.relatedTarget)) {
    handleProfileAvatarDragState(false);
  }
};

const handleProfileAvatarDrop = async (event) => {
  event.preventDefault();
  handleProfileAvatarDragState(false);

  const files = Array.from(event.dataTransfer?.files || []).filter((file) => AVATAR_ALLOWED_MIME_TYPES.has(file.type));
  if (files[0]) {
    try {
      await applyAvatarFileToDraft(files[0], 'Avatar dropped and ready to save.');
    } catch (err) {
      setAvatarDraftStatus('error', 'Avatar drop failed.', err.message || 'Choose a different image.');
      showToast(err.message, 'error');
    }
    return;
  }

  const droppedUrl = safeText(
    event.dataTransfer?.getData('text/uri-list') || event.dataTransfer?.getData('text/plain') || ''
  );
  if (droppedUrl) {
    if (dom.profileAvatarUrl) {
      dom.profileAvatarUrl.value = droppedUrl;
    }
    handleProfileAvatarUrlInput();
    markFormDirty(dom.profileForm);
  }
};

const handleProfileAvatarRemove = () => {
  clearAvatarValidationTimer();
  state.profileAvatarDraft = '';
  state.profileAvatarMetaDraft = createEmptyAvatarMeta();
  state.profileAvatarValidationId += 1;
  if (dom.profileAvatarUrl) {
    dom.profileAvatarUrl.value = '';
  }
  if (dom.profileAvatarUpload) {
    dom.profileAvatarUpload.value = '';
  }
  setAvatarDraftStatus('empty');
  renderAvatarDraft();
  markFormDirty(dom.profileForm);
};

const runManualRefresh = async () => {
  setButtonBusy(dom.refreshDataBtn, true, 'Refreshing...');

  try {
    await loadDashboardData({ silent: true });
    showToast('Dashboard data refreshed.', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.refreshDataBtn, false);
  }
};

const getAvailableTabButtons = () => dom.tabButtons.filter((button) => !button.hidden);

const getKnownTabIds = () =>
  new Set(getAvailableTabButtons().map((button) => safeText(button.dataset.tab)).filter(Boolean));

const normalizeTabId = (tabId) => {
  const normalized = safeText(tabId);
  return getKnownTabIds().has(normalized) ? normalized : 'overview';
};

const getTabUrl = (tabId) => {
  const url = new URL(window.location.href);
  if (tabId === 'overview') {
    url.searchParams.delete('tab');
  } else {
    url.searchParams.set('tab', tabId);
  }
  return url;
};

const getTabFromUrl = () => normalizeTabId(new URL(window.location.href).searchParams.get('tab'));

const switchTab = (tabId, options = {}) => {
  const { historyMode = 'push', focusPanel = false } = options;
  const nextTabId = normalizeTabId(tabId);

  if (state.activeTab === nextTabId && historyMode === 'push') {
    return;
  }

  state.activeTab = nextTabId;

  for (const btn of dom.tabButtons) {
    const active = btn.dataset.tab === nextTabId;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-selected', active ? 'true' : 'false');
    btn.tabIndex = active ? 0 : -1;
  }

  for (const panel of dom.tabContents) {
    const active = panel.id === nextTabId;
    panel.classList.toggle('active', active);
    panel.hidden = !active;
    if (active && focusPanel) {
      panel.tabIndex = -1;
      window.setTimeout(() => panel.focus({ preventScroll: true }), 40);
    }
  }

  requestCollapsibleSectionsSync();

  localStorage.setItem(ACTIVE_TAB_STORAGE_KEY, nextTabId);

  if (historyMode !== 'none') {
    const url = getTabUrl(nextTabId);
    if (historyMode === 'replace') {
      window.history.replaceState({ tabId: nextTabId }, '', url);
    } else {
      window.history.pushState({ tabId: nextTabId }, '', url);
    }
  }
};

const setupTabs = () => {
  for (const button of dom.tabButtons) {
    button.addEventListener('click', () => {
      const tabId = safeText(button.dataset.tab);
      if (!tabId) return;
      switchTab(tabId, { historyMode: 'push' });
    });

    button.addEventListener('keydown', (event) => {
      const availableButtons = getAvailableTabButtons();
      const currentIndex = availableButtons.indexOf(button);
      if (currentIndex === -1) return;

      let nextIndex = currentIndex;
      if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
        nextIndex = (currentIndex + 1) % availableButtons.length;
      } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
        nextIndex = (currentIndex - 1 + availableButtons.length) % availableButtons.length;
      } else if (event.key === 'Home') {
        nextIndex = 0;
      } else if (event.key === 'End') {
        nextIndex = availableButtons.length - 1;
      } else {
        return;
      }

      event.preventDefault();
      const nextButton = availableButtons[nextIndex];
      nextButton?.focus();
      if (nextButton?.dataset?.tab) {
        switchTab(nextButton.dataset.tab, { historyMode: 'push', focusPanel: true });
      }
    });
  }

  window.addEventListener('popstate', () => {
    switchTab(getTabFromUrl(), { historyMode: 'none' });
  });

  const url = new URL(window.location.href);
  const urlTab = normalizeTabId(url.searchParams.get('tab'));
  const savedTab = normalizeTabId(localStorage.getItem(ACTIVE_TAB_STORAGE_KEY));
  const initialTab = url.searchParams.has('tab') ? urlTab : savedTab || 'overview';
  switchTab(initialTab, { historyMode: 'replace' });
};

const setupSectionNavButtons = () => {
  for (const button of dom.sectionNavButtons) {
    button.addEventListener('click', () => {
      const tabTarget = safeText(button.dataset.tabTarget);
      const scrollTarget = safeText(button.dataset.scrollTarget);

      if (tabTarget) {
        switchTab(tabTarget, { historyMode: 'push', focusPanel: true });
        return;
      }

      if (scrollTarget) {
        scrollToSection(scrollTarget);
      }
    });
  }
};

const setupServiceFiltering = () => {
  if (dom.serviceFilter) {
    dom.serviceFilter.addEventListener('input', () => {
      renderServices();
    });
  }

  if (dom.favoriteFilterBtn) {
    dom.favoriteFilterBtn.addEventListener('click', () => {
      state.favoriteServicesOnly = !state.favoriteServicesOnly;
      persistServicePreferences();
      renderServices();
    });
  }

  for (const card of dom.serviceCards) {
    const pinButton = card.querySelector('.service-pin-btn');
    const serviceLink = card.querySelector('.service-link');
    if (!pinButton) continue;

    pinButton.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();

      const key = safeText(card.dataset.key).toLowerCase();
      if (!key) return;

      if (state.favoriteServices.has(key)) {
        state.favoriteServices.delete(key);
      } else {
        state.favoriteServices.add(key);
      }

      persistServicePreferences();
      renderServices();
    });

    if (serviceLink) {
      serviceLink.addEventListener('click', () => {
        const key = safeText(card.dataset.key).toLowerCase();
        trackServiceLaunch(key);
      });
    }
  }

  renderServices();
};

const isEditableTarget = (target) => {
  if (!target) return false;
  const tag = target.tagName ? target.tagName.toLowerCase() : '';
  return tag === 'input' || tag === 'textarea' || tag === 'select' || target.isContentEditable;
};

const setupKeyboardShortcuts = () => {
  window.addEventListener('keydown', (event) => {
    const isModifier = event.metaKey || event.ctrlKey;
    const key = safeText(event.key).toLowerCase();

    if (isDecisionModalOpen() && key === 'escape') {
      event.preventDefault();
      closeDecisionModal(null);
      return;
    }

    if (isDeleteModalOpen() && key === 'escape') {
      event.preventDefault();
      closeDeleteModal();
      return;
    }

    if (isPasskeyModalOpen() && key === 'escape') {
      event.preventDefault();
      closePasskeyModal();
      return;
    }

    if (isMfaModalOpen() && key === 'escape') {
      event.preventDefault();
      if (state.mfaManageMode) {
        closeMfaManagePanel();
      } else {
        closeMfaSetupPanel();
      }
      return;
    }

    if (isDecisionModalOpen() || isDeleteModalOpen() || isPasskeyModalOpen() || isMfaModalOpen()) {
      return;
    }

    if (state.launcherOpen && key === 'escape') {
      event.preventDefault();
      closeLauncher();
      return;
    }

    if (isModifier && key === 'k') {
      event.preventDefault();
      openLauncher();
      return;
    }

    if (isModifier && event.shiftKey && key === 'r') {
      event.preventDefault();
      runManualRefresh();
      return;
    }

    if (!isEditableTarget(event.target) && event.altKey && /^[1-9]$/.test(key)) {
      event.preventDefault();
      const tabIndex = Number(key) - 1;
      const tabButton = getAvailableTabButtons()[tabIndex];
      if (!tabButton?.dataset?.tab) return;
      switchTab(tabButton.dataset.tab);
      return;
    }

    if (!isEditableTarget(event.target) && key === '/') {
      event.preventDefault();
      dom.activityFilter?.focus();
      return;
    }

    if (!isEditableTarget(event.target) && key === '?') {
      event.preventDefault();
      showToast('Shortcuts: Cmd/Ctrl+K launcher, Cmd/Ctrl+Shift+R refresh, Alt+1..6 switch tabs.', 'warn', 5000);
    }
  });
};

const setupEventHandlers = () => {
  setupTabs();
  setupSectionNavButtons();
  setupCollapsibleSections();
  setupServiceFiltering();
  setupUnsavedChangeTracking();
  setupKeyboardShortcuts();

  if (dom.loadingSignInBtn) {
    dom.loadingSignInBtn.addEventListener('click', () => {
      if (state.landingPrimaryAction === 'retry') {
        retryLandingConnection();
        return;
      }

      promptSignIn();
    });
  }

  if (dom.logoutBtn) dom.logoutBtn.addEventListener('click', doLogout);
  if (dom.refreshDataBtn) dom.refreshDataBtn.addEventListener('click', runManualRefresh);
  if (dom.openLauncherBtn) dom.openLauncherBtn.addEventListener('click', openLauncher);
  if (dom.serviceLauncherBtn) dom.serviceLauncherBtn.addEventListener('click', openLauncher);
  if (dom.jumpUnsavedBtn) dom.jumpUnsavedBtn.addEventListener('click', jumpToFirstDirtyForm);
  if (dom.saveReminderJumpBtn) dom.saveReminderJumpBtn.addEventListener('click', jumpToFirstDirtyForm);
  if (dom.launcherCloseBtn) dom.launcherCloseBtn.addEventListener('click', closeLauncher);
  if (dom.launcherOverlay) dom.launcherOverlay.addEventListener('click', closeLauncher);
  if (dom.mfaCloseBtn) {
    dom.mfaCloseBtn.addEventListener('click', () => {
      if (state.mfaManageMode) {
        closeMfaManagePanel();
      } else {
        closeMfaSetupPanel();
      }
    });
  }
  if (dom.mfaOverlay) {
    dom.mfaOverlay.addEventListener('click', () => {
      if (state.mfaManageMode) {
        closeMfaManagePanel();
      } else {
        closeMfaSetupPanel();
      }
    });
  }
  if (dom.passkeyManageBtn) dom.passkeyManageBtn.addEventListener('click', openPasskeyModal);
  if (dom.passkeyCloseBtn) dom.passkeyCloseBtn.addEventListener('click', closePasskeyModal);
  if (dom.passkeyOverlay) dom.passkeyOverlay.addEventListener('click', closePasskeyModal);
  if (dom.decisionForm) {
    dom.decisionForm.addEventListener('submit', (event) => {
      event.preventDefault();
      submitDecisionModal();
    });
  }
  if (dom.decisionCancelBtn) dom.decisionCancelBtn.addEventListener('click', () => closeDecisionModal(null));
  if (dom.decisionDismissBtn) dom.decisionDismissBtn.addEventListener('click', () => closeDecisionModal(null));
  if (dom.decisionOverlay) dom.decisionOverlay.addEventListener('click', () => closeDecisionModal(null));
  if (dom.deleteOpenBtn) dom.deleteOpenBtn.addEventListener('click', openDeleteModal);
  if (dom.deleteCloseBtn) dom.deleteCloseBtn.addEventListener('click', closeDeleteModal);
  if (dom.deleteCancelBtn) dom.deleteCancelBtn.addEventListener('click', closeDeleteModal);
  if (dom.deleteOverlay) dom.deleteOverlay.addEventListener('click', closeDeleteModal);
  if (dom.launcherSearch) {
    dom.launcherSearch.addEventListener('input', renderLauncher);
    dom.launcherSearch.addEventListener('keydown', (event) => {
      const items = Array.from(dom.launcherList?.querySelectorAll('.launcher-item') || []);
      if (!items.length) {
        if (event.key === 'Escape') closeLauncher();
        return;
      }

      if (event.key === 'ArrowDown') {
        event.preventDefault();
        setLauncherActiveIndex(state.launcherActiveIndex + 1);
        return;
      }

      if (event.key === 'ArrowUp') {
        event.preventDefault();
        setLauncherActiveIndex(state.launcherActiveIndex - 1);
        return;
      }

      if (event.key === 'Enter') {
        event.preventDefault();
        items[state.launcherActiveIndex]?.click();
        return;
      }

      if (event.key === 'Escape') {
        event.preventDefault();
        closeLauncher();
      }
    });
  }

  if (dom.headerExportJsonBtn) {
    dom.headerExportJsonBtn.addEventListener('click', async () => {
      setButtonBusy(dom.headerExportJsonBtn, true, 'Exporting...');
      try {
        await exportAccountJson();
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(dom.headerExportJsonBtn, false);
      }
    });
  }

  if (dom.overviewJumpProfileBtn) {
    dom.overviewJumpProfileBtn.addEventListener('click', () => {
      switchTab('profile');
      dom.profileUsername?.focus();
    });
  }

  if (dom.overviewJumpSecurityBtn) {
    dom.overviewJumpSecurityBtn.addEventListener('click', () => {
      switchTab('security');
      dom.currentPassword?.focus();
    });
  }

  if (dom.overviewJumpActivityBtn) {
    dom.overviewJumpActivityBtn.addEventListener('click', () => {
      switchTab('activity');
      dom.activityFilter?.focus();
    });
  }

  if (dom.profileAvatarUploadBtn && dom.profileAvatarUpload) {
    dom.profileAvatarUploadBtn.addEventListener('click', () => {
      dom.profileAvatarUpload.click();
    });
    dom.profileAvatarUpload.addEventListener('change', handleProfileAvatarUpload);
  }

  if (dom.profileAvatarUrl) {
    dom.profileAvatarUrl.addEventListener('input', handleProfileAvatarUrlInput);
    dom.profileAvatarUrl.addEventListener('change', handleProfileAvatarUrlInput);
  }

  if (dom.profileAvatarCard) {
    dom.profileAvatarCard.addEventListener('paste', handleProfileAvatarPaste);
    dom.profileAvatarCard.addEventListener('dragenter', handleProfileAvatarDragOver);
    dom.profileAvatarCard.addEventListener('dragover', handleProfileAvatarDragOver);
    dom.profileAvatarCard.addEventListener('dragleave', handleProfileAvatarDragLeave);
    dom.profileAvatarCard.addEventListener('drop', handleProfileAvatarDrop);
  }

  if (dom.profileAvatarRemoveBtn) {
    dom.profileAvatarRemoveBtn.addEventListener('click', handleProfileAvatarRemove);
  }

  if (dom.profileUsername) {
    dom.profileUsername.addEventListener('input', refreshDraftPublicProfileUi);
  }

  if (dom.profileForm) {
    dom.profileForm.addEventListener('input', refreshDraftPublicProfileUi);
    dom.profileForm.addEventListener('change', refreshDraftPublicProfileUi);
  }

  if (dom.profileForm) dom.profileForm.addEventListener('submit', handleProfileSave);
  if (dom.copyPublicProfileLinkBtn) {
    dom.copyPublicProfileLinkBtn.addEventListener('click', handleCopyPublicProfileLink);
  }
  if (dom.openPublicProfileBtn) {
    dom.openPublicProfileBtn.addEventListener('click', () => {
      const url = getPublicProfileUrl(state.user?.username);
      if (!url || !state.user?.preferences?.profilePublic) return;
      window.open(url, '_blank', 'noopener');
    });
  }
  if (dom.verificationResendBtn) {
    dom.verificationResendBtn.addEventListener('click', handleResendVerification);
  }
  if (dom.linkedForm) {
    dom.linkedForm.addEventListener('submit', handleLinkedSave);
    dom.linkedForm.addEventListener('input', () => renderPublicProfilePreview(state.user));
    dom.linkedForm.addEventListener('change', () => renderPublicProfilePreview(state.user));
  }
  for (const provider of OAUTH_PROVIDERS) {
    const elements = getOauthProviderElements(provider);
    if (elements.connectBtn) {
      elements.connectBtn.addEventListener('click', () => handleOauthLink(provider));
    }
    if (elements.unlinkBtn) {
      elements.unlinkBtn.addEventListener('click', () => handleOauthUnlink(provider));
    }
  }
  if (dom.passwordForm) dom.passwordForm.addEventListener('submit', handlePasswordSave);
  if (dom.securityForm) dom.securityForm.addEventListener('submit', handleSecuritySave);
  if (dom.mfaCurrentPassword) {
    dom.mfaCurrentPassword.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      if (state.mfaSetup?.secret) {
        dom.mfaCode?.focus();
        return;
      }
      handleMfaSetup();
    });
  }
  if (dom.mfaSetupBtn) dom.mfaSetupBtn.addEventListener('click', openMfaSetupPanel);
  if (dom.mfaStartSetupBtn) dom.mfaStartSetupBtn.addEventListener('click', handleMfaSetup);
  if (dom.mfaCancelSetupBtn) dom.mfaCancelSetupBtn.addEventListener('click', closeMfaSetupPanel);
  if (dom.mfaCopySecretBtn) dom.mfaCopySecretBtn.addEventListener('click', handleCopyMfaSecret);
  if (dom.mfaCopyOtpAuthBtn) dom.mfaCopyOtpAuthBtn.addEventListener('click', handleCopyMfaOtpAuthUrl);
  if (dom.mfaCode) {
    dom.mfaCode.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      handleMfaEnable();
    });
  }
  if (dom.mfaEnableBtn) dom.mfaEnableBtn.addEventListener('click', handleMfaEnable);
  if (dom.mfaDisableBtn) dom.mfaDisableBtn.addEventListener('click', () => openMfaManagePanel('disable'));
  if (dom.mfaBackupBtn) dom.mfaBackupBtn.addEventListener('click', () => openMfaManagePanel('backup'));
  if (dom.mfaManageCurrentPassword) {
    dom.mfaManageCurrentPassword.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      if (!safeText(dom.mfaManageChallenge?.value)) {
        dom.mfaManageChallenge?.focus();
        return;
      }
      handleMfaManageConfirm();
    });
  }
  if (dom.mfaManageChallenge) {
    dom.mfaManageChallenge.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      handleMfaManageConfirm();
    });
  }
  if (dom.mfaManageConfirmBtn) dom.mfaManageConfirmBtn.addEventListener('click', handleMfaManageConfirm);
  if (dom.mfaManageCancelBtn) dom.mfaManageCancelBtn.addEventListener('click', closeMfaManagePanel);
  if (dom.passkeyCurrentPassword) {
    dom.passkeyCurrentPassword.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      if (requiresSensitiveActionMfa() && !safeText(dom.passkeyChallenge?.value)) {
        dom.passkeyChallenge?.focus();
        return;
      }
      handlePasskeyRegister();
    });
  }
  if (dom.passkeyChallenge) {
    dom.passkeyChallenge.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      handlePasskeyRegister();
    });
  }
  if (dom.passkeyRegisterBtn) dom.passkeyRegisterBtn.addEventListener('click', handlePasskeyRegister);
  if (dom.deletePassword) {
    dom.deletePassword.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      dom.deleteConfirmText?.focus();
    });
  }
  if (dom.deleteConfirmText) {
    dom.deleteConfirmText.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      if (requiresSensitiveActionMfa()) {
        dom.deleteChallenge?.focus();
        return;
      }
      if (dom.deleteForm) dom.deleteForm.requestSubmit();
    });
  }
  if (dom.deleteChallenge) {
    dom.deleteChallenge.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      if (dom.deleteForm) dom.deleteForm.requestSubmit();
    });
  }
  if (dom.publicProfilePreviewBtn) {
    dom.publicProfilePreviewBtn.addEventListener('click', () => {
      const draftState = getDraftPublicProfileState(state.user);
      if (draftState.hasPendingLinkChange || draftState.hasPendingVisibilityChange) {
        showToast('Save your latest public profile changes before previewing the live page.', 'warn');
        return;
      }

      const url = getPublicProfileUrl(state.user?.username);
      if (!url) {
        showToast('Set a username before previewing your public profile.', 'error');
        return;
      }
      if (!state.user?.preferences?.profilePublic) {
        showToast('Turn on public mode in Preferences before previewing the public page.', 'error');
        return;
      }
      window.open(url, '_blank', 'noopener');
    });
  }
  if (dom.publicProfileDirectoryBtn) {
    dom.publicProfileDirectoryBtn.addEventListener('click', openPublicProfileDirectory);
  }

  for (const input of [
    dom.privacyPublic,
    dom.privacySearchable,
    dom.publicFieldHeadline,
    dom.publicFieldBio,
    dom.publicFieldLocation,
    dom.publicFieldWebsite,
    dom.publicFieldLinked,
    dom.publicFieldMemberSince,
  ]) {
    if (!input) continue;
    input.addEventListener('change', refreshDraftPublicProfileUi);
  }

  if (dom.newPassword) {
    dom.newPassword.addEventListener('input', updatePasswordStrengthUi);
  }

  if (dom.privacyForm) {
    dom.privacyForm.addEventListener('submit', (event) => {
      event.preventDefault();
      savePreferences(dom.privacySaveBtn, 'Privacy settings saved.');
    });
  }

  if (dom.notificationForm) {
    dom.notificationForm.addEventListener('submit', (event) => {
      event.preventDefault();
      savePreferences(dom.notificationSaveBtn, 'Notification preferences saved.');
    });
  }

  if (dom.appearanceForm) {
    dom.appearanceForm.addEventListener('submit', (event) => {
      event.preventDefault();
      savePreferences(dom.appearanceSaveBtn, 'Appearance settings saved.');
    });
  }

  if (dom.appearanceResetBtn) {
    dom.appearanceResetBtn.addEventListener('click', () => {
      handleAppearanceReset();
    });
  }

  if (dom.activityRefreshBtn) {
    dom.activityRefreshBtn.addEventListener('click', async () => {
      setButtonBusy(dom.activityRefreshBtn, true, 'Refreshing...');
      try {
        await loadActivity();
        showToast('Activity refreshed.', 'success');
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(dom.activityRefreshBtn, false);
      }
    });
  }

  if (dom.activityExportBtn) dom.activityExportBtn.addEventListener('click', exportActivityCsv);
  if (dom.activityFilter) dom.activityFilter.addEventListener('input', renderActivity);
  if (dom.activityKind) dom.activityKind.addEventListener('change', renderActivity);

  if (dom.ownerFilterForm) {
    dom.ownerFilterForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setButtonBusy(dom.ownerApplyFiltersBtn, true, 'Loading...');
      try {
        await loadOwnerUsers({ preserveSelection: false });
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(dom.ownerApplyFiltersBtn, false);
      }
    });
  }

  if (dom.ownerRefreshBtn) {
    dom.ownerRefreshBtn.addEventListener('click', async () => {
      setButtonBusy(dom.ownerRefreshBtn, true, 'Refreshing...');
      try {
        await loadOwnerData({ preserveSelection: true });
        showToast('Owner workspace refreshed.', 'success');
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(dom.ownerRefreshBtn, false);
      }
    });
  }

  if (dom.ownerUserForm) {
    dom.ownerUserForm.addEventListener('submit', handleOwnerSave);
  }

  if (dom.ownerUserRevokeSessionsBtn) {
    dom.ownerUserRevokeSessionsBtn.addEventListener('click', async () => {
      try {
        const selectedUser = getSelectedOwnerUserOrThrow();
        await runOwnerUserAction({
          button: dom.ownerUserRevokeSessionsBtn,
          endpoint: (userId) => `/owner/users/${encodeURIComponent(userId)}/revoke-sessions`,
          busyLabel: 'Revoking...',
          successMessage: 'Sessions revoked.',
          confirmConfig: {
            title: 'Revoke all sessions',
            copy: `Type ${safeText(selectedUser.username || selectedUser.email)} to revoke every active session for this account.`,
            confirmLabel: 'Revoke Sessions',
            confirmClassName: 'danger-btn',
            fields: [
              {
                id: 'owner-confirm-revoke-sessions',
                name: 'confirmText',
                label: 'Confirm account handle or email',
                placeholder: safeText(selectedUser.username || selectedUser.email),
                required: true,
              },
            ],
            validate: (values) =>
              safeText(values.confirmText).toLowerCase() === safeText(selectedUser.username || selectedUser.email).toLowerCase()
                ? ''
                : 'Enter the selected account handle or email to confirm.',
          },
        });
      } catch (err) {
        showToast(err.message, 'error');
      }
    });
  }

  if (dom.ownerUserResetMfaBtn) {
    dom.ownerUserResetMfaBtn.addEventListener('click', async () => {
      try {
        await runOwnerUserAction({
          button: dom.ownerUserResetMfaBtn,
          endpoint: (userId) => `/owner/users/${encodeURIComponent(userId)}/reset-mfa`,
          busyLabel: 'Resetting...',
          successMessage: 'MFA reset.',
          confirmConfig: {
            title: 'Reset MFA',
            copy: 'Type RESET to clear every MFA secret and backup code for this account.',
            confirmLabel: 'Reset MFA',
            confirmClassName: 'danger-btn',
            fields: [
              {
                id: 'owner-confirm-reset-mfa',
                name: 'confirmText',
                label: 'Type RESET',
                placeholder: 'RESET',
                required: true,
              },
            ],
            validate: (values) => (safeText(values.confirmText).toUpperCase() === 'RESET' ? '' : 'Type RESET to continue.'),
          },
        });
      } catch (err) {
        showToast(err.message, 'error');
      }
    });
  }

  if (dom.ownerUserResendVerificationBtn) {
    dom.ownerUserResendVerificationBtn.addEventListener('click', async () => {
      try {
        await runOwnerUserAction({
          button: dom.ownerUserResendVerificationBtn,
          endpoint: (userId) => `/owner/users/${encodeURIComponent(userId)}/resend-verification`,
          busyLabel: 'Sending...',
          successMessage: 'Verification email sent.',
        });
      } catch (err) {
        showToast(err.message, 'error');
      }
    });
  }

  if (dom.ownerUserSendResetBtn) {
    dom.ownerUserSendResetBtn.addEventListener('click', async () => {
      try {
        await runOwnerUserAction({
          button: dom.ownerUserSendResetBtn,
          endpoint: (userId) => `/owner/users/${encodeURIComponent(userId)}/send-password-reset`,
          busyLabel: 'Sending...',
          successMessage: 'Password reset email sent.',
        });
      } catch (err) {
        showToast(err.message, 'error');
      }
    });
  }

  if (dom.ownerUserDeleteBtn) {
    dom.ownerUserDeleteBtn.addEventListener('click', async () => {
      try {
        const selectedUser = getSelectedOwnerUserOrThrow();
        await runOwnerUserAction({
          button: dom.ownerUserDeleteBtn,
          endpoint: (userId) => `/owner/users/${encodeURIComponent(userId)}`,
          method: 'DELETE',
          busyLabel: 'Deleting...',
          successMessage: 'Account deleted.',
          confirmConfig: {
            title: 'Delete account',
            copy: `Type DELETE to permanently remove ${safeText(selectedUser.email || selectedUser.username || selectedUser.userId)}.`,
            confirmLabel: 'Delete Account',
            confirmClassName: 'danger-btn',
            fields: [
              {
                id: 'owner-confirm-delete-account',
                name: 'confirmText',
                label: 'Type DELETE',
                placeholder: 'DELETE',
                required: true,
              },
            ],
            validate: (values) => (safeText(values.confirmText).toUpperCase() === 'DELETE' ? '' : 'Type DELETE to continue.'),
          },
        });
      } catch (err) {
        showToast(err.message, 'error');
      }
    });
  }

  if (dom.sessionsRefreshBtn) {
    dom.sessionsRefreshBtn.addEventListener('click', async () => {
      setButtonBusy(dom.sessionsRefreshBtn, true, 'Refreshing...');
      try {
        await loadSessions();
        showToast('Sessions refreshed.', 'success');
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(dom.sessionsRefreshBtn, false);
      }
    });
  }

  if (dom.devicesRefreshBtn) {
    dom.devicesRefreshBtn.addEventListener('click', async () => {
      setButtonBusy(dom.devicesRefreshBtn, true, 'Refreshing...');
      try {
        await loadDevices();
        showToast('Devices refreshed.', 'success');
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(dom.devicesRefreshBtn, false);
      }
    });
  }

  if (dom.sessionsRevokeOthersBtn) {
    dom.sessionsRevokeOthersBtn.addEventListener('click', async () => {
      const decision = await openDecisionModal({
        title: 'Revoke other sessions',
        copy: 'This signs out every other active session while keeping this device signed in.',
        confirmLabel: 'Revoke other sessions',
        confirmClassName: 'danger-btn',
      });
      if (!decision) return;

      setButtonBusy(dom.sessionsRevokeOthersBtn, true, 'Revoking...');
      try {
        const data = await apiRequest('/sessions', {
          method: 'DELETE',
          body: { exceptCurrent: true },
        });

        showToast(data.message || 'Other sessions revoked.', 'success');
        await Promise.all([loadSessions(), loadCurrentUser()]);
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(dom.sessionsRevokeOthersBtn, false);
      }
    });
  }

  if (dom.sessionsRevokeAllBtn) {
    dom.sessionsRevokeAllBtn.addEventListener('click', async () => {
      const decision = await openDecisionModal({
        title: 'Revoke all sessions',
        copy: 'This signs you out everywhere, including this device. You will need to sign in again.',
        confirmLabel: 'Revoke all sessions',
        confirmClassName: 'danger-btn',
      });
      if (!decision) return;

      setButtonBusy(dom.sessionsRevokeAllBtn, true, 'Revoking...');
      try {
        const data = await apiRequest('/sessions', {
          method: 'DELETE',
          body: { exceptCurrent: false },
        });

        showToast(data.message || 'Sessions revoked.', 'success');

        if (data.forceRelogin) {
          clearStoredAuth();
          stopSessionAutoRefresh();
          setLoggedOutUI();
          return;
        }

        await Promise.all([loadSessions(), loadCurrentUser()]);
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(dom.sessionsRevokeAllBtn, false);
      }
    });
  }

  if (dom.deleteForm) dom.deleteForm.addEventListener('submit', handleDeleteAccount);

  window.addEventListener('online', () => {
    setConnectionStatus();
    showToast('Connection restored.', 'success', 2200);
  });

  window.addEventListener('offline', () => {
    setConnectionStatus();
    showToast('You are offline. Some actions may fail.', 'warn', 2800);
  });

  window.addEventListener('beforeunload', (event) => {
    if (!hasUnsavedChanges()) return;
    event.preventDefault();
    event.returnValue = '';
  });

  window.addEventListener('message', async (event) => {
    if (!isTrustedLoginOrigin(event.origin)) return;
    const messageType = safeText(event.data?.type);
    if (!messageType) return;

    if (messageType === 'OAUTH_LINKED') {
      try {
        await Promise.all([loadCurrentUser(), loadLinkedAccounts()]);
        closeLoginPopup();
        showToast(`${getOauthProviderLabel(event.data?.provider)} linked successfully.`, 'success');
      } catch (err) {
        showToast(err.message || 'The identity provider was linked, but the dashboard could not refresh.', 'warn');
      }
      return;
    }

    if (messageType !== 'LOGIN_SUCCESS') return;

    const messageApiBase = normalizeApiBaseUrl(event.data?.apiBaseUrl);
    if (messageApiBase) {
      API_BASE_URL = messageApiBase;
      apiBaseValidated = true;
      rememberApiBaseUrl(messageApiBase);
    }

    try {
      storeSession(event.data || {});
      await loadDashboardData({ silent: true });
      closeLoginPopup();
      showApp();
      startSessionAutoRefresh();
      showToast('Signed in successfully.', 'success');
    } catch (err) {
      const refreshed = await refreshSession();
      if (!refreshed.ok) {
        showToast('Signed in, but the session could not be established.', 'error');
        return;
      }

      try {
        await loadDashboardData({ silent: true });
        closeLoginPopup();
        showApp();
        startSessionAutoRefresh();
        showToast('Signed in successfully.', 'success');
      } catch (retryError) {
        showToast(retryError.message || 'Could not load account data.', 'error');
      }
    }
  });

  const systemThemeMedia = window.matchMedia('(prefers-color-scheme: dark)');
  if (systemThemeMedia && typeof systemThemeMedia.addEventListener === 'function') {
    systemThemeMedia.addEventListener('change', () => {
      const selectedTheme = safeText(dom.appearanceTheme?.value || 'graphite').toLowerCase();
      if (selectedTheme === 'system') {
        applyAppearance({
          theme: 'graphite',
          compactMode: Boolean(dom.appearanceCompactMode?.checked),
          reducedMotion: Boolean(dom.appearanceReducedMotion?.checked),
          highContrast: Boolean(dom.appearanceHighContrast?.checked),
          dashboardDensity: safeText(dom.appearanceDensity?.value || 'comfortable'),
        });
      }
    });
  }
};

const startSessionAutoRefresh = () => {
  stopSessionAutoRefresh();

  state.refreshTimer = setInterval(async () => {
    const refreshed = await refreshSession();
    if (refreshed.ok) {
      return;
    }

    if (refreshed.reason === 'unauthenticated') {
      handleUnauthenticatedState({
        message: refreshed.message || 'Your session expired. Please sign in again.',
      });
      return;
    }

    if (!navigator.onLine || refreshed.reason === 'network' || refreshed.reason === 'timeout') {
      return;
    }

    if (!state.accessToken) {
      stopSessionAutoRefresh();
      return;
    }
  }, REFRESH_INTERVAL_MS);
};

window.addEventListener('load', async () => {
  setConnectionStatus();
  setSyncStatus(null);
  setupEventHandlers();
  updatePasswordStrengthUi();
  await bootstrapSession();
});

const express = require('express');
const auth = require('../middleware/authMiddleware');
const owner = require('../middleware/ownerMiddleware');
const ctrl = require('../controllers/authController');
const verifyEmailCtrl = require('../controllers/verifyEmailController');

const router = express.Router();

router.post('/register', ctrl.register);
router.post('/login', ctrl.login);
router.post('/logout', ctrl.logout);
router.post('/refresh_token', ctrl.refreshToken);
router.post('/bootstrap', ctrl.bootstrap);
router.post('/request-password-reset', ctrl.requestPasswordReset);
router.post('/resend-verification-public', ctrl.publicResendVerificationEmail);
router.post('/reset-password', ctrl.resetPassword);
router.get('/email-preview', ctrl.previewEmailIndex);
router.get('/email-preview/:type', ctrl.previewEmailHtml);
router.get('/verify-email', verifyEmailCtrl.verifyEmail);
router.get('/public-search', ctrl.searchPublicProfiles);
router.get('/public/:username', ctrl.getPublicProfile);
router.get('/oauth/:provider/start', ctrl.startOauthLogin);
router.get('/oauth/:provider/callback', ctrl.finishOauthCallback);
router.post('/passkeys/authenticate/options', ctrl.beginPasskeyAuthentication);
router.post('/passkeys/authenticate/verify', ctrl.finishPasskeyAuthentication);

router.get('/me', auth, ctrl.me);
router.get('/owner/summary', auth, owner, ctrl.getOwnerSummary);
router.get('/owner/users', auth, owner, ctrl.listOwnerUsers);
router.get('/owner/users/:userId', auth, owner, ctrl.getOwnerUser);
router.patch('/owner/users/:userId', auth, owner, ctrl.updateOwnerUser);
router.post('/owner/users/:userId/revoke-sessions', auth, owner, ctrl.revokeOwnerUserSessions);
router.post('/owner/users/:userId/reset-mfa', auth, owner, ctrl.resetOwnerUserMfa);
router.post('/owner/users/:userId/resend-verification', auth, owner, ctrl.resendOwnerUserVerification);
router.post('/owner/users/:userId/send-password-reset', auth, owner, ctrl.sendOwnerUserPasswordReset);
router.delete('/owner/users/:userId', auth, owner, ctrl.deleteOwnerUser);
router.post('/resend-verification', auth, ctrl.resendVerificationEmail);
router.patch('/profile', auth, ctrl.updateProfile);
router.patch('/email', auth, ctrl.updateEmail);
router.patch('/password', auth, ctrl.updatePassword);

router.get('/preferences', auth, ctrl.getPreferences);
router.patch('/preferences', auth, ctrl.updatePreferences);

router.get('/linked', auth, ctrl.getLinkedAccounts);
router.patch('/linked', auth, ctrl.updateLinkedAccounts);
router.post('/oauth/:provider/link-start', auth, ctrl.startOauthLink);
router.delete('/oauth/:provider', auth, ctrl.unlinkOauthProvider);

router.get('/activity', auth, ctrl.getActivity);

router.get('/security', auth, ctrl.getSecurity);
router.patch('/security', auth, ctrl.updateSecurity);
router.post('/mfa/setup', auth, ctrl.beginMfaSetup);
router.post('/mfa/enable', auth, ctrl.enableMfa);
router.post('/mfa/disable', auth, ctrl.disableMfa);
router.post('/mfa/regenerate-backup-codes', auth, ctrl.regenerateMfaBackupCodes);
router.post('/passkeys/register/options', auth, ctrl.beginPasskeyRegistration);
router.post('/passkeys/register/verify', auth, ctrl.finishPasskeyRegistration);
router.delete('/passkeys/:credentialId', auth, ctrl.deletePasskey);
router.get('/devices', auth, ctrl.getDevices);
router.patch('/devices/:fingerprint', auth, ctrl.updateDevice);
router.delete('/devices/:fingerprint', auth, ctrl.deleteDevice);
router.get('/sessions', auth, ctrl.getSessions);
router.delete('/sessions/:sessionId', auth, ctrl.revokeSession);
router.delete('/sessions', auth, ctrl.revokeAllSessions);
router.get('/export', auth, ctrl.exportAccountData);

router.delete('/account', auth, ctrl.deleteAccount);

module.exports = router;

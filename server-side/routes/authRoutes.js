
const express = require('express');
const passport = require('passport');
const authController = require('../controllers/authController');
const rateLimit = require('express-rate-limit');
const { ensureAuth } = require('../middleware/auth');

const router = express.Router();

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 10, 
    message: 'Too many login attempts, please try again later'
});

router.post('/register', authController.register);
router.post('/login', loginLimiter, authController.login);

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/' }), authController.googleLogin);

router.post('/enable-2fa', ensureAuth, authController.enableTwoFactor);
router.post('/verify-2fa', ensureAuth, authController.verifyTwoFactor);

router.post('/reset-password', authController.resetPassword);
router.post('/update-password', authController.updatePassword);

module.exports = router;

// src/routes/auth.routes.js
const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/auth.controller');
const { 
    authenticateToken, 
    validateRefreshToken, 
    rateLimiter,
    securityHeaders 
} = require('../middlewares/auth.middleware');

const router = express.Router();

// Apply security headers to all routes
router.use(securityHeaders);

// Validation rules
const loginValidation = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Please provide a valid email address'),
    body('password')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number')
];

const changePasswordValidation = [
    body('currentPassword')
        .notEmpty()
        .withMessage('Current password is required'),
    body('newPassword')
        .isLength({ min: 8 })
        .withMessage('New password must be at least 8 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
        .withMessage('New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
    body('confirmPassword')
        .custom((value, { req }) => {
            if (value !== req.body.newPassword) {
                throw new Error('Password confirmation does not match new password');
            }
            return true;
        })
];

// Routes

/**
 * @route   POST /api/auth/login
 * @desc    User login
 * @access  Public
 */
router.post('/login', 
    rateLimiter(5, 15 * 60 * 1000), // 5 attempts per 15 minutes
    loginValidation,
    authController.login
);

/**
 * @route   POST /api/auth/refresh
 * @desc    Refresh access token
 * @access  Public (requires refresh token)
 */
router.post('/refresh',
    rateLimiter(10, 15 * 60 * 1000), // 10 attempts per 15 minutes
    validateRefreshToken,
    authController.refreshToken
);

/**
 * @route   POST /api/auth/logout
 * @desc    User logout
 * @access  Private
 */
router.post('/logout',
    authenticateToken,
    authController.logout
);

/**
 * @route   POST /api/auth/logout-all
 * @desc    Logout from all devices
 * @access  Private
 */
router.post('/logout-all',
    authenticateToken,
    authController.logoutAll
);

/**
 * @route   GET /api/auth/profile
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/profile',
    authenticateToken,
    authController.getProfile
);

/**
 * @route   PUT /api/auth/change-password
 * @desc    Change user password
 * @access  Private
 */
router.put('/change-password',
    authenticateToken,
    rateLimiter(3, 60 * 60 * 1000), // 3 attempts per hour
    changePasswordValidation,
    authController.changePassword
);

/**
 * @route   GET /api/auth/validate
 * @desc    Validate access token
 * @access  Private
 */
router.get('/validate',
    authenticateToken,
    authController.validateToken
);

module.exports = router;
// src/controllers/auth.controller.js
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwtService = require('../services/jwt.service');
const redisConfig = require('../config/redis.config');
const { validationResult } = require('express-validator');
// Import your User model here
// const User = require('../models/user.model');

class AuthController {
    /**
     * User login with secure authentication
     */
    async login(req, res) {
        try {
            // Check validation results
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: errors.array()
                });
            }

            const { email, password, rememberMe = false } = req.body;
            const userIP = req.ip || req.connection.remoteAddress;

            // Check for failed login attempts
            const failedAttemptsKey = `failed_login:${email}`;
            const failedAttempts = await redisConfig.get(failedAttemptsKey) || 0;

            if (failedAttempts >= 5) {
                return res.status(429).json({
                    success: false,
                    message: 'Account temporarily locked due to multiple failed login attempts',
                    error: 'ACCOUNT_LOCKED'
                });
            }

            // Find user (replace with your User model query)
            // const user = await User.findOne({ email });
            
            // Mock user for demonstration - replace with actual database query
            const user = {
                id: 1,
                email: email,
                password: '$2a$12$hash', // This should be the actual hashed password from DB
                role: 'employee',
                department: 'IT',
                isActive: true,
                loginAttempts: 0,
                lastLogin: null
            };

            if (!user || !user.isActive) {
                // Increment failed attempts
                await redisConfig.set(failedAttemptsKey, failedAttempts + 1, 900); // 15 min expiry
                
                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials',
                    error: 'INVALID_CREDENTIALS'
                });
            }

            // Verify password
            const isValidPassword = await bcrypt.compare(password, user.password);
            if (!isValidPassword) {
                // Increment failed attempts
                await redisConfig.set(failedAttemptsKey, failedAttempts + 1, 900);
                
                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials',
                    error: 'INVALID_CREDENTIALS'
                });
            }

            // Clear failed attempts on successful login
            await redisConfig.del(failedAttemptsKey);

            // Generate tokens
            const tokens = await jwtService.generateTokens(user);

            // Store login session info
            const sessionKey = `session:${user.id}`;
            const sessionData = {
                userId: user.id,
                email: user.email,
                loginTime: new Date().toISOString(),
                ipAddress: userIP,
                userAgent: req.headers['user-agent']
            };

            await redisConfig.set(sessionKey, sessionData, 7 * 24 * 60 * 60); // 7 days

            // Update user's last login (replace with actual DB update)
            // await User.findByIdAndUpdate(user.id, {
            //     lastLogin: new Date(),
            //     loginAttempts: 0
            // });

            // Set secure cookie for refresh token if remember me is selected
            if (rememberMe) {
                res.cookie('refreshToken', tokens.refreshToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
                });
            }

            res.status(200).json({
                success: true,
                message: 'Login successful',
                data: {
                    user: {
                        id: user.id,
                        email: user.email,
                        role: user.role,
                        department: user.department
                    },
                    tokens: {
                        accessToken: tokens.accessToken,
                        refreshToken: rememberMe ? undefined : tokens.refreshToken, // Don't send in body if using cookies
                        expiresIn: tokens.accessTokenExpiry
                    }
                }
            });

        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error',
                error: 'SERVER_ERROR'
            });
        }
    }

    /**
     * Refresh access token
     */
    async refreshToken(req, res) {
        try {
            const refreshToken = req.body.refreshToken || req.cookies.refreshToken;

            if (!refreshToken) {
                return res.status(400).json({
                    success: false,
                    message: 'Refresh token is required',
                    error: 'MISSING_REFRESH_TOKEN'
                });
            }

            // Get user data from refresh token
            const tokenData = await jwtService.verifyRefreshToken(refreshToken);
            
            // Fetch full user data (replace with actual DB query)
            // const user = await User.findById(tokenData.userId);
            const user = {
                id: tokenData.userId,
                email: tokenData.email,
                role: 'employee',
                department: 'IT'
            };

            if (!user) {
                return res.status(401).json({
                    success: false,
                    message: 'User not found',
                    error: 'USER_NOT_FOUND'
                });
            }

            // Generate new access token
            const newTokens = await jwtService.refreshAccessToken(refreshToken, user);

            res.status(200).json({
                success: true,
                message: 'Token refreshed successfully',
                data: {
                    accessToken: newTokens.accessToken,
                    expiresIn: newTokens.accessTokenExpiry
                }
            });

        } catch (error) {
            console.error('Token refresh error:', error);
            res.status(401).json({
                success: false,
                message: 'Invalid or expired refresh token',
                error: 'INVALID_REFRESH_TOKEN'
            });
        }
    }

    /**
     * User logout
     */
    async logout(req, res) {
        try {
            const refreshToken = req.body.refreshToken || req.cookies.refreshToken;
            const userId = req.user?.id;

            if (refreshToken) {
                // Invalidate refresh token
                await jwtService.invalidateRefreshToken(refreshToken);
            }

            if (userId) {
                // Clear session data
                const sessionKey = `session:${userId}`;
                await redisConfig.del(sessionKey);
            }

            // Clear refresh token cookie
            res.clearCookie('refreshToken');

            res.status(200).json({
                success: true,
                message: 'Logout successful'
            });

        } catch (error) {
            console.error('Logout error:', error);
            res.status(500).json({
                success: false,
                message: 'Logout failed',
                error: 'SERVER_ERROR'
            });
        }
    }

    /**
     * Logout from all devices
     */
    async logoutAll(req, res) {
        try {
            const userId = req.user.id;

            // Invalidate all user tokens
            await jwtService.invalidateAllUserTokens(userId);

            // Clear all sessions
            const sessionKey = `session:${userId}`;
            await redisConfig.del(sessionKey);

            // Clear refresh token cookie
            res.clearCookie('refreshToken');

            res.status(200).json({
                success: true,
                message: 'Logged out from all devices successfully'
            });

        } catch (error) {
            console.error('Logout all error:', error);
            res.status(500).json({
                success: false,
                message: 'Logout from all devices failed',
                error: 'SERVER_ERROR'
            });
        }
    }

    /**
     * Get current user profile
     */
    async getProfile(req, res) {
        try {
            const userId = req.user.id;
            
            // Check cache first
            const cacheKey = `user_profile:${userId}`;
            let userProfile = await redisConfig.get(cacheKey);

            if (!userProfile) {
                // Fetch from database (replace with actual DB query)
                // userProfile = await User.findById(userId).select('-password');
                
                // Mock data - replace with actual query
                userProfile = {
                    id: userId,
                    email: req.user.email,
                    role: req.user.role,
                    department: req.user.department,
                    createdAt: new Date(),
                    lastLogin: new Date()
                };

                // Cache for 1 hour
                await redisConfig.set(cacheKey, userProfile, 3600);
            }

            res.status(200).json({
                success: true,
                message: 'Profile retrieved successfully',
                data: userProfile
            });

        } catch (error) {
            console.error('Get profile error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to retrieve profile',
                error: 'SERVER_ERROR'
            });
        }
    }

    /**
     * Change password
     */
    async changePassword(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: errors.array()
                });
            }

            const { currentPassword, newPassword } = req.body;
            const userId = req.user.id;

            // Get user from database
            // const user = await User.findById(userId);
            
            // Mock user - replace with actual query
            const user = {
                id: userId,
                password: '$2a$12$hash' // Current hashed password from DB
            };

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found',
                    error: 'USER_NOT_FOUND'
                });
            }

            // Verify current password
            const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
            if (!isCurrentPasswordValid) {
                return res.status(400).json({
                    success: false,
                    message: 'Current password is incorrect',
                    error: 'INVALID_CURRENT_PASSWORD'
                });
            }

            // Hash new password
            const saltRounds = 12;
            const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

            // Update password in database
            // await User.findByIdAndUpdate(userId, {
            //     password: hashedNewPassword,
            //     updatedAt: new Date()
            // });

            // Invalidate all user sessions (force re-login)
            await jwtService.invalidateAllUserTokens(userId);
            
            // Clear user profile cache
            const cacheKey = `user_profile:${userId}`;
            await redisConfig.del(cacheKey);

            res.status(200).json({
                success: true,
                message: 'Password changed successfully. Please login again.'
            });

        } catch (error) {
            console.error('Change password error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to change password',
                error: 'SERVER_ERROR'
            });
        }
    }

    /**
     * Validate token endpoint
     */
    async validateToken(req, res) {
        try {
            // If we reach here, the token is valid (middleware validated it)
            res.status(200).json({
                success: true,
                message: 'Token is valid',
                data: {
                    user: req.user,
                    tokenValid: true
                }
            });
        } catch (error) {
            console.error('Token validation error:', error);
            res.status(500).json({
                success: false,
                message: 'Token validation failed',
                error: 'SERVER_ERROR'
            });
        }
    }
}

module.exports = new AuthController();
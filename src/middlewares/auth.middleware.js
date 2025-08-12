const jwtService = require('../services/jwt.service');
const redisConfig = require('../config/redis.config');

/**
 * Middleware to authenticate JWT tokens
 */
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Access token is required',
                error: 'MISSING_TOKEN'
            });
        }

        // Verify the access token
        const decoded = jwtService.verifyAccessToken(token);
        
        // Check if user is blacklisted (optional security measure)
        const blacklistKey = `blacklist:${decoded.id}`;
        const isBlacklisted = await redisConfig.exists(blacklistKey);
        
        if (isBlacklisted) {
            return res.status(401).json({
                success: false,
                message: 'Access denied',
                error: 'USER_BLACKLISTED'
            });
        }

        // Add user info to request object
        req.user = decoded;
        next();
    } catch (error) {
        if (error.message === 'Access token expired') {
            return res.status(401).json({
                success: false,
                message: 'Access token expired',
                error: 'TOKEN_EXPIRED'
            });
        }
        
        return res.status(403).json({
            success: false,
            message: 'Invalid or malformed token',
            error: 'INVALID_TOKEN'
        });
    }
};

/**
 * Middleware to check user roles
 */
const authorizeRoles = (...allowedRoles) => {
    return (req, res, next) => {
        try {
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required',
                    error: 'NOT_AUTHENTICATED'
                });
            }

            if (!allowedRoles.includes(req.user.role)) {
                return res.status(403).json({
                    success: false,
                    message: 'Insufficient permissions',
                    error: 'INSUFFICIENT_PERMISSIONS'
                });
            }

            next();
        } catch (error) {
            return res.status(500).json({
                success: false,
                message: 'Authorization check failed',
                error: 'AUTHORIZATION_ERROR'
            });
        }
    };
};

/**
 * Middleware for optional authentication (doesn't fail if no token)
 */
const optionalAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (token) {
            try {
                const decoded = jwtService.verifyAccessToken(token);
                req.user = decoded;
            } catch (error) {
                // Token invalid or expired, but we don't fail the request
                req.user = null;
            }
        }

        next();
    } catch (error) {
        next();
    }
};

/**
 * Middleware to validate refresh token
 */
const validateRefreshToken = async (req, res, next) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(400).json({
                success: false,
                message: 'Refresh token is required',
                error: 'MISSING_REFRESH_TOKEN'
            });
        }

        // Verify refresh token
        const tokenData = await jwtService.verifyRefreshToken(refreshToken);
        req.refreshTokenData = tokenData;
        req.refreshToken = refreshToken;
        
        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: 'Invalid or expired refresh token',
            error: 'INVALID_REFRESH_TOKEN'
        });
    }
};

/**
 * Rate limiting middleware using Redis
 */
const rateLimiter = (maxAttempts = 5, windowMs = 15 * 60 * 1000, blockDurationMs = 15 * 60 * 1000) => {
    return async (req, res, next) => {
        try {
            const identifier = req.ip || req.connection.remoteAddress;
            const key = `rate_limit:${identifier}`;
            
            // Get current attempts
            const attempts = await redisConfig.get(key) || { count: 0, resetTime: Date.now() + windowMs };
            
            // Check if window has expired
            if (Date.now() > attempts.resetTime) {
                attempts.count = 0;
                attempts.resetTime = Date.now() + windowMs;
            }

            // Check if rate limit exceeded
            if (attempts.count >= maxAttempts) {
                const timeLeft = Math.ceil((attempts.resetTime - Date.now()) / 1000);
                return res.status(429).json({
                    success: false,
                    message: `Too many requests. Try again in ${timeLeft} seconds.`,
                    error: 'RATE_LIMIT_EXCEEDED',
                    retryAfter: timeLeft
                });
            }

            // Increment attempts
            attempts.count += 1;
            await redisConfig.set(key, attempts, Math.ceil(windowMs / 1000));

            next();
        } catch (error) {
            console.error('Rate limiting error:', error);
            next(); // Don't fail the request if rate limiting fails
        }
    };
};

/**
 * Security headers middleware
 */
const securityHeaders = (req, res, next) => {
    // Remove server information
    res.removeHeader('X-Powered-By');
    
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    next();
};

module.exports = {
    authenticateToken,
    authorizeRoles,
    optionalAuth,
    validateRefreshToken,
    rateLimiter,
    securityHeaders
}
// server/src/routes/auth.routes.ts
import { Router } from 'express'
import rateLimit from 'express-rate-limit'
import { AuthController } from '../controllers/auth.controller'
import { authMiddleware } from '../middleware/auth.middleware'
import { validationMiddleware } from '../middleware/validation.middleware'
import { 
  validateLogin, 
  validateRegister, 
  validateChangePassword,
  validateRequestPasswordReset,
  validateResetPassword,
  validateVerifyEmail,
  validateResendVerification,
  validateRefreshToken
} from '../schemas/auth.schema'

const router = Router()
const authController = new AuthController()

// Stricter rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 requests per window
  message: {
    success: false,
    message: 'Demasiados intentos de autenticación, intenta más tarde',
    errors: ['Authentication rate limit exceeded']
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true
})

const strictLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // 5 requests per window
  message: {
    success: false,
    message: 'Demasiados intentos, espera antes de intentar nuevamente',
    errors: ['Strict rate limit exceeded']
  }
})

// Public routes (no authentication required)

/**
 * @route POST /api/auth/login
 * @desc Authenticate user and return tokens
 * @access Public
 */
router.post('/login', 
  authLimiter,
  validationMiddleware(validateLogin),
  authController.login
)

/**
 * @route POST /api/auth/register
 * @desc Register a new user
 * @access Public
 */
router.post('/register',
  authLimiter,
  validationMiddleware(validateRegister),
  authController.register
)

/**
 * @route POST /api/auth/refresh-token
 * @desc Refresh access token using refresh token
 * @access Public
 */
router.post('/refresh-token',
  authLimiter,
  validationMiddleware(validateRefreshToken),
  authController.refreshToken
)

/**
 * @route POST /api/auth/request-password-reset
 * @desc Request password reset email
 * @access Public
 */
router.post('/request-password-reset',
  strictLimiter,
  validationMiddleware(validateRequestPasswordReset),
  authController.requestPasswordReset
)

/**
 * @route POST /api/auth/reset-password
 * @desc Reset password using token
 * @access Public
 */
router.post('/reset-password',
  authLimiter,
  validationMiddleware(validateResetPassword),
  authController.resetPassword
)

/**
 * @route POST /api/auth/verify-email
 * @desc Verify user email with token
 * @access Public
 */
router.post('/verify-email',
  authLimiter,
  validationMiddleware(validateVerifyEmail),
  authController.verifyEmail
)

/**
 * @route POST /api/auth/resend-verification
 * @desc Resend email verification
 * @access Public
 */
router.post('/resend-verification',
  strictLimiter,
  validationMiddleware(validateResendVerification),
  authController.resendEmailVerification
)

/**
 * @route POST /api/auth/validate-token
 * @desc Validate JWT token
 * @access Public
 */
router.post('/validate-token',
  authController.validateToken
)

// Protected routes (authentication required)

/**
 * @route POST /api/auth/logout
 * @desc Logout user and invalidate tokens
 * @access Private
 */
router.post('/logout',
  authMiddleware,
  authController.logout
)

/**
 * @route POST /api/auth/change-password
 * @desc Change user password
 * @access Private
 */
router.post('/change-password',
  authMiddleware,
  authLimiter,
  validationMiddleware(validateChangePassword),
  authController.changePassword
)

/**
 * @route GET /api/auth/profile
 * @desc Get current user profile
 * @access Private
 */
router.get('/profile',
  authMiddleware,
  authController.getProfile
)

/**
 * @route GET /api/auth/sessions
 * @desc Get user active sessions
 * @access Private
 */
router.get('/sessions',
  authMiddleware,
  authController.getSessions
)

/**
 * @route DELETE /api/auth/sessions/:sessionId
 * @desc Invalidate specific session
 * @access Private
 */
router.delete('/sessions/:sessionId',
  authMiddleware,
  authController.invalidateSession
)

/**
 * @route GET /api/auth/health
 * @desc Auth service health check
 * @access Public
 */
router.get('/health',
  authController.healthCheck
)

export { router as authRoutes }
// server/src/controllers/auth.controller.ts
import { Request, Response } from 'express'
import { AuthService } from '../services/auth.service'
import { EmailService } from '../services/email.service'
import { 
  validateLogin, 
  validateRegister, 
  validateChangePassword,
  validateRequestPasswordReset,
  validateResetPassword,
  validateVerifyEmail,
  validateResendVerification,
  validateRefreshToken,
  validateLogout
} from '../schemas/auth.schema'
import { AuthResponse, APIResponse } from '../types/auth.types'
import { logger, apiLogger } from '../utils/logger'
import { ValidationUtils } from '../utils/validation.utils'

export class AuthController {
  private authService: AuthService
  private emailService: EmailService

  constructor() {
    this.authService = new AuthService()
    this.emailService = new EmailService()
  }

  /**
   * Login endpoint
   */
  login = async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now()
    const ipAddress = req.ip || req.connection.remoteAddress
    const userAgent = req.get('User-Agent')

    try {
      // Validate request body
      const validation = validateLogin(req.body)
      if (!validation.success) {
        res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: validation.error.errors.map(err => err.message)
        } as AuthResponse)
        return
      }

      const { username, password, rememberMe } = validation.data

      // Rate limiting check could be added here
      
      const result = await this.authService.login(
        { username, password, rememberMe },
        ipAddress,
        userAgent
      )

      // Set HTTP-only cookie for refresh token
      res.cookie('refreshToken', result.tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000 // 30 days or 1 day
      })

      const duration = Date.now() - startTime
      apiLogger.performance('AUTH_LOGIN', duration, {
        userId: result.user.id,
        username: result.user.username
      })

      res.status(200).json({
        success: true,
        message: 'Inicio de sesión exitoso',
        data: {
          user: result.user,
          tokens: {
            accessToken: result.tokens.accessToken,
            tokenType: result.tokens.tokenType,
            expiresIn: result.tokens.expiresIn
          }
        }
      } as AuthResponse)

    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Login controller error', error as Error, {
        duration,
        ipAddress,
        userAgent
      })

      res.status(401).json({
        success: false,
        message: (error as Error).message || 'Error en el inicio de sesión',
        errors: [(error as Error).message]
      } as AuthResponse)
    }
  }

  /**
   * Register endpoint
   */
  register = async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now()
    const ipAddress = req.ip || req.connection.remoteAddress
    const userAgent = req.get('User-Agent')

    try {
      // Validate request body
      const validation = validateRegister(req.body)
      if (!validation.success) {
        res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: validation.error.errors.map(err => err.message)
        } as AuthResponse)
        return
      }

      const registerData = validation.data

      const result = await this.authService.register(registerData, ipAddress, userAgent)

      // Send verification email
      try {
        await this.emailService.sendEmailVerification(
          result.user.email,
          result.emailVerificationToken,
          result.user.firstName || result.user.username
        )
      } catch (emailError) {
        logger.error('Failed to send verification email', emailError as Error, {
          userId: result.user.id,
          email: result.user.email
        })
        // Continue with registration success even if email fails
      }

      const duration = Date.now() - startTime
      apiLogger.performance('AUTH_REGISTER', duration, {
        userId: result.user.id,
        username: result.user.username
      })

      res.status(201).json({
        success: true,
        message: 'Registro exitoso. Por favor verifica tu email.',
        data: {
          user: result.user
        }
      } as AuthResponse)

    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Register controller error', error as Error, {
        duration,
        ipAddress,
        userAgent
      })

      let statusCode = 500
      if ((error as Error).message.includes('ya está') || (error as Error).message.includes('already')) {
        statusCode = 409
      }

      res.status(statusCode).json({
        success: false,
        message: (error as Error).message || 'Error en el registro',
        errors: [(error as Error).message]
      } as AuthResponse)
    }
  }

  /**
   * Refresh token endpoint
   */
  refreshToken = async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now()
    const ipAddress = req.ip || req.connection.remoteAddress
    const userAgent = req.get('User-Agent')

    try {
      // Get refresh token from cookie or body
      const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken

      if (!refreshToken) {
        res.status(401).json({
          success: false,
          message: 'Refresh token requerido',
          errors: ['No refresh token provided']
        } as AuthResponse)
        return
      }

      const validation = validateRefreshToken({ refreshToken })
      if (!validation.success) {
        res.status(400).json({
          success: false,
          message: 'Refresh token inválido',
          errors: validation.error.errors.map(err => err.message)
        } as AuthResponse)
        return
      }

      const tokens = await this.authService.refreshToken(refreshToken, ipAddress, userAgent)

      const duration = Date.now() - startTime
      apiLogger.performance('AUTH_REFRESH_TOKEN', duration)

      res.status(200).json({
        success: true,
        message: 'Token renovado exitosamente',
        data: {
          tokens: {
            accessToken: tokens.accessToken,
            tokenType: tokens.tokenType,
            expiresIn: tokens.expiresIn
          }
        }
      } as AuthResponse)

    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Refresh token controller error', error as Error, {
        duration,
        ipAddress,
        userAgent
      })

      res.status(401).json({
        success: false,
        message: (error as Error).message || 'Error renovando token',
        errors: [(error as Error).message]
      } as AuthResponse)
    }
  }

  /**
   * Logout endpoint
   */
  logout = async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now()
    const user = (req as any).user

    try {
      const validation = validateLogout(req.body)
      const { logoutAll } = validation.success ? validation.data : { logoutAll: false }

      await this.authService.logout(user?.id, undefined, logoutAll)

      // Clear refresh token cookie
      res.clearCookie('refreshToken')

      const duration = Date.now() - startTime
      apiLogger.performance('AUTH_LOGOUT', duration, {
        userId: user?.id,
        logoutAll
      })

      res.status(200).json({
        success: true,
        message: logoutAll ? 'Sesiones cerradas exitosamente' : 'Sesión cerrada exitosamente'
      } as APIResponse)

    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Logout controller error', error as Error, {
        duration,
        userId: user?.id
      })

      res.status(500).json({
        success: false,
        message: 'Error cerrando sesión',
        errors: [(error as Error).message]
      } as APIResponse)
    }
  }

  /**
   * Request password reset endpoint
   */
  requestPasswordReset = async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now()
    const ipAddress = req.ip || req.connection.remoteAddress
    const userAgent = req.get('User-Agent')

    try {
      const validation = validateRequestPasswordReset(req.body)
      if (!validation.success) {
        res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: validation.error.errors.map(err => err.message)
        } as APIResponse)
        return
      }

      const { email } = validation.data

      const resetToken = await this.authService.requestPasswordReset(email, ipAddress, userAgent)

      // Send password reset email
      try {
        await this.emailService.sendPasswordReset(email, resetToken)
      } catch (emailError) {
        logger.error('Failed to send password reset email', emailError as Error, { email })
        // Continue with success response for security
      }

      const duration = Date.now() - startTime
      apiLogger.performance('AUTH_REQUEST_PASSWORD_RESET', duration)

      // Always return success for security (don't reveal if email exists)
      res.status(200).json({
        success: true,
        message: 'Si el email existe, recibirás instrucciones para restablecer tu contraseña'
      } as APIResponse)

    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Request password reset controller error', error as Error, {
        duration,
        ipAddress,
        userAgent
      })

      res.status(500).json({
        success: false,
        message: 'Error procesando solicitud',
        errors: [(error as Error).message]
      } as APIResponse)
    }
  }

  /**
   * Reset password endpoint
   */
  resetPassword = async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now()
    const ipAddress = req.ip || req.connection.remoteAddress
    const userAgent = req.get('User-Agent')

    try {
      const validation = validateResetPassword(req.body)
      if (!validation.success) {
        res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: validation.error.errors.map(err => err.message)
        } as APIResponse)
        return
      }

      const { token, newPassword } = validation.data

      await this.authService.resetPassword(token, newPassword, ipAddress, userAgent)

      const duration = Date.now() - startTime
      apiLogger.performance('AUTH_RESET_PASSWORD', duration)

      res.status(200).json({
        success: true,
        message: 'Contraseña restablecida exitosamente'
      } as APIResponse)

    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Reset password controller error', error as Error, {
        duration,
        ipAddress,
        userAgent
      })

      res.status(400).json({
        success: false,
        message: (error as Error).message || 'Error restableciendo contraseña',
        errors: [(error as Error).message]
      } as APIResponse)
    }
  }

  /**
   * Change password endpoint
   */
  changePassword = async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now()
    const user = (req as any).user
    const ipAddress = req.ip || req.connection.remoteAddress
    const userAgent = req.get('User-Agent')

    try {
      const validation = validateChangePassword(req.body)
      if (!validation.success) {
        res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: validation.error.errors.map(err => err.message)
        } as APIResponse)
        return
      }

      const { currentPassword, newPassword } = validation.data

      await this.authService.changePassword(
        user.id,
        currentPassword,
        newPassword,
        ipAddress,
        userAgent
      )

      const duration = Date.now() - startTime
      apiLogger.performance('AUTH_CHANGE_PASSWORD', duration, {
        userId: user.id
      })

      res.status(200).json({
        success: true,
        message: 'Contraseña cambiada exitosamente'
      } as APIResponse)

    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Change password controller error', error as Error, {
        duration,
        userId: user?.id,
        ipAddress,
        userAgent
      })

      res.status(400).json({
        success: false,
        message: (error as Error).message || 'Error cambiando contraseña',
        errors: [(error as Error).message]
      } as APIResponse)
    }
  }

  /**
   * Verify email endpoint
   */
  verifyEmail = async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now()
    const ipAddress = req.ip || req.connection.remoteAddress
    const userAgent = req.get('User-Agent')

    try {
      const validation = validateVerifyEmail(req.body)
      if (!validation.success) {
        res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: validation.error.errors.map(err => err.message)
        } as APIResponse)
        return
      }

      const { token } = validation.data

      await this.authService.verifyEmail(token, ipAddress, userAgent)

      const duration = Date.now() - startTime
      apiLogger.performance('AUTH_VERIFY_EMAIL', duration)

      res.status(200).json({
        success: true,
        message: 'Email verificado exitosamente'
      } as APIResponse)

    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Verify email controller error', error as Error, {
        duration,
        ipAddress,
        userAgent
      })

      res.status(400).json({
        success: false,
        message: (error as Error).message || 'Error verificando email',
        errors: [(error as Error).message]
      } as APIResponse)
    }
  }

  /**
   * Resend email verification endpoint
   */
  resendEmailVerification = async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now()
    const ipAddress = req.ip || req.connection.remoteAddress
    const userAgent = req.get('User-Agent')

    try {
      const validation = validateResendVerification(req.body)
      if (!validation.success) {
        res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: validation.error.errors.map(err => err.message)
        } as APIResponse)
        return
      }

      const { email } = validation.data

      const verificationToken = await this.authService.resendEmailVerification(
        email,
        ipAddress,
        userAgent
      )

      // Send verification email
      try {
        await this.emailService.sendEmailVerification(email, verificationToken)
      } catch (emailError) {
        logger.error('Failed to send verification email', emailError as Error, { email })
        throw new Error('Error enviando email de verificación')
      }

      const duration = Date.now() - startTime
      apiLogger.performance('AUTH_RESEND_EMAIL_VERIFICATION', duration)

      res.status(200).json({
        success: true,
        message: 'Email de verificación enviado'
      } as APIResponse)

    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Resend email verification controller error', error as Error, {
        duration,
        ipAddress,
        userAgent
      })

      res.status(400).json({
        success: false,
        message: (error as Error).message || 'Error enviando verificación',
        errors: [(error as Error).message]
      } as APIResponse)
    }
  }

  /**
   * Get user profile endpoint
   */
  getProfile = async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now()
    const user = (req as any).user

    try {
      const profile = await this.authService.getUserProfile(user.id)

      const duration = Date.now() - startTime
      apiLogger.performance('AUTH_GET_PROFILE', duration, {
        userId: user.id
      })

      res.status(200).json({
        success: true,
        message: 'Perfil obtenido exitosamente',
        data: {
          user: profile
        }
      } as AuthResponse)

    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Get profile controller error', error as Error, {
        duration,
        userId: user?.id
      })

      res.status(500).json({
        success: false,
        message: 'Error obteniendo perfil',
        errors: [(error as Error).message]
      } as APIResponse)
    }
  }

  /**
   * Get user sessions endpoint
   */
  getSessions = async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now()
    const user = (req as any).user

    try {
      const sessions = await this.authService.getUserSessions(user.id)

      const duration = Date.now() - startTime
      apiLogger.performance('AUTH_GET_SESSIONS', duration, {
        userId: user.id
      })

      res.status(200).json({
        success: true,
        message: 'Sesiones obtenidas exitosamente',
        data: {
          sessions: sessions.map(session => ({
            id: session.id,
            ipAddress: session.ipAddress,
            userAgent: session.userAgent,
            createdAt: session.createdAt,
            lastActivity: session.lastActivity,
            isValid: session.isValid
          }))
        }
      } as APIResponse)

    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Get sessions controller error', error as Error, {
        duration,
        userId: user?.id
      })

      res.status(500).json({
        success: false,
        message: 'Error obteniendo sesiones',
        errors: [(error as Error).message]
      } as APIResponse)
    }
  }

  /**
   * Invalidate session endpoint
   */
  invalidateSession = async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now()
    const user = (req as any).user
    const { sessionId } = req.params

    try {
      if (!ValidationUtils.validateUUID(sessionId)) {
        res.status(400).json({
          success: false,
          message: 'ID de sesión inválido',
          errors: ['Invalid session ID format']
        } as APIResponse)
        return
      }

      await this.authService.invalidateSession(sessionId)

      const duration = Date.now() - startTime
      apiLogger.performance('AUTH_INVALIDATE_SESSION', duration, {
        userId: user.id,
        sessionId
      })

      res.status(200).json({
        success: true,
        message: 'Sesión invalidada exitosamente'
      } as APIResponse)

    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Invalidate session controller error', error as Error, {
        duration,
        userId: user?.id,
        sessionId
      })

      res.status(500).json({
        success: false,
        message: 'Error invalidando sesión',
        errors: [(error as Error).message]
      } as APIResponse)
    }
  }

  /**
   * Validate token endpoint
   */
  validateToken = async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now()

    try {
      const authHeader = req.headers.authorization
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
          success: false,
          message: 'Token requerido',
          errors: ['No authorization token provided']
        } as APIResponse)
        return
      }

      const token = authHeader.split(' ')[1]
      const decoded = await this.authService.validateToken(token)

      const duration = Date.now() - startTime
      apiLogger.performance('AUTH_VALIDATE_TOKEN', duration)

      res.status(200).json({
        success: true,
        message: 'Token válido',
        data: {
          user: {
            id: decoded.sub,
            username: decoded.username,
            email: decoded.email,
            roles: decoded.roles,
            permissions: decoded.permissions
          },
          expiresAt: new Date(decoded.exp * 1000)
        }
      } as APIResponse)

    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Validate token controller error', error as Error, {
        duration
      })

      res.status(401).json({
        success: false,
        message: 'Token inválido',
        errors: [(error as Error).message]
      } as APIResponse)
    }
  }

  /**
   * Health check endpoint
   */
  healthCheck = async (req: Request, res: Response): Promise<void> => {
    try {
      res.status(200).json({
        success: true,
        message: 'Auth service is healthy',
        data: {
          timestamp: new Date().toISOString(),
          uptime: process.uptime(),
          version: process.env.API_VERSION || '1.0.0'
        }
      } as APIResponse)

    } catch (error) {
      logger.error('Health check controller error', error as Error)

      res.status(500).json({
        success: false,
        message: 'Auth service is unhealthy',
        errors: [(error as Error).message]
      } as APIResponse)
    }
  }
}
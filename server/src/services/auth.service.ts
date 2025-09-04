// server/src/services/auth.service.ts
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { 
  IUser, 
  IUserPublic, 
  LoginDTO, 
  RegisterDTO, 
  AuthTokens, 
  JWTPayload, 
  RefreshTokenPayload 
} from '../types/auth.types'
import { UserModelPostgreSQL } from '../models/postgresql/User.model'
import { authConfig } from '../config/auth'
import { logger, authLogger } from '../utils/logger'
import { CryptoUtils } from '../utils/crypto.utils'
import { ValidationUtils } from '../utils/validation.utils'

export class AuthService {
  private userModel: UserModelPostgreSQL
  private readonly JWT_SECRET: string
  private readonly REFRESH_SECRET: string

  constructor() {
    this.userModel = new UserModelPostgreSQL()
    this.JWT_SECRET = authConfig.jwt.secret
    this.REFRESH_SECRET = authConfig.jwt.secret + '_refresh'
  }

  /**
   * Authenticate user with username/email and password
   */
  async login(loginData: LoginDTO, ipAddress?: string, userAgent?: string): Promise<{
    user: IUserPublic
    tokens: AuthTokens
  }> {
    const { username, password, rememberMe } = loginData

    try {
      // Find user by username or email
      let user = await this.userModel.findByUsername(username)
      if (!user) {
        user = await this.userModel.findByEmail(username)
      }

      // Log failed attempt for non-existent user
      if (!user) {
        await this.createLoginHistory(null, username, ipAddress, userAgent, false, 'User not found')
        authLogger.authFailure(username, ipAddress || 'unknown', 'User not found')
        throw new Error('Credenciales inválidas')
      }

      // Check if user is active
      if (!user.isActive) {
        await this.createLoginHistory(user.id, username, ipAddress, userAgent, false, 'Account disabled')
        authLogger.authFailure(username, ipAddress || 'unknown', 'Account disabled')
        throw new Error('Cuenta desactivada')
      }

      // Check if user is locked out
      const isLocked = await this.userModel.isUserLocked(user.id)
      if (isLocked) {
        await this.createLoginHistory(user.id, username, ipAddress, userAgent, false, 'Account locked')
        authLogger.authFailure(username, ipAddress || 'unknown', 'Account locked')
        throw new Error('Cuenta bloqueada temporalmente')
      }

      // Check failed attempts
      if (user.failedLoginAttempts >= authConfig.security.maxLoginAttempts) {
        const lockoutUntil = new Date(Date.now() + authConfig.security.lockoutDuration)
        await this.userModel.setLockout(user.id, lockoutUntil)
        await this.createLoginHistory(user.id, username, ipAddress, userAgent, false, 'Max attempts exceeded')
        authLogger.securityEvent('ACCOUNT_LOCKOUT', {
          userId: user.id,
          username: user.username,
          ipAddress,
          failedAttempts: user.failedLoginAttempts
        })
        throw new Error('Demasiados intentos fallidos. Cuenta bloqueada temporalmente')
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password)
      if (!isValidPassword) {
        await this.userModel.incrementFailedAttempts(user.id)
        await this.createLoginHistory(user.id, username, ipAddress, userAgent, false, 'Invalid password')
        authLogger.authFailure(username, ipAddress || 'unknown', 'Invalid password')
        throw new Error('Credenciales inválidas')
      }

      // Reset failed attempts on successful login
      await this.userModel.resetFailedAttempts(user.id)
      await this.userModel.updateLastLogin(user.id)

      // Create session
      const sessionData = {
        tokenHash: CryptoUtils.hashToken(CryptoUtils.generateSecureToken()),
        ipAddress: ipAddress || 'unknown',
        userAgent: userAgent || 'unknown',
        expiresAt: new Date(Date.now() + (rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000)) // 30 days or 1 day
      }

      await this.userModel.createSession(user.id, sessionData)

      // Generate tokens
      const tokens = await this.generateTokens(user, rememberMe)

      // Log successful login
      await this.createLoginHistory(user.id, username, ipAddress, userAgent, true)
      authLogger.authSuccess(user.id, user.username, ipAddress || 'unknown')

      // Return user without sensitive data
      const publicUser = this.toPublicUser(user)

      return {
        user: publicUser,
        tokens
      }

    } catch (error) {
      logger.error('Login failed', error as Error, { username, ipAddress })
      throw error
    }
  }

  /**
   * Register new user
   */
  async register(registerData: RegisterDTO, ipAddress?: string, userAgent?: string): Promise<{
    user: IUserPublic
    emailVerificationToken: string
  }> {
    const { username, email, password, firstName, lastName } = registerData

    try {
      // Check if username exists
      const existingUsername = await this.userModel.existsByUsername(username)
      if (existingUsername) {
        throw new Error('El nombre de usuario ya está en uso')
      }

      // Check if email exists
      const existingEmail = await this.userModel.existsByEmail(email)
      if (existingEmail) {
        throw new Error('El email ya está registrado')
      }

      // Create user
      const userData = {
        username: username.toLowerCase(),
        email: email.toLowerCase(),
        password,
        firstName,
        lastName
      }

      const user = await this.userModel.create(userData)

      // Generate email verification token
      const emailVerificationToken = CryptoUtils.generateSecureToken()
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours

      await this.userModel.setEmailVerificationToken(email, emailVerificationToken, expiresAt)

      // Log registration
      await this.userModel.createAuditLog({
        userId: user.id,
        action: 'USER_REGISTERED',
        resource: 'user',
        resourceId: user.id,
        ipAddress,
        userAgent,
        success: true
      })

      authLogger.info('User registered successfully', {
        userId: user.id,
        username: user.username,
        email: user.email,
        ipAddress
      })

      return {
        user: this.toPublicUser(user),
        emailVerificationToken
      }

    } catch (error) {
      logger.error('Registration failed', error as Error, { registerData: { username, email }, ipAddress })
      throw error
    }
  }

  /**
   * Refresh access token
   */
  async refreshToken(refreshToken: string, ipAddress?: string, userAgent?: string): Promise<AuthTokens> {
    try {
      // Verify refresh token
      const decoded = jwt.verify(refreshToken, this.REFRESH_SECRET) as RefreshTokenPayload

      // Find user
      const user = await this.userModel.findById(decoded.sub)
      if (!user) {
        throw new Error('Usuario no encontrado')
      }

      if (!user.isActive) {
        throw new Error('Cuenta desactivada')
      }

      // Generate new tokens
      const tokens = await this.generateTokens(user, false)

      authLogger.info('Token refreshed successfully', {
        userId: user.id,
        username: user.username,
        ipAddress
      })

      return tokens

    } catch (error) {
      logger.error('Token refresh failed', error as Error, { ipAddress })
      throw new Error('Token de refresh inválido')
    }
  }

  /**
   * Logout user
   */
  async logout(userId: string, sessionId?: string, logoutAll: boolean = false): Promise<void> {
    try {
      if (logoutAll) {
        await this.userModel.invalidateUserSessions(userId)
        authLogger.info('All sessions invalidated', { userId })
      } else if (sessionId) {
        await this.userModel.invalidateSession(sessionId)
        authLogger.info('Session invalidated', { userId, sessionId })
      }

      await this.userModel.createAuditLog({
        userId,
        action: 'USER_LOGOUT',
        resource: 'session',
        success: true
      })

    } catch (error) {
      logger.error('Logout failed', error as Error, { userId, sessionId, logoutAll })
      throw error
    }
  }

  /**
   * Request password reset
   */
  async requestPasswordReset(email: string, ipAddress?: string, userAgent?: string): Promise<string> {
    try {
      const user = await this.userModel.findByEmail(email)
      
      // Always return success message for security (don't reveal if email exists)
      if (!user) {
        logger.warn('Password reset requested for non-existent email', { email, ipAddress })
        return CryptoUtils.generateSecureToken() // Return dummy token
      }

      if (!user.isActive) {
        throw new Error('Cuenta desactivada')
      }

      // Generate reset token
      const resetToken = CryptoUtils.generateSecureToken()
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000) // 1 hour

      await this.userModel.setPasswordResetToken(email, resetToken, expiresAt)

      await this.userModel.createAuditLog({
        userId: user.id,
        action: 'PASSWORD_RESET_REQUESTED',
        resource: 'user',
        resourceId: user.id,
        ipAddress,
        userAgent,
        success: true
      })

      authLogger.info('Password reset requested', {
        userId: user.id,
        email: user.email,
        ipAddress
      })

      return resetToken

    } catch (error) {
      logger.error('Password reset request failed', error as Error, { email, ipAddress })
      throw error
    }
  }

  /**
   * Reset password with token
   */
  async resetPassword(token: string, newPassword: string, ipAddress?: string, userAgent?: string): Promise<void> {
    try {
      const user = await this.userModel.findByPasswordResetToken(token)
      if (!user) {
        throw new Error('Token inválido o expirado')
      }

      // Validate new password
      const passwordValidation = ValidationUtils.validatePassword(newPassword)
      if (!passwordValidation.isValid) {
        throw new Error(passwordValidation.errors.join(', '))
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, authConfig.bcrypt.saltRounds)

      // Update password
      await this.userModel.updatePassword(user.id, hashedPassword)

      // Invalidate all sessions
      await this.userModel.invalidateUserSessions(user.id)

      await this.userModel.createAuditLog({
        userId: user.id,
        action: 'PASSWORD_RESET',
        resource: 'user',
        resourceId: user.id,
        ipAddress,
        userAgent,
        success: true
      })

      authLogger.info('Password reset successfully', {
        userId: user.id,
        email: user.email,
        ipAddress
      })

    } catch (error) {
      logger.error('Password reset failed', error as Error, { token: '***', ipAddress })
      throw error
    }
  }

  /**
   * Change password for authenticated user
   */
  async changePassword(userId: string, currentPassword: string, newPassword: string, ipAddress?: string, userAgent?: string): Promise<void> {
    try {
      const user = await this.userModel.findById(userId)
      if (!user) {
        throw new Error('Usuario no encontrado')
      }

      // Verify current password
      const isValidPassword = await bcrypt.compare(currentPassword, user.password)
      if (!isValidPassword) {
        throw new Error('Contraseña actual incorrecta')
      }

      // Validate new password
      const passwordValidation = ValidationUtils.validatePassword(newPassword)
      if (!passwordValidation.isValid) {
        throw new Error(passwordValidation.errors.join(', '))
      }

      // Check if new password is different from current
      const isSamePassword = await bcrypt.compare(newPassword, user.password)
      if (isSamePassword) {
        throw new Error('La nueva contraseña debe ser diferente a la actual')
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, authConfig.bcrypt.saltRounds)

      // Update password
      await this.userModel.updatePassword(userId, hashedPassword)

      await this.userModel.createAuditLog({
        userId,
        action: 'PASSWORD_CHANGED',
        resource: 'user',
        resourceId: userId,
        ipAddress,
        userAgent,
        success: true
      })

      authLogger.info('Password changed successfully', {
        userId,
        ipAddress
      })

    } catch (error) {
      logger.error('Password change failed', error as Error, { userId, ipAddress })
      throw error
    }
  }

  /**
   * Verify email with token
   */
  async verifyEmail(token: string, ipAddress?: string, userAgent?: string): Promise<void> {
    try {
      const verified = await this.userModel.verifyEmail(token)
      if (!verified) {
        throw new Error('Token de verificación inválido o expirado')
      }

      authLogger.info('Email verified successfully', {
        token: token.substring(0, 8) + '...',
        ipAddress
      })

    } catch (error) {
      logger.error('Email verification failed', error as Error, { token: '***', ipAddress })
      throw error
    }
  }

  /**
   * Resend email verification
   */
  async resendEmailVerification(email: string, ipAddress?: string, userAgent?: string): Promise<string> {
    try {
      const user = await this.userModel.findByEmail(email)
      if (!user) {
        throw new Error('Email no encontrado')
      }

      if (user.emailVerified) {
        throw new Error('El email ya está verificado')
      }

      if (!user.isActive) {
        throw new Error('Cuenta desactivada')
      }

      // Generate new verification token
      const verificationToken = CryptoUtils.generateSecureToken()
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours

      await this.userModel.setEmailVerificationToken(email, verificationToken, expiresAt)

      await this.userModel.createAuditLog({
        userId: user.id,
        action: 'EMAIL_VERIFICATION_RESENT',
        resource: 'user',
        resourceId: user.id,
        ipAddress,
        userAgent,
        success: true
      })

      authLogger.info('Email verification resent', {
        userId: user.id,
        email: user.email,
        ipAddress
      })

      return verificationToken

    } catch (error) {
      logger.error('Email verification resend failed', error as Error, { email, ipAddress })
      throw error
    }
  }

  /**
   * Validate JWT token
   */
  async validateToken(token: string): Promise<JWTPayload> {
    try {
      const decoded = jwt.verify(token, this.JWT_SECRET) as JWTPayload

      // Check if user still exists and is active
      const user = await this.userModel.findById(decoded.sub)
      if (!user || !user.isActive) {
        throw new Error('Token inválido')
      }

      return decoded

    } catch (error) {
      logger.error('Token validation failed', error as Error)
      throw new Error('Token inválido')
    }
  }

  /**
   * Get user profile
   */
  async getUserProfile(userId: string): Promise<IUserPublic> {
    try {
      const user = await this.userModel.findById(userId)
      if (!user) {
        throw new Error('Usuario no encontrado')
      }

      return this.toPublicUser(user)

    } catch (error) {
      logger.error('Get user profile failed', error as Error, { userId })
      throw error
    }
  }

  /**
   * Generate JWT tokens
   */
  private async generateTokens(user: IUser, rememberMe: boolean = false): Promise<AuthTokens> {
    const permissions = await this.userModel.getUserPermissions(user.id)
    const roleIds = await this.userModel.getUserRoles(user.id)

    const accessTokenExpiry = rememberMe ? '7d' : authConfig.jwt.accessTokenExpiry
    const refreshTokenExpiry = rememberMe ? '30d' : authConfig.jwt.refreshTokenExpiry

    // Access token payload
    const accessTokenPayload: JWTPayload = {
      sub: user.id,
      username: user.username,
      email: user.email,
      roles: roleIds,
      permissions,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + this.parseExpiry(accessTokenExpiry),
      iss: authConfig.jwt.issuer,
      aud: authConfig.jwt.audience
    }

    // Refresh token payload
    const refreshTokenPayload: RefreshTokenPayload = {
      sub: user.id,
      username: user.username,
      tokenVersion: 1, // For token revocation
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + this.parseExpiry(refreshTokenExpiry),
      iss: authConfig.jwt.issuer,
      aud: authConfig.jwt.audience
    }

    const accessToken = jwt.sign(accessTokenPayload, this.JWT_SECRET, {
      algorithm: authConfig.jwt.algorithm
    })

    const refreshToken = jwt.sign(refreshTokenPayload, this.REFRESH_SECRET, {
      algorithm: authConfig.jwt.algorithm
    })

    return {
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: this.parseExpiry(accessTokenExpiry)
    }
  }

  /**
   * Parse expiry string to seconds
   */
  private parseExpiry(expiry: string): number {
    const unit = expiry.slice(-1)
    const value = parseInt(expiry.slice(0, -1))

    switch (unit) {
      case 's': return value
      case 'm': return value * 60
      case 'h': return value * 60 * 60
      case 'd': return value * 24 * 60 * 60
      default: return 900 // 15 minutes default
    }
  }

  /**
   * Convert user to public format (remove sensitive data)
   */
  private toPublicUser(user: IUser): IUserPublic {
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      isActive: user.isActive,
      emailVerified: user.emailVerified,
      lastLogin: user.lastLogin,
      createdAt: user.createdAt,
      roles: user.roles.map(role => ({
        id: role.id,
        name: role.name,
        description: role.description
      }))
    }
  }

  /**
   * Create login history entry
   */
  private async createLoginHistory(
    userId: string | null,
    username: string,
    ipAddress?: string,
    userAgent?: string,
    success: boolean = false,
    failureReason?: string
  ): Promise<void> {
    try {
      await this.userModel.createAuditLog({
        userId,
        action: success ? 'LOGIN_SUCCESS' : 'LOGIN_FAILURE',
        resource: 'authentication',
        details: {
          username,
          failureReason
        },
        ipAddress,
        userAgent,
        success
      })
    } catch (error) {
      logger.error('Failed to create login history', error as Error)
    }
  }

  /**
   * Get user active sessions
   */
  async getUserSessions(userId: string): Promise<ISession[]> {
    try {
      return await this.userModel.getUserActiveSessions(userId)
    } catch (error) {
      logger.error('Get user sessions failed', error as Error, { userId })
      throw error
    }
  }

  /**
   * Invalidate specific session
   */
  async invalidateSession(sessionId: string): Promise<void> {
    try {
      await this.userModel.invalidateSession(sessionId)
    } catch (error) {
      logger.error('Invalidate session failed', error as Error, { sessionId })
      throw error
    }
  }
}
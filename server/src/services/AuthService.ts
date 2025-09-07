import { UserRepository } from '@/models/UserModel';
import { SessionRepository } from '@/models/SessionModel';
import { RoleRepository } from '@/models/RoleModel';
import { CryptoUtils } from '@/utils/crypto';
import { config } from '@/config/environment';
import { logger, logAuthEvent, logSecurityEvent } from '@/config/logger';
import { 
  Errors,
  InvalidCredentialsError,
  AccountLockedError,
  EmailNotVerifiedError,
  AccountDeactivatedError,
  UserAlreadyExistsError,
  TokenExpiredError,
  InvalidTokenError,
  UserNotFoundError
} from '@/utils/errors.js';
import type {
  User,
  AuthResponse,
  LoginRequest,
  RegisterRequest,
  ForgotPasswordRequest,
  ResetPasswordRequest,
  ChangePasswordRequest,
  CreateUserOptions,
  AuthContext,
  LockoutConfig
} from '@/types/auth.js';

/**
 * Account lockout configuration
 */
const LOCKOUT_CONFIG: LockoutConfig = {
  maxAttempts: 5,
  lockDuration: 15 * 60 * 1000, // 15 minutes
  resetTime: 60 * 60 * 1000 // 1 hour
};

/**
 * Authentication Service
 * Handles all authentication-related business logic
 */
export class AuthService {
  /**
   * Authenticate user with username and password
   */
  static async login(credentials: LoginRequest, ipAddress?: string, userAgent?: string): Promise<AuthResponse> {
    const { username, password, rememberMe = false } = credentials;
    
    try {
      // Find user by username
      const user = await UserRepository.findByUsername(username);
      if (!user) {
        logSecurityEvent('Login attempt with non-existent username', 'medium', {
          username,
          ipAddress,
          userAgent
        });
        throw new InvalidCredentialsError();
      }

      // Check if account is locked
      if (user.lockUntil && user.lockUntil > new Date()) {
        logSecurityEvent('Login attempt on locked account', 'high', {
          userId: user.id,
          username,
          ipAddress,
          lockUntil: user.lockUntil
        });
        throw new AccountLockedError(user.lockUntil);
      }

      // Check if account is active
      if (!user.isActive) {
        logSecurityEvent('Login attempt on deactivated account', 'medium', {
          userId: user.id,
          username,
          ipAddress
        });
        throw new AccountDeactivatedError();
      }

      // Verify password
      const isPasswordValid = await CryptoUtils.password.verifyPassword(password, user.passwordHash);
      
      if (!isPasswordValid) {
        await this.handleFailedLoginAttempt(user.id);
        logSecurityEvent('Invalid password attempt', 'medium', {
          userId: user.id,
          username,
          ipAddress,
          attempts: user.loginAttempts + 1
        });
        throw new InvalidCredentialsError();
      }

      // Check email verification if required
      if (!user.emailVerified && config.isDevelopment === false) {
        throw new EmailNotVerifiedError();
      }

      // Create session and tokens
      const sessionToken = CryptoUtils.session.generateSessionToken();
      const refreshToken = CryptoUtils.session.generateRefreshTokenForSession();
      const expiresAt = CryptoUtils.session.calculateExpiryDate(
        rememberMe ? '30d' : config.security.jwtExpiresIn
      );

      // Create session in database
      const session = await SessionRepository.createSession({
        userId: user.id,
        token: sessionToken,
        refreshToken,
        expiresAt,
        ipAddress,
        userAgent
      });

      // Get user roles and permissions
      const roles = await RoleRepository.getUserRoles(user.id);
      const permissions = await RoleRepository.getUserPermissions(user.id);

      // Generate JWT tokens
      const accessToken = CryptoUtils.token.generateAccessToken({
        sub: user.id,
        username: user.username,
        email: user.email,
        roles: roles.map(role => role.name),
        permissions: permissions.map(p => `${p.resource}:${p.action}`),
        sessionId: session.id
      });

      const jwtRefreshToken = CryptoUtils.token.generateRefreshToken({
        sub: user.id,
        sessionId: session.id,
        tokenVersion: session.version
      });

      // Update user login information
      await UserRepository.updateLastLogin(user.id);

      logAuthEvent('User login successful', user.id, {
        ipAddress,
        userAgent,
        sessionId: session.id
      });

      return {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          emailVerified: user.emailVerified,
          isActive: user.isActive,
          roles: roles.map(role => role.name),
          createdAt: user.createdAt,
          lastLoginAt: new Date()
        },
        tokens: {
          accessToken,
          refreshToken: jwtRefreshToken,
          expiresIn: Math.floor((expiresAt.getTime() - Date.now()) / 1000)
        },
        permissions: permissions.map(p => `${p.resource}:${p.action}`)
      };

    } catch (error) {
      if (error instanceof InvalidCredentialsError || 
          error instanceof AccountLockedError || 
          error instanceof AccountDeactivatedError ||
          error instanceof EmailNotVerifiedError) {
        throw error;
      }
      
      logger.error('Login error', { error, username });
      throw new Errors.InternalServer('Login failed');
    }
  }

  /**
   * Register a new user
   */
  static async register(userData: RegisterRequest, options: CreateUserOptions = {}): Promise<AuthResponse> {
    const { username, email, password, firstName, lastName } = userData;

    try {
      // Check if user already exists
      const existingUser = await UserRepository.existsByUsernameOrEmail(username, email);
      if (existingUser) {
        // Determine which field conflicts
        const existingByUsername = await UserRepository.findByUsername(username);
        const existingByEmail = await UserRepository.findByEmail(email);
        
        if (existingByUsername) {
          throw new UserAlreadyExistsError('username', username);
        }
        if (existingByEmail) {
          throw new UserAlreadyExistsError('email', email);
        }
      }

      // Hash password
      const passwordHash = await CryptoUtils.password.hashPassword(password);

      // Generate email verification token if needed
      let emailVerificationToken: string | undefined;
      if (options.sendVerificationEmail && !options.autoVerify) {
        emailVerificationToken = CryptoUtils.general.generateSecureRandomString(64);
      }

      // Create user
      const newUser = await UserRepository.create({
        username,
        email,
        passwordHash,
        emailVerified: options.autoVerify || false,
        emailVerificationToken,
        isActive: true
      }, options);

      // Assign default role if specified
      if (options.assignDefaultRole !== false) {
        const defaultRole = await RoleRepository.findRoleByName('user');
        if (defaultRole) {
          await RoleRepository.assignRoleToUser(newUser.id, defaultRole.id, newUser.id);
        }
      }

      logAuthEvent('User registration successful', newUser.id, {
        username: newUser.username,
        email: newUser.email
      });

      // Auto-login after registration
      return await this.login({ username, password });

    } catch (error) {
      if (error instanceof UserAlreadyExistsError) {
        throw error;
      }
      
      logger.error('Registration error', { error, userData: { username, email } });
      throw new Errors.InternalServer('Registration failed');
    }
  }

  /**
   * Logout user and invalidate session
   */
  static async logout(sessionId: string): Promise<void> {
    try {
      const session = await SessionRepository.findById(sessionId);
      if (!session) {
        throw new Errors.SessionNotFound();
      }

      await SessionRepository.deactivateSession(sessionId);

      logAuthEvent('User logout successful', session.userId, {
        sessionId
      });

    } catch (error) {
      logger.error('Logout error', { error, sessionId });
      throw error;
    }
  }

  /**
   * Refresh authentication tokens
   */
  static async refreshTokens(refreshToken: string): Promise<{ accessToken: string; refreshToken: string; expiresIn: number }> {
    try {
      // Verify refresh token
      const payload = CryptoUtils.token.verifyRefreshToken(refreshToken);
      
      // Find session
      const session = await SessionRepository.findById(payload.sessionId);
      if (!session || !session.isActive) {
        throw new InvalidTokenError('refresh token');
      }

      // Verify token version
      if (payload.tokenVersion !== session.version) {
        throw new InvalidTokenError('refresh token');
      }

      // Get user and verify status
      const user = await UserRepository.findById(payload.sub);
      if (!user || !user.isActive) {
        await SessionRepository.deactivateSession(session.id);
        throw new AccountDeactivatedError();
      }

      // Get user roles and permissions
      const roles = await RoleRepository.getUserRoles(user.id);
      const permissions = await RoleRepository.getUserPermissions(user.id);

      // Generate new tokens
      const newAccessToken = CryptoUtils.token.generateAccessToken({
        sub: user.id,
        username: user.username,
        email: user.email,
        roles: roles.map(role => role.name),
        permissions: permissions.map(p => `${p.resource}:${p.action}`),
        sessionId: session.id
      });

      const newRefreshToken = CryptoUtils.token.generateRefreshToken({
        sub: user.id,
        sessionId: session.id,
        tokenVersion: session.version + 1
      });

      // Update session with new tokens
      const expiresAt = CryptoUtils.session.calculateExpiryDate(config.security.jwtRefreshExpiresIn);
      await SessionRepository.updateTokens(session.id, session.token, newRefreshToken, expiresAt);

      logAuthEvent('Tokens refreshed', user.id, {
        sessionId: session.id
      });

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: Math.floor((expiresAt.getTime() - Date.now()) / 1000)
      };

    } catch (error) {
      if (error instanceof InvalidTokenError || error instanceof AccountDeactivatedError) {
        throw error;
      }
      
      logger.error('Token refresh error', { error });
      throw new Errors.InternalServer('Token refresh failed');
    }
  }

  /**
   * Initiate password reset process
   */
  static async forgotPassword(request: ForgotPasswordRequest): Promise<void> {
    const { email } = request;

    try {
      const user = await UserRepository.findByEmail(email);
      
      // Always return success to prevent email enumeration
      if (!user) {
        logger.warn('Password reset requested for non-existent email', { email });
        return;
      }

      // Generate reset token
      const resetToken = CryptoUtils.token.generatePasswordResetToken(user.id, user.email);
      const resetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      // Update user with reset token
      await UserRepository.update(user.id, {
        passwordResetToken: resetToken,
        passwordResetExpires: resetExpires
      });

      logSecurityEvent('Password reset requested', 'low', {
        userId: user.id,
        email
      });

      // TODO: Send password reset email
      // await EmailService.sendPasswordResetEmail(user.email, resetToken);

    } catch (error) {
      logger.error('Forgot password error', { error, email });
      // Don't throw error to prevent email enumeration
    }
  }

  /**
   * Reset password with token
   */
  static async resetPassword(request: ResetPasswordRequest): Promise<void> {
    const { token, newPassword } = request;

    try {
      // Verify reset token
      const payload = CryptoUtils.token.verifyPasswordResetToken(token);
      
      // Find user with valid reset token
      const user = await UserRepository.findByPasswordResetToken(token);
      if (!user || user.id !== payload.sub) {
        throw new InvalidTokenError('password reset token');
      }

      // Hash new password
      const passwordHash = await CryptoUtils.password.hashPassword(newPassword);

      // Update user password and clear reset token
      await UserRepository.update(user.id, {
        passwordHash,
        passwordResetToken: null,
        passwordResetExpires: null,
        loginAttempts: 0,
        lockUntil: null
      });

      // Deactivate all user sessions
      await SessionRepository.deactivateUserSessions(user.id);

      logSecurityEvent('Password reset completed', 'medium', {
        userId: user.id,
        email: user.email
      });

    } catch (error) {
      if (error instanceof InvalidTokenError || error instanceof TokenExpiredError) {
        throw error;
      }
      
      logger.error('Password reset error', { error });
      throw new Errors.InternalServer('Password reset failed');
    }
  }

  /**
   * Change user password (authenticated)
   */
  static async changePassword(userId: string, request: ChangePasswordRequest): Promise<void> {
    const { currentPassword, newPassword } = request;

    try {
      const user = await UserRepository.findById(userId);
      if (!user) {
        throw new UserNotFoundError();
      }

      // Verify current password
      const isCurrentPasswordValid = await CryptoUtils.password.verifyPassword(
        currentPassword, 
        user.passwordHash
      );
      
      if (!isCurrentPasswordValid) {
        throw new InvalidCredentialsError();
      }

      // Hash new password
      const passwordHash = await CryptoUtils.password.hashPassword(newPassword);

      // Update password
      await UserRepository.update(userId, { passwordHash });

      // Deactivate all other sessions except current one
      await SessionRepository.deactivateUserSessions(userId);

      logSecurityEvent('Password changed', 'medium', {
        userId,
        email: user.email
      });

    } catch (error) {
      if (error instanceof UserNotFoundError || error instanceof InvalidCredentialsError) {
        throw error;
      }
      
      logger.error('Password change error', { error, userId });
      throw new Errors.InternalServer('Password change failed');
    }
  }

  /**
   * Verify email address
   */
  static async verifyEmail(token: string): Promise<void> {
    try {
      const payload = CryptoUtils.token.verifyEmailVerificationToken(token);
      
      const user = await UserRepository.findById(payload.sub);
      if (!user) {
        throw new UserNotFoundError();
      }

      if (user.email !== payload.email) {
        throw new InvalidTokenError('email verification token');
      }

      if (user.emailVerified) {
        return; // Already verified
      }

      await UserRepository.update(user.id, {
        emailVerified: true,
        emailVerificationToken: null
      });

      logAuthEvent('Email verified', user.id, {
        email: user.email
      });

    } catch (error) {
      if (error instanceof InvalidTokenError || error instanceof UserNotFoundError) {
        throw error;
      }
      
      logger.error('Email verification error', { error });
      throw new Errors.InternalServer('Email verification failed');
    }
  }

  /**
   * Get authentication context from session
   */
  static async getAuthContext(sessionId: string): Promise<AuthContext> {
    try {
      const session = await SessionRepository.findById(sessionId);
      if (!session || !session.isActive) {
        throw new Errors.SessionNotFound();
      }

      const user = await UserRepository.findById(session.userId);
      if (!user || !user.isActive) {
        throw new AccountDeactivatedError();
      }

      const roles = await RoleRepository.getUserRoles(user.id);
      const permissions = await RoleRepository.getUserPermissions(user.id);

      return {
        user,
        session,
        roles,
        permissions
      };

    } catch (error) {
      logger.error('Get auth context error', { error, sessionId });
      throw error;
    }
  }

  /**
   * Validate session and return user info
   */
  static async validateSession(token: string): Promise<{
    user: User;
    session: any;
    permissions: string[];
  } | null> {
    try {
      const sessionData = await SessionRepository.validateSessionWithUser(token);
      if (!sessionData) {
        return null;
      }

      const permissions = await RoleRepository.getUserPermissions(sessionData.user.id);
      
      // Update last accessed time
      await SessionRepository.updateLastAccessed(sessionData.session.id);

      return {
        user: await UserRepository.findById(sessionData.user.id) as User,
        session: sessionData.session,
        permissions: permissions.map(p => `${p.resource}:${p.action}`)
      };

    } catch (error) {
      logger.error('Session validation error', { error });
      return null;
    }
  }

  /**
   * Handle failed login attempt
   */
  private static async handleFailedLoginAttempt(userId: string): Promise<void> {
    const user = await UserRepository.findById(userId);
    if (!user) return;

    const newAttempts = user.loginAttempts + 1;
    let lockUntil: Date | undefined;

    if (newAttempts >= LOCKOUT_CONFIG.maxAttempts) {
      lockUntil = new Date(Date.now() + LOCKOUT_CONFIG.lockDuration);
      
      logSecurityEvent('Account locked due to multiple failed attempts', 'high', {
        userId,
        attempts: newAttempts,
        lockUntil
      });
    }

    await UserRepository.update(userId, {
      loginAttempts: newAttempts,
      lockUntil
    });
  }

  /**
   * Clean up expired sessions
   */
  static async cleanupExpiredSessions(): Promise<number> {
    try {
      const count = await SessionRepository.cleanupExpiredSessions();
      
      if (count > 0) {
        logger.info('Cleaned up expired sessions', { count });
      }
      
      return count;
    } catch (error) {
      logger.error('Session cleanup error', { error });
      return 0;
    }
  }

  /**
   * Get user sessions
   */
  static async getUserSessions(userId: string): Promise<any[]> {
    try {
      return await SessionRepository.getUserActiveSessions(userId);
    } catch (error) {
      logger.error('Get user sessions error', { error, userId });
      throw new Errors.InternalServer('Failed to get user sessions');
    }
  }

  /**
   * Terminate specific session
   */
  static async terminateSession(sessionId: string, userId: string): Promise<void> {
    try {
      const session = await SessionRepository.findById(sessionId);
      if (!session || session.userId !== userId) {
        throw new Errors.SessionNotFound();
      }

      await SessionRepository.deactivateSession(sessionId);

      logAuthEvent('Session terminated', userId, { sessionId });

    } catch (error) {
      logger.error('Terminate session error', { error, sessionId, userId });
      throw error;
    }
  }

  /**
   * Terminate all user sessions except current
   */
  static async terminateAllOtherSessions(userId: string, currentSessionId: string): Promise<number> {
    try {
      const sessions = await SessionRepository.getUserActiveSessions(userId);
      let terminatedCount = 0;

      for (const session of sessions) {
        if (session.id !== currentSessionId) {
          await SessionRepository.deactivateSession(session.id);
          terminatedCount++;
        }
      }

      if (terminatedCount > 0) {
        logAuthEvent('Multiple sessions terminated', userId, { 
          terminatedCount,
          currentSessionId 
        });
      }

      return terminatedCount;
    } catch (error) {
      logger.error('Terminate all sessions error', { error, userId });
      throw new Errors.InternalServer('Failed to terminate sessions');
    }
  }
}
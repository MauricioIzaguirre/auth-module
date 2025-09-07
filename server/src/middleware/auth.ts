import type { Request, Response, NextFunction } from 'express';
import { CryptoUtils } from '@/utils/crypto.js';
import { AuthService } from '@/services/AuthService.js';
import { RoleRepository } from '@/models/RoleModel.js';
import { ResponseUtils } from '@/utils/response.js';
import { logger, logSecurityEvent } from '@/config/logger.js';
import {
  AuthenticationError,
  AuthorizationError,
  InvalidTokenError,
  TokenExpiredError,
  AccountDeactivatedError
} from '@/utils/errors.js';
import type { AuthenticatedUser } from '@/types/core.js';

/**
 * Extended Request interface with authentication data
 */
export interface AuthenticatedRequest extends Request {
  user: AuthenticatedUser;
  sessionId: string;
  permissions: string[];
}

/**
 * Authentication middleware
 * Validates JWT tokens and sets user context
 */
export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Extract token from Authorization header or cookies
    let token: string | null = null;
    
    const authHeader = req.headers.authorization;
    if (authHeader) {
      token = CryptoUtils.token.extractBearerToken(authHeader);
    } else if (req.cookies?.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      logSecurityEvent('Authentication attempt without token', 'low', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path
      });
      
      ResponseUtils.unauthorized(res, 'Authentication token required');
      return;
    }

    try {
      // Verify JWT token
      const payload = CryptoUtils.token.verifyAccessToken(token);
      
      // Validate session in database
      const sessionData = await AuthService.validateSession(payload.sessionId || '');
      if (!sessionData) {
        throw new InvalidTokenError('session');
      }

      // Set user context in request
      (req as AuthenticatedRequest).user = {
        id: sessionData.user.id,
        username: sessionData.user.username,
        email: sessionData.user.email,
        roles: payload.roles,
        permissions: payload.permissions,
        lastLoginAt: sessionData.user.lastLoginAt
      };
      
      (req as AuthenticatedRequest).sessionId = payload.sessionId || '';
      (req as AuthenticatedRequest).permissions = sessionData.permissions;

      next();

    } catch (error) {
      if (error instanceof TokenExpiredError) {
        logSecurityEvent('Expired token used', 'low', {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          path: req.path
        });
        
        ResponseUtils.unauthorized(res, 'Token has expired');
        return;
      }

      if (error instanceof InvalidTokenError) {
        logSecurityEvent('Invalid token used', 'medium', {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          path: req.path
        });
        
        ResponseUtils.unauthorized(res, 'Invalid authentication token');
        return;
      }

      throw error;
    }

  } catch (error) {
    logger.error('Authentication middleware error', { 
      error,
      ip: req.ip,
      path: req.path
    });
    
    ResponseUtils.error(res, new AuthenticationError('Authentication failed'));
  }
};

/**
 * Optional authentication middleware
 * Adds user context if token is present but doesn't require authentication
 */
export const optionalAuthenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Extract token from Authorization header or cookies
    let token: string | null = null;
    
    const authHeader = req.headers.authorization;
    if (authHeader) {
      token = CryptoUtils.token.extractBearerToken(authHeader);
    } else if (req.cookies?.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      next();
      return;
    }

    try {
      // Verify JWT token
      const payload = CryptoUtils.token.verifyAccessToken(token);
      
      // Validate session in database
      const sessionData = await AuthService.validateSession(payload.sessionId || '');
      if (sessionData) {
        // Set user context in request
        (req as AuthenticatedRequest).user = {
          id: sessionData.user.id,
          username: sessionData.user.username,
          email: sessionData.user.email,
          roles: payload.roles,
          permissions: payload.permissions,
          lastLoginAt: sessionData.user.lastLoginAt
        };
        
        (req as AuthenticatedRequest).sessionId = payload.sessionId || '';
        (req as AuthenticatedRequest).permissions = sessionData.permissions;
      }
    } catch (error) {
      // Ignore authentication errors in optional middleware
      logger.debug('Optional authentication failed', { error });
    }

    next();

  } catch (error) {
    logger.error('Optional authentication middleware error', { error });
    next();
  }
};

/**
 * Role-based authorization middleware
 * Requires user to have at least one of the specified roles
 */
export const authorize = (...roles: string[]) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authReq = req as AuthenticatedRequest;
      
      if (!authReq.user) {
        ResponseUtils.unauthorized(res, 'Authentication required');
        return;
      }

      const userRoles = authReq.user.roles;
      const hasRole = roles.some(role => userRoles.includes(role));

      if (!hasRole) {
        logSecurityEvent('Unauthorized role access attempt', 'medium', {
          userId: authReq.user.id,
          requiredRoles: roles,
          userRoles,
          path: req.path,
          ip: req.ip
        });
        
        ResponseUtils.forbidden(res, `Access denied. Required roles: ${roles.join(', ')}`);
        return;
      }

      next();

    } catch (error) {
      logger.error('Authorization middleware error', { error, roles });
      ResponseUtils.error(res, new AuthorizationError('Authorization failed'));
    }
  };
};

/**
 * Permission-based authorization middleware
 * Requires user to have specific permission (resource:action)
 */
export const requirePermission = (resource: string, action: string) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authReq = req as AuthenticatedRequest;
      
      if (!authReq.user) {
        ResponseUtils.unauthorized(res, 'Authentication required');
        return;
      }

      const requiredPermission = `${resource}:${action}`;
      const hasPermission = authReq.permissions.includes(requiredPermission);

      if (!hasPermission) {
        // Double-check with database (in case permissions changed)
        const dbHasPermission = await RoleRepository.userHasPermission(
          authReq.user.id,
          resource,
          action
        );

        if (!dbHasPermission) {
          logSecurityEvent('Unauthorized permission access attempt', 'medium', {
            userId: authReq.user.id,
            requiredPermission,
            userPermissions: authReq.permissions,
            path: req.path,
            ip: req.ip
          });
          
          ResponseUtils.forbidden(res, `Access denied. Required permission: ${requiredPermission}`);
          return;
        }
      }

      next();

    } catch (error) {
      logger.error('Permission middleware error', { error, resource, action });
      ResponseUtils.error(res, new AuthorizationError('Permission check failed'));
    }
  };
};

/**
 * Ownership verification middleware
 * Ensures user can only access their own resources
 */
export const requireOwnership = (userIdParam: string = 'userId') => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authReq = req as AuthenticatedRequest;
      
      if (!authReq.user) {
        ResponseUtils.unauthorized(res, 'Authentication required');
        return;
      }

      const resourceUserId = req.params[userIdParam];
      
      if (!resourceUserId) {
        ResponseUtils.error(res, new Error('User ID parameter missing'));
        return;
      }

      // Allow access if user owns the resource or has admin role
      const isOwner = authReq.user.id === resourceUserId;
      const isAdmin = authReq.user.roles.includes('admin') || authReq.user.roles.includes('super_admin');

      if (!isOwner && !isAdmin) {
        logSecurityEvent('Unauthorized ownership access attempt', 'medium', {
          userId: authReq.user.id,
          attemptedResourceUserId: resourceUserId,
          path: req.path,
          ip: req.ip
        });
        
        ResponseUtils.forbidden(res, 'Access denied. You can only access your own resources');
        return;
      }

      next();

    } catch (error) {
      logger.error('Ownership middleware error', { error, userIdParam });
      ResponseUtils.error(res, new AuthorizationError('Ownership verification failed'));
    }
  };
};

/**
 * Admin-only middleware
 */
export const requireAdmin = authorize('admin', 'super_admin');

/**
 * Super admin-only middleware
 */
export const requireSuperAdmin = authorize('super_admin');

/**
 * Account status verification middleware
 */
export const requireActiveAccount = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authReq = req as AuthenticatedRequest;
    
    if (!authReq.user) {
      ResponseUtils.unauthorized(res, 'Authentication required');
      return;
    }

    // Check if account is still active (could have been deactivated after token was issued)
    const sessionData = await AuthService.validateSession(authReq.sessionId);
    if (!sessionData || !sessionData.user.isActive) {
      logSecurityEvent('Deactivated account access attempt', 'high', {
        userId: authReq.user.id,
        sessionId: authReq.sessionId,
        path: req.path,
        ip: req.ip
      });
      
      ResponseUtils.error(res, new AccountDeactivatedError());
      return;
    }

    next();

  } catch (error) {
    logger.error('Account status middleware error', { error });
    ResponseUtils.error(res, new AuthorizationError('Account verification failed'));
  }
};

/**
 * Email verification requirement middleware
 */
export const requireEmailVerified = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authReq = req as AuthenticatedRequest;
    
    if (!authReq.user) {
      ResponseUtils.unauthorized(res, 'Authentication required');
      return;
    }

    // In development, skip email verification
    if (process.env.NODE_ENV === 'development') {
      next();
      return;
    }

    const sessionData = await AuthService.validateSession(authReq.sessionId);
    if (!sessionData || !sessionData.user.emailVerified) {
      ResponseUtils.error(res, new Error('Email verification required'));
      return;
    }

    next();

  } catch (error) {
    logger.error('Email verification middleware error', { error });
    ResponseUtils.error(res, new AuthorizationError('Email verification check failed'));
  }
};

/**
 * Rate limiting middleware for sensitive operations
 */
export const rateLimitSensitive = (windowMs: number = 15 * 60 * 1000, maxAttempts: number = 5) => {
  const attempts = new Map<string, { count: number; resetTime: number }>();

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authReq = req as AuthenticatedRequest;
      const key = authReq.user?.id || req.ip;
      const now = Date.now();

      const userAttempts = attempts.get(key);
      
      if (userAttempts) {
        if (now < userAttempts.resetTime) {
          if (userAttempts.count >= maxAttempts) {
            logSecurityEvent('Rate limit exceeded for sensitive operation', 'high', {
              userId: authReq.user?.id,
              ip: req.ip,
              path: req.path,
              attempts: userAttempts.count
            });
            
            ResponseUtils.rateLimit(res, 'Too many attempts. Please try again later.');
            return;
          }
          
          userAttempts.count++;
        } else {
          // Reset window
          attempts.set(key, { count: 1, resetTime: now + windowMs });
        }
      } else {
        attempts.set(key, { count: 1, resetTime: now + windowMs });
      }

      next();

    } catch (error) {
      logger.error('Rate limit middleware error', { error });
      next();
    }
  };
};

/**
 * Middleware composition helper
 */
export const composeMiddleware = (...middlewares: Array<(req: Request, res: Response, next: NextFunction) => void>) => {
  return (req: Request, res: Response, next: NextFunction) => {
    let index = 0;

    const dispatch = (i: number): void => {
      if (i <= index) return next(new Error('next() called multiple times'));
      index = i;
      
      let fn = middlewares[i];
      if (i === middlewares.length) fn = next as any;
      if (!fn) return next();
      
      try {
        fn(req, res, dispatch.bind(null, i + 1));
      } catch (err) {
        next(err);
      }
    };

    dispatch(0);
  };
};

/**
 * Export common middleware combinations
 */
export const authMiddleware = {
  // Basic authentication
  auth: authenticate,
  optionalAuth: optionalAuthenticate,
  
  // Role-based
  requireUser: composeMiddleware(authenticate, authorize('user')),
  requireAdmin: composeMiddleware(authenticate, requireAdmin),
  requireSuperAdmin: composeMiddleware(authenticate, requireSuperAdmin),
  
  // Permission-based
  requirePermission,
  
  // Special requirements
  requireOwnership,
  requireActiveAccount: composeMiddleware(authenticate, requireActiveAccount),
  requireEmailVerified: composeMiddleware(authenticate, requireEmailVerified),
  
  // Sensitive operations
  sensitiveOperation: composeMiddleware(authenticate, requireActiveAccount, rateLimitSensitive()),
  
  // Admin operations
  adminOperation: composeMiddleware(authenticate, requireAdmin, requireActiveAccount),
  superAdminOperation: composeMiddleware(authenticate, requireSuperAdmin, requireActiveAccount)
};
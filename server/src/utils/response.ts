import type { Response } from 'express';
import type { ApiResponse, PaginatedResult, ResponseMeta, ValidationError } from '@/types/core';
import { BaseError, ErrorUtils } from './errors';
import { logger } from '@/config/logger';
import { ErrorType, HttpStatus } from '@/types/core';

/**
 * Response utility class for standardized API responses
 */
export class ResponseUtils {
  /**
   * Send successful response
   */
  static success<T>(
    res: Response, 
    data?: T | undefined, 
    message?: string | undefined, 
    statusCode: number = 200
  ): Response {
    const response: ApiResponse<T> = {
      success: true,
      ...(data !== undefined && { data }),
      ...(message !== undefined && { message })
    };

    return res.status(statusCode).json(response);
  }

  /**
   * Send successful response with pagination
   */
  static successWithPagination<T>(
    res: Response,
    result: PaginatedResult<T>,
    message?: string | undefined,
    statusCode: number = 200
  ): Response {
    const response: ApiResponse<T[]> = {
      success: true,
      data: result.items as T[],
      ...(message !== undefined && { message }),
      meta: result.meta
    };

    return res.status(statusCode).json(response);
  }

  /**
   * Send error response
   */
  static error(
    res: Response,
    error: BaseError | Error | string,
    statusCode?: number | undefined
  ): Response {
    let appError: BaseError;
    let responseCode: number;

    if (error instanceof BaseError) {
      appError = error;
      responseCode = statusCode || appError.statusCode;
    } else {
      const message = error instanceof Error ? error.message : error;
      appError = new BaseError(
        ErrorType.INTERNAL_SERVER_ERROR,
        message,
        HttpStatus.INTERNAL_SERVER_ERROR,
        'INTERNAL_SERVER_ERROR'
      );
      responseCode = statusCode || 500;
    }

    // Log error
    const logLevel = ErrorUtils.getLogLevel(appError);
    logger[logLevel]('API Error Response', {
      error: appError.message,
      type: appError.type,
      code: appError.code,
      statusCode: responseCode,
      stack: appError.stack
    });

    const sanitizedError = ErrorUtils.sanitizeError(appError);
    const response: ApiResponse = {
      success: false,
      message: sanitizedError.message,
      errors: [{
        field: 'general',
        message: sanitizedError.message,
        code: sanitizedError.code || 'UNKNOWN_ERROR'
      }]
    };

    return res.status(responseCode).json(response);
  }

  /**
   * Send validation error response
   */
  static validationError(
    res: Response,
    errors: ValidationError[],
    message: string = 'Validation failed'
  ): Response {
    logger.warn('Validation Error Response', { errors });

    const response: ApiResponse = {
      success: false,
      message,
      errors
    };

    return res.status(422).json(response);
  }

  /**
   * Send unauthorized response
   */
  static unauthorized(
    res: Response,
    message: string = 'Authentication required'
  ): Response {
    const response: ApiResponse = {
      success: false,
      message
    };

    return res.status(401).json(response);
  }

  /**
   * Send forbidden response
   */
  static forbidden(
    res: Response,
    message: string = 'Insufficient permissions'
  ): Response {
    const response: ApiResponse = {
      success: false,
      message
    };

    return res.status(403).json(response);
  }

  /**
   * Send not found response
   */
  static notFound(
    res: Response,
    resource: string = 'Resource'
  ): Response {
    const response: ApiResponse = {
      success: false,
      message: `${resource} not found`
    };

    return res.status(404).json(response);
  }

  /**
   * Send created response
   */
  static created<T>(
    res: Response,
    data: T,
    message: string = 'Resource created successfully'
  ): Response {
    return this.success(res, data, message, 201);
  }

  /**
   * Send no content response
   */
  static noContent(res: Response): Response {
    return res.status(204).send();
  }

  /**
   * Send conflict response
   */
  static conflict(
    res: Response,
    message: string = 'Resource already exists'
  ): Response {
    const response: ApiResponse = {
      success: false,
      message
    };

    return res.status(409).json(response);
  }

  /**
   * Send rate limit response
   */
  static rateLimit(
    res: Response,
    message: string = 'Too many requests'
  ): Response {
    const response: ApiResponse = {
      success: false,
      message
    };

    return res.status(429).json(response);
  }

  /**
   * Create pagination metadata
   */
  static createPaginationMeta(
    page: number,
    limit: number,
    total: number
  ): ResponseMeta {
    const totalPages = Math.ceil(total / limit);
    
    return {
      page,
      limit,
      total,
      totalPages
    };
  }

  /**
   * Handle async route errors
   */
  static asyncHandler(
    fn: (req: any, res: Response, next: any) => Promise<any>
  ) {
    return (req: any, res: Response, next: any) => {
      Promise.resolve(fn(req, res, next)).catch(next);
    };
  }
}

/**
 * Response builder class for fluent API responses
 */
export class ResponseBuilder {
  private statusCode: number = 200;
  private data?: unknown | undefined;
  private message?: string | undefined;
  private errors?: ValidationError[] | undefined;
  private meta?: ResponseMeta | undefined;

  constructor(private res: Response) {}

  /**
   * Set status code
   */
  status(code: number): this {
    this.statusCode = code;
    return this;
  }

  /**
   * Set response data
   */
  withData<T>(data: T): this {
    this.data = data;
    return this;
  }

  /**
   * Set response message
   */
  withMessage(message: string): this {
    this.message = message;
    return this;
  }

  /**
   * Set validation errors
   */
  withErrors(errors: ValidationError[]): this {
    this.errors = errors;
    return this;
  }

  /**
   * Set pagination metadata
   */
  withMeta(meta: ResponseMeta): this {
    this.meta = meta;
    return this;
  }

  /**
   * Send success response
   */
  success(): Response {
    const response: ApiResponse = {
      success: true,
      ...(this.data !== undefined && { data: this.data }),
      ...(this.message !== undefined && { message: this.message }),
      ...(this.meta !== undefined && { meta: this.meta })
    };

    return this.res.status(this.statusCode).json(response);
  }

  /**
   * Send error response
   */
  error(): Response {
    const response: ApiResponse = {
      success: false,
      message: this.message || 'An error occurred',
      ...(this.errors !== undefined && { errors: this.errors })
    };

    return this.res.status(this.statusCode).json(response);
  }
}

/**
 * Cookie utilities for authentication
 */
export class CookieUtils {
  /**
   * Set secure HTTP-only cookie
   */
  static setSecureCookie(
    res: Response,
    name: string,
    value: string,
    maxAge: number = 24 * 60 * 60 * 1000 // 24 hours
  ): void {
    res.cookie(name, value, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge,
      path: '/'
    });
  }

  /**
   * Clear cookie
   */
  static clearCookie(res: Response, name: string): void {
    res.clearCookie(name, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/'
    });
  }

  /**
   * Set authentication cookies
   */
  static setAuthCookies(
    res: Response,
    accessToken: string,
    refreshToken: string,
    accessTokenMaxAge: number = 15 * 60 * 1000, // 15 minutes
    refreshTokenMaxAge: number = 7 * 24 * 60 * 60 * 1000 // 7 days
  ): void {
    this.setSecureCookie(res, 'accessToken', accessToken, accessTokenMaxAge);
    this.setSecureCookie(res, 'refreshToken', refreshToken, refreshTokenMaxAge);
  }

  /**
   * Clear authentication cookies
   */
  static clearAuthCookies(res: Response): void {
    this.clearCookie(res, 'accessToken');
    this.clearCookie(res, 'refreshToken');
  }
}

/**
 * Create response builder instance
 */
export const createResponseBuilder = (res: Response): ResponseBuilder => {
  return new ResponseBuilder(res);
};

/**
 * HTTP status constants for easy reference
 */
export const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  SERVICE_UNAVAILABLE: 503
} as const;

/**
 * Common success messages
 */
export const SUCCESS_MESSAGES = {
  USER_CREATED: 'User created successfully',
  USER_UPDATED: 'User updated successfully',
  USER_DELETED: 'User deleted successfully',
  LOGIN_SUCCESS: 'Login successful',
  LOGOUT_SUCCESS: 'Logout successful',
  PASSWORD_CHANGED: 'Password changed successfully',
  PASSWORD_RESET_SENT: 'Password reset instructions sent to your email',
  PASSWORD_RESET_SUCCESS: 'Password reset successfully',
  EMAIL_VERIFIED: 'Email verified successfully',
  PROFILE_UPDATED: 'Profile updated successfully',
  ROLE_ASSIGNED: 'Role assigned successfully',
  ROLE_REMOVED: 'Role removed successfully',
  PERMISSION_GRANTED: 'Permission granted successfully',
  PERMISSION_REVOKED: 'Permission revoked successfully'
} as const;

/**
 * Common error messages
 */
export const ERROR_MESSAGES = {
  INVALID_CREDENTIALS: 'Invalid username or password',
  ACCOUNT_LOCKED: 'Account is temporarily locked',
  EMAIL_NOT_VERIFIED: 'Email address must be verified',
  ACCOUNT_DEACTIVATED: 'Account has been deactivated',
  TOKEN_EXPIRED: 'Token has expired',
  INVALID_TOKEN: 'Invalid token',
  INSUFFICIENT_PERMISSIONS: 'Insufficient permissions',
  USER_NOT_FOUND: 'User not found',
  ROLE_NOT_FOUND: 'Role not found',
  PERMISSION_NOT_FOUND: 'Permission not found',
  SESSION_NOT_FOUND: 'Session not found',
  VALIDATION_FAILED: 'Validation failed',
  INTERNAL_SERVER_ERROR: 'Internal server error',
  RATE_LIMIT_EXCEEDED: 'Rate limit exceeded'
} as const;
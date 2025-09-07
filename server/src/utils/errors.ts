import { ErrorType, HttpStatus } from '@/types/core';
import type { AppError } from '@/types/core';

/**
 * Base application error class
 */
export class BaseError extends Error implements AppError {
  public readonly type: ErrorType;
  public readonly statusCode: HttpStatus;
  public readonly code?: string | undefined;
  public readonly details?: Record<string, unknown> | undefined;

  constructor(
    type: ErrorType,
    message: string,
    statusCode: HttpStatus,
    code?: string | undefined,
    details?: Record<string, unknown> | undefined
  ) {
    super(message);
    this.name = this.constructor.name;
    this.type = type;
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;

    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, BaseError.prototype);
  }
}

/**
 * Validation error - 400 Bad Request
 */
export class ValidationError extends BaseError {
  constructor(message: string, details?: Record<string, unknown> | undefined) {
    super(
      ErrorType.VALIDATION_ERROR,
      message,
      HttpStatus.BAD_REQUEST,
      'VALIDATION_ERROR',
      details
    );
  }
}

/**
 * Authentication error - 401 Unauthorized
 */
export class AuthenticationError extends BaseError {
  constructor(message: string = 'Authentication required', details?: Record<string, unknown> | undefined) {
    super(
      ErrorType.AUTHENTICATION_ERROR,
      message,
      HttpStatus.UNAUTHORIZED,
      'AUTHENTICATION_ERROR',
      details
    );
  }
}

/**
 * Authorization error - 403 Forbidden
 */
export class AuthorizationError extends BaseError {
  constructor(message: string = 'Insufficient permissions', details?: Record<string, unknown> | undefined) {
    super(
      ErrorType.AUTHORIZATION_ERROR,
      message,
      HttpStatus.FORBIDDEN,
      'AUTHORIZATION_ERROR',
      details
    );
  }
}

/**
 * Not found error - 404 Not Found
 */
export class NotFoundError extends BaseError {
  constructor(resource: string = 'Resource', details?: Record<string, unknown> | undefined) {
    super(
      ErrorType.NOT_FOUND_ERROR,
      `${resource} not found`,
      HttpStatus.NOT_FOUND,
      'NOT_FOUND_ERROR',
      details
    );
  }
}

/**
 * Conflict error - 409 Conflict
 */
export class ConflictError extends BaseError {
  constructor(message: string, details?: Record<string, unknown> | undefined) {
    super(
      ErrorType.CONFLICT_ERROR,
      message,
      HttpStatus.CONFLICT,
      'CONFLICT_ERROR',
      details
    );
  }
}

/**
 * Rate limit error - 429 Too Many Requests
 */
export class RateLimitError extends BaseError {
  constructor(message: string = 'Too many requests', details?: Record<string, unknown> | undefined) {
    super(
      ErrorType.RATE_LIMIT_ERROR,
      message,
      HttpStatus.TOO_MANY_REQUESTS,
      'RATE_LIMIT_ERROR',
      details
    );
  }
}

/**
 * Database error - 500 Internal Server Error
 */
export class DatabaseError extends BaseError {
  constructor(message: string = 'Database operation failed', details?: Record<string, unknown> | undefined) {
    super(
      ErrorType.DATABASE_ERROR,
      message,
      HttpStatus.INTERNAL_SERVER_ERROR,
      'DATABASE_ERROR',
      details
    );
  }
}

/**
 * External service error - 502/503 Service Unavailable
 */
export class ExternalServiceError extends BaseError {
  constructor(
    service: string,
    message: string = 'External service unavailable',
    details?: Record<string, unknown> | undefined
  ) {
    super(
      ErrorType.EXTERNAL_SERVICE_ERROR,
      `${service}: ${message}`,
      HttpStatus.SERVICE_UNAVAILABLE,
      'EXTERNAL_SERVICE_ERROR',
      { service, ...details }
    );
  }
}

/**
 * Internal server error - 500 Internal Server Error
 */
export class InternalServerError extends BaseError {
  constructor(message: string = 'Internal server error', details?: Record<string, unknown> | undefined) {
    super(
      ErrorType.INTERNAL_SERVER_ERROR,
      message,
      HttpStatus.INTERNAL_SERVER_ERROR,
      'INTERNAL_SERVER_ERROR',
      details
    );
  }
}

/**
 * Specific authentication-related errors
 */
export class InvalidCredentialsError extends AuthenticationError {
  constructor() {
    super('Invalid username or password', { reason: 'invalid_credentials' });
  }
}

export class AccountLockedError extends AuthenticationError {
  constructor(lockUntil?: Date | undefined) {
    super('Account is temporarily locked due to multiple failed login attempts', {
      reason: 'account_locked',
      lockUntil: lockUntil?.toISOString()
    });
  }
}

export class TokenExpiredError extends AuthenticationError {
  constructor(tokenType: string = 'token') {
    super(`${tokenType} has expired`, { reason: 'token_expired' });
  }
}

export class InvalidTokenError extends AuthenticationError {
  constructor(tokenType: string = 'token') {
    super(`Invalid ${tokenType}`, { reason: 'invalid_token' });
  }
}

export class EmailNotVerifiedError extends AuthenticationError {
  constructor() {
    super('Email address must be verified', { reason: 'email_not_verified' });
  }
}

export class AccountDeactivatedError extends AuthenticationError {
  constructor() {
    super('Account has been deactivated', { reason: 'account_deactivated' });
  }
}

/**
 * Resource-specific errors
 */
export class UserNotFoundError extends NotFoundError {
  constructor(identifier?: string | undefined) {
    super('User', { identifier });
  }
}

export class RoleNotFoundError extends NotFoundError {
  constructor(identifier?: string | undefined) {
    super('Role', { identifier });
  }
}

export class PermissionNotFoundError extends NotFoundError {
  constructor(identifier?: string | undefined) {
    super('Permission', { identifier });
  }
}

export class SessionNotFoundError extends NotFoundError {
  constructor() {
    super('Session');
  }
}

/**
 * Business logic errors
 */
export class UserAlreadyExistsError extends ConflictError {
  constructor(field: string, value: string) {
    super(`User with this ${field} already exists`, { field, value });
  }
}

export class RoleAlreadyAssignedError extends ConflictError {
  constructor() {
    super('Role is already assigned to this user');
  }
}

export class PermissionAlreadyAssignedError extends ConflictError {
  constructor() {
    super('Permission is already assigned to this role');
  }
}

export class CannotDeleteSystemRoleError extends ConflictError {
  constructor() {
    super('Cannot delete system roles');
  }
}

export class WeakPasswordError extends ValidationError {
  constructor(requirements: string[]) {
    super('Password does not meet security requirements', { requirements });
  }
}

/**
 * Error utility functions
 */
export class ErrorUtils {
  /**
   * Check if error is an application error
   */
  static isAppError(error: unknown): error is BaseError {
    return error instanceof BaseError;
  }

  /**
   * Extract error message safely
   */
  static getErrorMessage(error: unknown): string {
    if (error instanceof Error) {
      return error.message;
    }
    if (typeof error === 'string') {
      return error;
    }
    return 'An unknown error occurred';
  }

  /**
   * Create error response object
   */
  static createErrorResponse(error: BaseError) {
    return {
      success: false,
      error: {
        type: error.type,
        message: error.message,
        code: error.code,
        details: error.details
      }
    };
  }

  /**
   * Sanitize error for client response (remove sensitive information)
   */
  static sanitizeError(error: BaseError): AppError {
    // In production, don't expose database errors or internal details
    if (process.env.NODE_ENV === 'production') {
      if (error.type === ErrorType.DATABASE_ERROR) {
        return {
          type: ErrorType.INTERNAL_SERVER_ERROR,
          message: 'Internal server error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          code: 'INTERNAL_SERVER_ERROR'
        };
      }

      // Remove stack trace and sensitive details in production
      return {
        type: error.type,
        message: error.message,
        statusCode: error.statusCode,
        code: error.code,
        details: error.details
      };
    }

    // In development, return full error details
    return {
      type: error.type,
      message: error.message,
      statusCode: error.statusCode,
      code: error.code,
      details: error.details,
      stack: error.stack
    };
  }

  /**
   * Log error with appropriate level
   */
  static getLogLevel(error: BaseError): 'error' | 'warn' | 'info' {
    switch (error.statusCode) {
      case HttpStatus.INTERNAL_SERVER_ERROR:
      case HttpStatus.SERVICE_UNAVAILABLE:
        return 'error';
      case HttpStatus.BAD_REQUEST:
      case HttpStatus.NOT_FOUND:
      case HttpStatus.CONFLICT:
        return 'warn';
      case HttpStatus.UNAUTHORIZED:
      case HttpStatus.FORBIDDEN:
      case HttpStatus.TOO_MANY_REQUESTS:
        return 'info';
      default:
        return 'warn';
    }
  }

  /**
   * Convert database constraint errors to application errors
   */
  static fromDatabaseError(error: any): BaseError {
    // PostgreSQL error codes
    if (error.code === '23505') { // unique_violation
      const detail = error.detail || '';
      if (detail.includes('username')) {
        return new UserAlreadyExistsError('username', 'provided username');
      }
      if (detail.includes('email')) {
        return new UserAlreadyExistsError('email', 'provided email');
      }
      return new ConflictError('Resource already exists');
    }

    if (error.code === '23503') { // foreign_key_violation
      return new ValidationError('Referenced resource does not exist');
    }

    if (error.code === '23514') { // check_violation
      return new ValidationError('Data validation failed');
    }

    // Connection errors
    if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
      return new DatabaseError('Database connection failed');
    }

    // Default database error
    return new DatabaseError(error.message || 'Database operation failed');
  }

  /**
   * Convert validation errors to application errors
   */
  static fromValidationErrors(errors: Array<{ field: string; message: string }>): ValidationError {
    const details = errors.reduce((acc, err) => {
      acc[err.field] = err.message;
      return acc;
    }, {} as Record<string, string>);

    return new ValidationError('Validation failed', details);
  }
}

/**
 * Export error classes for easy access
 */
export const Errors = {
  Base: BaseError,
  Validation: ValidationError,
  Authentication: AuthenticationError,
  Authorization: AuthorizationError,
  NotFound: NotFoundError,
  Conflict: ConflictError,
  RateLimit: RateLimitError,
  Database: DatabaseError,
  ExternalService: ExternalServiceError,
  InternalServer: InternalServerError,
  
  // Specific errors
  InvalidCredentials: InvalidCredentialsError,
  AccountLocked: AccountLockedError,
  TokenExpired: TokenExpiredError,
  InvalidToken: InvalidTokenError,
  EmailNotVerified: EmailNotVerifiedError,
  AccountDeactivated: AccountDeactivatedError,
  UserNotFound: UserNotFoundError,
  RoleNotFound: RoleNotFoundError,
  PermissionNotFound: PermissionNotFoundError,
  SessionNotFound: SessionNotFoundError,
  UserAlreadyExists: UserAlreadyExistsError,
  RoleAlreadyAssigned: RoleAlreadyAssignedError,
  PermissionAlreadyAssigned: PermissionAlreadyAssignedError,
  CannotDeleteSystemRole: CannotDeleteSystemRoleError,
  WeakPassword: WeakPasswordError
} as const;
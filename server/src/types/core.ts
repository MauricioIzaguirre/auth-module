// Core types for the authentication module

/** Base entity interface that all entities extend */
export interface BaseEntity {
  readonly id: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

/** Database entity with additional metadata */
export interface DatabaseEntity extends BaseEntity {
  readonly version: number;
  readonly deletedAt?: Date | null;
}

/** Standard API response structure */
export interface ApiResponse<T = unknown> {
  readonly success: boolean;
  readonly data?: T;
  readonly message?: string;
  readonly errors?: ValidationError[];
  readonly meta?: ResponseMeta;
}

/** Pagination metadata */
export interface ResponseMeta {
  readonly page: number;
  readonly limit: number;
  readonly total: number;
  readonly totalPages: number;
}

/** Validation error structure */
export interface ValidationError {
  readonly field: string;
  readonly message: string;
  readonly code: string;
  readonly value?: unknown;
}

/** Generic paginated result */
export interface PaginatedResult<T> {
  readonly items: readonly T[];
  readonly meta: ResponseMeta;
}

/** Query parameters for pagination */
export interface PaginationQuery {
  readonly page?: number;
  readonly limit?: number;
  readonly sortBy?: string;
  readonly sortOrder?: 'ASC' | 'DESC';
}

/** Filter parameters */
export interface FilterQuery {
  readonly search?: string;
  readonly status?: string;
  readonly createdFrom?: Date;
  readonly createdTo?: Date;
}

/** Combined query parameters */
export interface QueryParams extends PaginationQuery, FilterQuery {
  readonly [key: string]: unknown;
}

/** Request with authenticated user */
export interface AuthenticatedRequest {
  readonly user: AuthenticatedUser;
  readonly sessionId: string;
  readonly permissions: readonly string[];
}

/** Authenticated user information */
export interface AuthenticatedUser {
  readonly id: string;
  readonly username: string;
  readonly email: string;
  readonly roles: readonly string[];
  readonly permissions: readonly string[];
  readonly lastLoginAt?: Date;
}

/** Environment configuration type */
export type Environment = 'development' | 'testing' | 'staging' | 'production';

/** Log levels */
export type LogLevel = 'error' | 'warn' | 'info' | 'debug';

/** HTTP status codes */
export enum HttpStatus {
  OK = 200,
  CREATED = 201,
  NO_CONTENT = 204,
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  CONFLICT = 409,
  UNPROCESSABLE_ENTITY = 422,
  TOO_MANY_REQUESTS = 429,
  INTERNAL_SERVER_ERROR = 500,
  SERVICE_UNAVAILABLE = 503
}

/** Generic error types */
export enum ErrorType {
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  AUTHENTICATION_ERROR = 'AUTHENTICATION_ERROR',
  AUTHORIZATION_ERROR = 'AUTHORIZATION_ERROR',
  NOT_FOUND_ERROR = 'NOT_FOUND_ERROR',
  CONFLICT_ERROR = 'CONFLICT_ERROR',
  RATE_LIMIT_ERROR = 'RATE_LIMIT_ERROR',
  DATABASE_ERROR = 'DATABASE_ERROR',
  EXTERNAL_SERVICE_ERROR = 'EXTERNAL_SERVICE_ERROR',
  INTERNAL_SERVER_ERROR = 'INTERNAL_SERVER_ERROR'
}

/** Custom application error */
export interface AppError {
  readonly type: ErrorType;
  readonly message: string;
  readonly statusCode: HttpStatus;
  readonly code?: string;
  readonly details?: Record<string, unknown>;
  readonly stack?: string;
}

/** Database connection configuration */
export interface DatabaseConfig {
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly username: string;
  readonly password: string;
  readonly maxConnections: number;
  readonly minConnections: number;
  readonly idleTimeout: number;
  readonly connectionTimeout: number;
  readonly ssl?: boolean;
}

/** JWT configuration */
export interface JwtConfig {
  readonly secret: string;
  readonly expiresIn: string;
  readonly refreshSecret: string;
  readonly refreshExpiresIn: string;
  readonly issuer?: string;
  readonly audience?: string;
}

/** Rate limiting configuration */
export interface RateLimitConfig {
  readonly windowMs: number;
  readonly maxRequests: number;
  readonly skipSuccessfulRequests?: boolean;
  readonly skipFailedRequests?: boolean;
}
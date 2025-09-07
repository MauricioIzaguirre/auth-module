import type { DatabaseEntity, BaseEntity } from './core.js';

/** User entity structure */
export interface User extends DatabaseEntity {
  readonly username: string;
  readonly email: string;
  readonly passwordHash: string;
  readonly emailVerified: boolean;
  readonly emailVerificationToken: string | null;
  readonly passwordResetToken: string | null;
  readonly passwordResetExpires: Date | null;
  readonly lastLoginAt: Date | null;
  readonly loginAttempts: number;
  readonly lockUntil: Date | null;
  readonly isActive: boolean;
  readonly profile?: UserProfile | null;
}

/** User profile information */
export interface UserProfile extends BaseEntity {
  readonly userId: string;
  readonly firstName: string | null;
  readonly lastName: string | null;
  readonly avatar: string | null;
  readonly phone: string | null;
  readonly dateOfBirth: Date | null;
  readonly address: Address | null;
  readonly preferences?: UserPreferences;
}

/** User address information */
export interface Address {
  readonly street: string;
  readonly city: string;
  readonly state: string;
  readonly postalCode: string;
  readonly country: string;
}

/** User preferences */
export interface UserPreferences {
  readonly language: string;
  readonly timezone: string;
  readonly theme: 'light' | 'dark' | 'system';
  readonly notifications: NotificationSettings;
}

/** Notification settings */
export interface NotificationSettings {
  readonly email: boolean;
  readonly push: boolean;
  readonly sms: boolean;
}

/** Role entity */
export interface Role extends DatabaseEntity {
  readonly name: string;
  readonly description: string | null;
  readonly isSystem: boolean;
  readonly permissions: readonly Permission[];
}

/** Permission entity */
export interface Permission extends DatabaseEntity {
  readonly name: string;
  readonly resource: string;
  readonly action: string;
  readonly description: string | null;
}

/** User-Role relationship */
export interface UserRole extends BaseEntity {
  readonly userId: string;
  readonly roleId: string;
  readonly assignedBy: string;
  readonly assignedAt: Date;
  readonly expiresAt: Date | null;
}

/** Session entity */
export interface Session extends DatabaseEntity {
  readonly userId: string;
  readonly token: string;
  readonly refreshToken: string;
  readonly expiresAt: Date;
  readonly ipAddress: string | null;
  readonly userAgent: string | null;
  readonly isActive: boolean;
  readonly lastAccessedAt: Date;
}

/** Login request DTO */
export interface LoginRequest {
  readonly username: string;
  readonly password: string;
  readonly rememberMe?: boolean;
}

/** Register request DTO */
export interface RegisterRequest {
  readonly username: string;
  readonly email: string;
  readonly password: string;
  readonly confirmPassword: string;
  readonly firstName?: string;
  readonly lastName?: string;
  readonly acceptTerms: boolean;
}

/** Forgot password request DTO */
export interface ForgotPasswordRequest {
  readonly email: string;
}

/** Reset password request DTO */
export interface ResetPasswordRequest {
  readonly token: string;
  readonly newPassword: string;
  readonly confirmPassword: string;
}

/** Change password request DTO */
export interface ChangePasswordRequest {
  readonly currentPassword: string;
  readonly newPassword: string;
  readonly confirmPassword: string;
}

/** Update profile request DTO */
export interface UpdateProfileRequest {
  readonly firstName?: string;
  readonly lastName?: string;
  readonly phone?: string;
  readonly dateOfBirth?: Date;
  readonly address?: Partial<Address>;
  readonly preferences?: Partial<UserPreferences>;
}

/** Authentication response DTO */
export interface AuthResponse {
  readonly user: PublicUser;
  readonly tokens: TokenPair;
  readonly permissions: readonly string[];
}

/** Token pair */
export interface TokenPair {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresIn: number;
}

/** Public user data (without sensitive information) */
export interface PublicUser {
  readonly id: string;
  readonly username: string;
  readonly email: string;
  readonly emailVerified: boolean;
  readonly isActive: boolean;
  readonly roles: readonly string[];
  readonly profile?: PublicUserProfile;
  readonly createdAt: Date;
  readonly lastLoginAt: Date | null;
}

/** Public user profile (without sensitive information) */
export interface PublicUserProfile {
  readonly firstName: string | null;
  readonly lastName: string | null;
  readonly avatar: string | null;
  readonly preferences?: UserPreferences;
}

/** JWT payload structure */
export interface JwtPayload {
  readonly sub: string; // user id
  readonly username: string;
  readonly email: string;
  readonly roles: readonly string[];
  readonly permissions: readonly string[];
  readonly sessionId: string;
  readonly iat: number;
  readonly exp: number;
  readonly iss?: string;
  readonly aud?: string;
}

/** Refresh token payload */
export interface RefreshTokenPayload {
  readonly sub: string; // user id
  readonly sessionId: string;
  readonly tokenVersion: number;
  readonly iat: number;
  readonly exp: number;
}

/** Password reset token payload */
export interface PasswordResetTokenPayload {
  readonly sub: string; // user id
  readonly email: string;
  readonly type: 'password-reset';
  readonly iat: number;
  readonly exp: number;
}

/** Email verification token payload */
export interface EmailVerificationTokenPayload {
  readonly sub: string; // user id
  readonly email: string;
  readonly type: 'email-verification';
  readonly iat: number;
  readonly exp: number;
}

/** User creation options */
export interface CreateUserOptions {
  readonly sendVerificationEmail?: boolean;
  readonly autoVerify?: boolean;
  readonly assignDefaultRole?: boolean;
}

/** Password validation rules */
export interface PasswordRules {
  readonly minLength: number;
  readonly requireUppercase: boolean;
  readonly requireLowercase: boolean;
  readonly requireNumbers: boolean;
  readonly requireSpecialChars: boolean;
  readonly maxLength?: number;
}

/** Account lockout configuration */
export interface LockoutConfig {
  readonly maxAttempts: number;
  readonly lockDuration: number; // in milliseconds
  readonly resetTime: number; // in milliseconds
}

/** Authentication context */
export interface AuthContext {
  readonly user: User;
  readonly session: Session;
  readonly permissions: readonly Permission[];
  readonly roles: readonly Role[];
}
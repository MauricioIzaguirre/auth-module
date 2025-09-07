import { z } from 'zod';
import type { 
  LoginRequest,
  RegisterRequest,
  ForgotPasswordRequest,
  ResetPasswordRequest,
  ChangePasswordRequest,
  UpdateProfileRequest,
  PasswordRules 
} from '@/types/auth.js';
import type { ValidationError } from '@/types/core.js';

/**
 * Password validation rules configuration
 */
export const DEFAULT_PASSWORD_RULES: PasswordRules = {
  minLength: 8,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true
};

/**
 * Create password validation schema based on rules
 */
function createPasswordSchema(rules: PasswordRules = DEFAULT_PASSWORD_RULES) {
  let schema = z.string().min(rules.minLength, {
    message: `Password must be at least ${rules.minLength} characters long`
  });

  if (rules.maxLength) {
    schema = schema.max(rules.maxLength, {
      message: `Password must not exceed ${rules.maxLength} characters`
    });
  }

  return schema.refine((password) => {
    const errors: string[] = [];

    if (rules.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('at least one uppercase letter');
    }

    if (rules.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('at least one lowercase letter');
    }

    if (rules.requireNumbers && !/\d/.test(password)) {
      errors.push('at least one number');
    }

    if (rules.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('at least one special character');
    }

    return errors.length === 0;
  }, {
    message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
  });
}

/**
 * Username validation schema
 */
const usernameSchema = z
  .string()
  .min(3, 'Username must be at least 3 characters long')
  .max(30, 'Username must not exceed 30 characters')
  .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, hyphens, and underscores')
  .refine((username) => !username.includes('admin'), 'Username cannot contain "admin"');

/**
 * Email validation schema
 */
const emailSchema = z
  .string()
  .email('Invalid email address')
  .max(255, 'Email must not exceed 255 characters')
  .toLowerCase();

/**
 * Login request validation schema
 */
export const loginSchema = z.object({
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
  rememberMe: z.boolean().optional().default(false)
}) satisfies z.ZodSchema<LoginRequest>;

/**
 * Register request validation schema
 */
export const registerSchema = z.object({
  username: usernameSchema,
  email: emailSchema,
  password: createPasswordSchema(),
  confirmPassword: z.string(),
  firstName: z.string().max(50, 'First name must not exceed 50 characters'),
  lastName: z.string().max(50, 'Last name must not exceed 50 characters'),
  acceptTerms: z.boolean().refine(val => val === true, 'You must accept the terms and conditions')
}).refine(data => data.password === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword']
}) satisfies z.ZodSchema<RegisterRequest>;

/**
 * Forgot password request validation schema
 */
export const forgotPasswordSchema = z.object({
  email: emailSchema
}) satisfies z.ZodSchema<ForgotPasswordRequest>;

/**
 * Reset password request validation schema
 */
export const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Reset token is required'),
  newPassword: createPasswordSchema(),
  confirmPassword: z.string()
}).refine(data => data.newPassword === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword']
}) satisfies z.ZodSchema<ResetPasswordRequest>;

/**
 * Change password request validation schema
 */
export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: createPasswordSchema(),
  confirmPassword: z.string()
}).refine(data => data.newPassword === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword']
}).refine(data => data.currentPassword !== data.newPassword, {
  message: 'New password must be different from current password',
  path: ['newPassword']
}) satisfies z.ZodSchema<ChangePasswordRequest>;

/**
 * Update profile request validation schema
 */
export const updateProfileSchema = z.object({
    firstName: z.string().max(50, 'First name must not exceed 50 characters'),
    lastName: z.string().max(50, 'Last name must not exceed 50 characters'),
    phone: z.string()
        .regex(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number format'),
    dateOfBirth: z.coerce.date()
        .max(new Date(), 'Date of birth cannot be in the future'),
    address: z.object({
        street: z.string().max(255, 'Street must not exceed 255 characters'),
        city: z.string().max(100, 'City must not exceed 100 characters'),
        state: z.string().max(100, 'State must not exceed 100 characters'),
        postalCode: z.string().max(20, 'Postal code must not exceed 20 characters'),
        country: z.string().max(100, 'Country must not exceed 100 characters')
    }),
    preferences: z.object({
        language: z.string().max(10, 'Language must not exceed 10 characters'),
        timezone: z.string().max(50, 'Timezone must not exceed 50 characters'),
        theme: z.enum(['light', 'dark', 'system']),
        notifications: z.object({
            email: z.boolean(),
            push: z.boolean(),
            sms: z.boolean()
        })
    })
}) satisfies z.ZodSchema<UpdateProfileRequest>;

/**
 * Pagination query validation schema
 */
export const paginationSchema = z.object({
  page: z.coerce.number().min(1, 'Page must be at least 1').default(1),
  limit: z.coerce.number().min(1).max(100, 'Limit must be between 1 and 100').default(10),
  sortBy: z.string().max(50, 'Sort field must not exceed 50 characters').optional(),
  sortOrder: z.enum(['ASC', 'DESC']).default('DESC'),
  search: z.string().max(255, 'Search term must not exceed 255 characters').optional(),
  status: z.string().max(20, 'Status must not exceed 20 characters').optional()
});

/**
 * UUID validation schema
 */
export const uuidSchema = z.string().uuid('Invalid UUID format');

/**
 * Role creation validation schema
 */
export const createRoleSchema = z.object({
  name: z.string()
    .min(1, 'Role name is required')
    .max(50, 'Role name must not exceed 50 characters')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Role name can only contain letters, numbers, hyphens, and underscores'),
  description: z.string().max(255, 'Description must not exceed 255 characters').optional(),
  isSystem: z.boolean().default(false)
});

/**
 * Permission creation validation schema
 */
export const createPermissionSchema = z.object({
  name: z.string()
    .min(1, 'Permission name is required')
    .max(100, 'Permission name must not exceed 100 characters'),
  resource: z.string()
    .min(1, 'Resource is required')
    .max(50, 'Resource must not exceed 50 characters')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Resource can only contain letters, numbers, hyphens, and underscores'),
  action: z.string()
    .min(1, 'Action is required')
    .max(20, 'Action must not exceed 20 characters')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Action can only contain letters, numbers, hyphens, and underscores'),
  description: z.string().max(255, 'Description must not exceed 255 characters').optional()
});

/**
 * Role assignment validation schema
 */
export const assignRoleSchema = z.object({
  userId: uuidSchema,
  roleId: uuidSchema,
  expiresAt: z.coerce.date().min(new Date(), 'Expiry date must be in the future').optional()
});

/**
 * Validation utility class
 */
export class ValidationUtils {
  /**
   * Validate data against a schema and return formatted errors
   */
  static validate<T>(schema: z.ZodSchema<T>, data: unknown): {
    success: boolean;
    data?: T;
    errors?: ValidationError[];
  } {
    try {
      const result = schema.safeParse(data);
      
      if (result.success) {
        return {
          success: true,
          data: result.data
        };
      }

      const errors: ValidationError[] = result.error.issues.map(issue => ({
        field: issue.path.join('.'),
        message: issue.message,
        code: issue.code,
        value: issue.path.reduce((obj: any, key) => obj?.[key], data)
      }));

      return {
        success: false,
        errors
      };
    } catch (error) {
      return {
        success: false,
        errors: [{
          field: 'unknown',
          message: 'Validation failed',
          code: 'unknown_error'
        }]
      };
    }
  }

  /**
   * Sanitize string input
   */
  static sanitizeString(input: string): string {
    return input.trim().replace(/[<>]/g, '');
  }

  /**
   * Validate if string is a valid UUID
   */
  static isValidUUID(uuid: string): boolean {
    const result = uuidSchema.safeParse(uuid);
    return result.success;
  }

  /**
   * Validate if string is a valid email
   */
  static isValidEmail(email: string): boolean {
    const result = emailSchema.safeParse(email);
    return result.success;
  }

  /**
   * Check password strength
   */
  static checkPasswordStrength(password: string, rules: PasswordRules = DEFAULT_PASSWORD_RULES): {
    isValid: boolean;
    score: number;
    feedback: string[];
  } {
    const feedback: string[] = [];
    let score = 0;

    // Length check
    if (password.length >= rules.minLength) {
      score += 1;
    } else {
      feedback.push(`Password must be at least ${rules.minLength} characters long`);
    }

    // Character variety checks
    if (rules.requireUppercase && /[A-Z]/.test(password)) {
      score += 1;
    } else if (rules.requireUppercase) {
      feedback.push('Add uppercase letters');
    }

    if (rules.requireLowercase && /[a-z]/.test(password)) {
      score += 1;
    } else if (rules.requireLowercase) {
      feedback.push('Add lowercase letters');
    }

    if (rules.requireNumbers && /\d/.test(password)) {
      score += 1;
    } else if (rules.requireNumbers) {
      feedback.push('Add numbers');
    }

    if (rules.requireSpecialChars && /[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      score += 1;
    } else if (rules.requireSpecialChars) {
      feedback.push('Add special characters');
    }

    // Additional scoring for length
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;

    const maxScore = 7;
    const normalizedScore = Math.min(score / maxScore * 100, 100);

    return {
      isValid: feedback.length === 0,
      score: Math.round(normalizedScore),
      feedback
    };
  }

  /**
   * Validate if username is available format
   */
  static validateUsernameFormat(username: string): {
    isValid: boolean;
    errors: string[];
  } {
    const result = usernameSchema.safeParse(username);
    
    if (result.success) {
      return { isValid: true, errors: [] };
    }

    return {
      isValid: false,
      errors: result.error.issues.map(issue => issue.message)
    };
  }

  /**
   * Clean and validate search query
   */
  static sanitizeSearchQuery(query: string, maxLength: number = 255): string {
    return query
      .trim()
      .slice(0, maxLength)
      .replace(/[<>]/g, '')
      .replace(/[%_]/g, '\\$&'); // Escape SQL wildcards
  }
}

/**
 * Export validation schemas for use in controllers
 */
export const validationSchemas = {
  login: loginSchema,
  register: registerSchema,
  forgotPassword: forgotPasswordSchema,
  resetPassword: resetPasswordSchema,
  changePassword: changePasswordSchema,
  updateProfile: updateProfileSchema,
  pagination: paginationSchema,
  uuid: uuidSchema,
  createRole: createRoleSchema,
  createPermission: createPermissionSchema,
  assignRole: assignRoleSchema
} as const;
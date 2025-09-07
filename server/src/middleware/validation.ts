import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { ValidationUtils } from '@/utils/validation.js';
import { ResponseUtils } from '@/utils/response.js';
import { logger } from '@/config/logger.js';
import type { ValidationError } from '@/types/core.js';

/**
 * Validation target types
 */
type ValidationType = 'body' | 'query' | 'params' | 'headers';

/**
 * Create validation middleware for specific schema and target
 */
export const validate = <T>(schema: z.ZodSchema<T>, target: ValidationType = 'body') => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const data = req[target];
      const result = ValidationUtils.validate(schema, data);

      if (!result.success) {
        logger.warn('Validation failed', {
          target,
          errors: result.errors,
          path: req.path,
          method: req.method
        });

        ResponseUtils.validationError(res, result.errors || []);
        return;
      }

      // Replace original data with validated/transformed data
      (req as any)[target] = result.data;
      next();

    } catch (error) {
      logger.error('Validation middleware error', { error, target });
      ResponseUtils.error(res, new Error('Validation failed'));
    }
  };
};

/**
 * Body validation middleware
 */
export const validateBody = <T>(schema: z.ZodSchema<T>) => validate(schema, 'body');

/**
 * Query validation middleware
 */
export const validateQuery = <T>(schema: z.ZodSchema<T>) => validate(schema, 'query');

/**
 * Params validation middleware
 */
export const validateParams = <T>(schema: z.ZodSchema<T>) => validate(schema, 'params');

/**
 * Headers validation middleware
 */
export const validateHeaders = <T>(schema: z.ZodSchema<T>) => validate(schema, 'headers');

/**
 * Sanitize request data middleware
 */
export const sanitize = (target: ValidationType = 'body') => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const data = req[target];
      
      if (data && typeof data === 'object') {
        const sanitized = sanitizeObject(data);
        (req as any)[target] = sanitized;
      }

      next();
    } catch (error) {
      logger.error('Sanitization middleware error', { error, target });
      next();
    }
  };
};

/**
 * Recursively sanitize object properties
 */
function sanitizeObject(obj: any): any {
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item));
  }

  if (obj && typeof obj === 'object') {
    const sanitized: any = {};
    
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string') {
        sanitized[key] = ValidationUtils.sanitizeString(value);
      } else {
        sanitized[key] = sanitizeObject(value);
      }
    }
    
    return sanitized;
  }

  return obj;
}

/**
 * File upload validation middleware
 */
export const validateFileUpload = (options: {
  maxSize?: number;
  allowedTypes?: string[];
  required?: boolean;
} = {}) => {
  const { maxSize = 5 * 1024 * 1024, allowedTypes = [], required = false } = options;

  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const files = req.files as Express.Multer.File[] | undefined;
      const file = req.file as Express.Multer.File | undefined;

      if (required && !file && (!files || files.length === 0)) {
        const error: ValidationError = {
          field: 'file',
          message: 'File upload is required',
          code: 'required'
        };
        
        ResponseUtils.validationError(res, [error]);
        return;
      }

      const filesToValidate = file ? [file] : (files || []);
      const errors: ValidationError[] = [];

      for (const uploadedFile of filesToValidate) {
        // Check file size
        if (uploadedFile.size > maxSize) {
          errors.push({
            field: 'file',
            message: `File size must not exceed ${Math.round(maxSize / (1024 * 1024))}MB`,
            code: 'file_too_large',
            value: uploadedFile.size
          });
        }

        // Check file type
        if (allowedTypes.length > 0 && !allowedTypes.includes(uploadedFile.mimetype)) {
          errors.push({
            field: 'file',
            message: `File type not allowed. Allowed types: ${allowedTypes.join(', ')}`,
            code: 'invalid_file_type',
            value: uploadedFile.mimetype
          });
        }
      }

      if (errors.length > 0) {
        ResponseUtils.validationError(res, errors);
        return;
      }

      next();
    } catch (error) {
      logger.error('File validation middleware error', { error });
      ResponseUtils.error(res, new Error('File validation failed'));
    }
  };
};

/**
 * Custom validation middleware factory
 */
export const customValidation = (
  validator: (data: any) => Promise<ValidationError[]> | ValidationError[],
  target: ValidationType = 'body'
) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const data = req[target];
      const errors = await Promise.resolve(validator(data));

      if (errors.length > 0) {
        ResponseUtils.validationError(res, errors);
        return;
      }

      next();
    } catch (error) {
      logger.error('Custom validation middleware error', { error, target });
      ResponseUtils.error(res, new Error('Validation failed'));
    }
  };
};

/**
 * Pagination validation middleware
 */
export const validatePagination = validateQuery(z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(10),
  sortBy: z.string().max(50).optional(),
  sortOrder: z.enum(['ASC', 'DESC']).default('DESC'),
  search: z.string().max(255).optional()
}));

/**
 * ID parameter validation middleware
 */
export const validateId = (paramName: string = 'id') => {
  const schema = z.object({
    [paramName]: z.string().uuid('Invalid ID format')
  });
  
  return validateParams(schema);
};

/**
 * Multiple ID validation middleware
 */
export const validateIds = (paramName: string = 'ids') => {
  return validateBody(z.object({
    [paramName]: z.array(z.string().uuid('Invalid ID format')).min(1, 'At least one ID is required')
  }));
};

/**
 * Email validation middleware
 */
export const validateEmail = (field: string = 'email', target: ValidationType = 'body') => {
  const schema = z.object({
    [field]: z.string().email('Invalid email address').toLowerCase()
  });
  
  return validate(schema, target);
};

/**
 * Password strength validation middleware
 */
export const validatePasswordStrength = (field: string = 'password') => {
  return customValidation((data) => {
    const password = data[field];
    
    if (!password) {
      return [{
        field,
        message: 'Password is required',
        code: 'required'
      }];
    }

    const strength = ValidationUtils.checkPasswordStrength(password);
    
    if (!strength.isValid) {
      return [{
        field,
        message: `Password is too weak: ${strength.feedback.join(', ')}`,
        code: 'weak_password',
        value: { score: strength.score, feedback: strength.feedback }
      }];
    }

    return [];
  });
};

/**
 * Username availability validation middleware
 */
export const validateUsernameFormat = (field: string = 'username') => {
  return customValidation((data) => {
    const username = data[field];
    
    if (!username) {
      return [{
        field,
        message: 'Username is required',
        code: 'required'
      }];
    }

    const validation = ValidationUtils.validateUsernameFormat(username);
    
    if (!validation.isValid) {
      return validation.errors.map(error => ({
        field,
        message: error,
        code: 'invalid_format'
      }));
    }

    return [];
  });
};

/**
 * Date range validation middleware
 */
export const validateDateRange = (
  startField: string = 'startDate', 
  endField: string = 'endDate',
  target: ValidationType = 'query'
) => {
  return customValidation((data) => {
    const startDate = data[startField];
    const endDate = data[endField];
    const errors: ValidationError[] = [];

    if (startDate && endDate) {
      const start = new Date(startDate);
      const end = new Date(endDate);

      if (start > end) {
        errors.push({
          field: endField,
          message: 'End date must be after start date',
          code: 'invalid_range'
        });
      }

      // Check if dates are not too far in the past or future
      const now = new Date();
      const maxPast = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000 * 10); // 10 years ago
      const maxFuture = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000 * 5); // 5 years from now

      if (start < maxPast || end < maxPast) {
        errors.push({
          field: startField,
          message: 'Date cannot be more than 10 years in the past',
          code: 'date_too_old'
        });
      }

      if (start > maxFuture || end > maxFuture) {
        errors.push({
          field: endField,
          message: 'Date cannot be more than 5 years in the future',
          code: 'date_too_future'
        });
      }
    }

    return errors;
  }, target);
};

/**
 * Content-Type validation middleware
 */
export const validateContentType = (...allowedTypes: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const contentType = req.get('Content-Type');
    
    if (!contentType || !allowedTypes.some(type => contentType.includes(type))) {
      const error: ValidationError = {
        field: 'content-type',
        message: `Invalid content type. Allowed: ${allowedTypes.join(', ')}`,
        code: 'invalid_content_type',
        value: contentType
      };
      
      ResponseUtils.validationError(res, [error]);
      return;
    }

    next();
  };
};

/**
 * Request size validation middleware
 */
export const validateRequestSize = (maxSize: number = 1024 * 1024) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const contentLength = parseInt(req.get('Content-Length') || '0');
    
    if (contentLength > maxSize) {
      const error: ValidationError = {
        field: 'content-length',
        message: `Request too large. Maximum size: ${Math.round(maxSize / 1024)}KB`,
        code: 'request_too_large',
        value: contentLength
      };
      
      ResponseUtils.validationError(res, [error]);
      return;
    }

    next();
  };
};

/**
 * Export validation middleware collection
 */
export const validationMiddleware = {
  // Core validation
  validate,
  validateBody,
  validateQuery,
  validateParams,
  validateHeaders,
  
  // Sanitization
  sanitize,
  
  // Common validations
  validatePagination,
  validateId,
  validateIds,
  validateEmail,
  validatePasswordStrength,
  validateUsernameFormat,
  validateDateRange,
  
  // File validation
  validateFileUpload,
  
  // Request validation
  validateContentType,
  validateRequestSize,
  
  // Custom validation
  customValidation
};
import { PoolClient } from 'pg';
import { database, DatabaseHelpers } from '@/config/database.js';
import { logger, logDatabaseOperation } from '@/config/logger.js';
import type { 
  User, 
  PublicUser, 
  CreateUserOptions,
  UpdateProfileRequest,
  QueryParams,
  PaginatedResult 
} from '@/types/auth';

/**
 * User repository implementing the Repository pattern
 * Handles all database operations for users
 */
export class UserRepository {
  /**
   * Create a new user
   */
  static async create(userData: {
    username: string;
    email: string;
    passwordHash: string;
    emailVerified?: boolean;
    emailVerificationToken?: string;
    isActive?: boolean;
  }, options: CreateUserOptions = {}): Promise<User> {
    const startTime = Date.now();
    
    try {
      const query = `
        INSERT INTO users (
          id, username, email, password_hash, email_verified, 
          email_verification_token, is_active, created_at, updated_at
        ) VALUES (
          gen_random_uuid(), $1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        RETURNING *
      `;

      const values = [
        userData.username,
        userData.email,
        userData.passwordHash,
        userData.emailVerified ?? false,
        userData.emailVerificationToken ?? null,
        userData.isActive ?? true
      ];

      const result = await database.query<User>(query, values);
      const user = result[0];
      
      if (!user) {
        throw new Error('Failed to create user');
      }

      logDatabaseOperation('INSERT', 'users', Date.now() - startTime, {
        userId: user.id,
        username: user.username
      });

      return user;
    } catch (error) {
      logger.error('Error creating user', { error, userData: userData.username });
      throw error;
    }
  }

  /**
   * Find user by ID
   */
  static async findById(id: string): Promise<User | null> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT 
          id, username, email, password_hash, email_verified,
          email_verification_token, password_reset_token, password_reset_expires,
          last_login_at, login_attempts, lock_until, is_active,
          created_at, updated_at, version, deleted_at
        FROM users 
        WHERE id = $1 AND deleted_at IS NULL
      `;

      const result = await database.query<User>(query, [id]);
      const user = result[0] || null;

      logDatabaseOperation('SELECT', 'users', Date.now() - startTime, {
        userId: id,
        found: !!user
      });

      return user;
    } catch (error) {
      logger.error('Error finding user by ID', { error, userId: id });
      throw error;
    }
  }

  /**
   * Find user by username
   */
  static async findByUsername(username: string): Promise<User | null> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT 
          id, username, email, password_hash, email_verified,
          email_verification_token, password_reset_token, password_reset_expires,
          last_login_at, login_attempts, lock_until, is_active,
          created_at, updated_at, version, deleted_at
        FROM users 
        WHERE username = $1 AND deleted_at IS NULL
      `;

      const result = await database.query<User>(query, [username]);
      const user = result[0] || null;

      logDatabaseOperation('SELECT', 'users', Date.now() - startTime, {
        username,
        found: !!user
      });

      return user;
    } catch (error) {
      logger.error('Error finding user by username', { error, username });
      throw error;
    }
  }

  /**
   * Find user by email
   */
  static async findByEmail(email: string): Promise<User | null> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT 
          id, username, email, password_hash, email_verified,
          email_verification_token, password_reset_token, password_reset_expires,
          last_login_at, login_attempts, lock_until, is_active,
          created_at, updated_at, version, deleted_at
        FROM users 
        WHERE email = $1 AND deleted_at IS NULL
      `;

      const result = await database.query<User>(query, [email]);
      const user = result[0] || null;

      logDatabaseOperation('SELECT', 'users', Date.now() - startTime, {
        email,
        found: !!user
      });

      return user;
    } catch (error) {
      logger.error('Error finding user by email', { error, email });
      throw error;
    }
  }

  /**
   * Find user by password reset token
   */
  static async findByPasswordResetToken(token: string): Promise<User | null> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT 
          id, username, email, password_hash, email_verified,
          email_verification_token, password_reset_token, password_reset_expires,
          last_login_at, login_attempts, lock_until, is_active,
          created_at, updated_at, version, deleted_at
        FROM users 
        WHERE password_reset_token = $1 
          AND password_reset_expires > CURRENT_TIMESTAMP 
          AND deleted_at IS NULL
      `;

      const result = await database.query<User>(query, [token]);
      const user = result[0] || null;

      logDatabaseOperation('SELECT', 'users', Date.now() - startTime, {
        tokenFound: !!user,
        expired: false
      });

      return user;
    } catch (error) {
      logger.error('Error finding user by reset token', { error });
      throw error;
    }
  }

  /**
   * Update user
   */
  static async update(id: string, updates: Partial<User>): Promise<User | null> {
    const startTime = Date.now();
    
    try {
      const allowedFields = [
        'username', 'email', 'password_hash', 'email_verified',
        'email_verification_token', 'password_reset_token', 'password_reset_expires',
        'last_login_at', 'login_attempts', 'lock_until', 'is_active'
      ];

      const filteredUpdates = Object.fromEntries(
        Object.entries(updates).filter(([key]) => allowedFields.includes(key))
      );

      if (Object.keys(filteredUpdates).length === 0) {
        throw new Error('No valid fields to update');
      }

      const setClause = Object.keys(filteredUpdates)
        .map((key, index) => `${key} = ${index + 2}`)
        .join(', ');

      const query = `
        UPDATE users 
        SET ${setClause}, updated_at = CURRENT_TIMESTAMP, version = version + 1
        WHERE id = $1 AND deleted_at IS NULL
        RETURNING *
      `;

      const values = [id, ...Object.values(filteredUpdates)];
      const result = await database.query<User>(query, values);
      const user = result[0] || null;

      logDatabaseOperation('UPDATE', 'users', Date.now() - startTime, {
        userId: id,
        updatedFields: Object.keys(filteredUpdates),
        success: !!user
      });

      return user;
    } catch (error) {
      logger.error('Error updating user', { error, userId: id });
      throw error;
    }
  }

  /**
   * Update last login timestamp
   */
  static async updateLastLogin(id: string): Promise<void> {
    const startTime = Date.now();
    
    try {
      const query = `
        UPDATE users 
        SET last_login_at = CURRENT_TIMESTAMP, 
            login_attempts = 0,
            lock_until = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1 AND deleted_at IS NULL
      `;

      await database.query(query, [id]);

      logDatabaseOperation('UPDATE', 'users', Date.now() - startTime, {
        userId: id,
        operation: 'updateLastLogin'
      });
    } catch (error) {
      logger.error('Error updating last login', { error, userId: id });
      throw error;
    }
  }

  /**
   * Increment login attempts
   */
  static async incrementLoginAttempts(id: string, lockDuration?: number): Promise<void> {
    const startTime = Date.now();
    
    try {
      let query = `
        UPDATE users 
        SET login_attempts = login_attempts + 1,
            updated_at = CURRENT_TIMESTAMP
      `;

      const values = [id];

      if (lockDuration) {
        query += `, lock_until = CURRENT_TIMESTAMP + INTERVAL '${lockDuration} milliseconds'`;
      }

      query += ` WHERE id = $1 AND deleted_at IS NULL`;

      await database.query(query, values);

      logDatabaseOperation('UPDATE', 'users', Date.now() - startTime, {
        userId: id,
        operation: 'incrementLoginAttempts',
        lockDuration
      });
    } catch (error) {
      logger.error('Error incrementing login attempts', { error, userId: id });
      throw error;
    }
  }

  /**
   * Check if user exists by username or email
   */
  static async existsByUsernameOrEmail(username: string, email: string): Promise<boolean> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT COUNT(*) as count 
        FROM users 
        WHERE (username = $1 OR email = $2) AND deleted_at IS NULL
      `;

      const result = await database.query<{ count: string }>(query, [username, email]);
      const exists = parseInt(result[0]?.count || '0') > 0;

      logDatabaseOperation('SELECT', 'users', Date.now() - startTime, {
        operation: 'existsByUsernameOrEmail',
        exists
      });

      return exists;
    } catch (error) {
      logger.error('Error checking user existence', { error, username, email });
      throw error;
    }
  }

  /**
   * Get paginated users with optional filters
   */
  static async findMany(params: QueryParams = {}): Promise<PaginatedResult<PublicUser>> {
    const startTime = Date.now();
    
    try {
      const {
        page = 1,
        limit = 10,
        sortBy = 'created_at',
        sortOrder = 'DESC',
        search,
        status
      } = params;

      // Build base query
      let baseQuery = `
        FROM users u
        WHERE u.deleted_at IS NULL
      `;

      const queryParams: unknown[] = [];
      let paramIndex = 1;

      // Add search filter
      if (search) {
        baseQuery += ` AND (u.username ILIKE ${paramIndex} OR u.email ILIKE ${paramIndex})`;
        queryParams.push(`%${search}%`);
        paramIndex++;
      }

      // Add status filter
      if (status) {
        if (status === 'active') {
          baseQuery += ` AND u.is_active = true`;
        } else if (status === 'inactive') {
          baseQuery += ` AND u.is_active = false`;
        }
      }

      // Count total records
      const countQuery = `SELECT COUNT(*) as total ${baseQuery}`;
      const countResult = await database.query<{ total: string }>(countQuery, queryParams);
      const total = parseInt(countResult[0]?.total || '0');

      // Build main query with pagination
      const orderClause = DatabaseHelpers.buildOrderClause(sortBy, sortOrder);
      const { clause: paginationClause, values: paginationValues } = 
        DatabaseHelpers.buildPaginationClause(page, limit, paramIndex);

      const selectQuery = `
        SELECT 
          u.id, u.username, u.email, u.email_verified, u.is_active,
          u.created_at, u.last_login_at,
          COALESCE(
            JSON_AGG(
              JSON_BUILD_OBJECT('name', r.name)
            ) FILTER (WHERE r.name IS NOT NULL), 
            '[]'
          ) as roles
        ${baseQuery}
        LEFT JOIN user_roles ur ON u.id = ur.user_id
        LEFT JOIN roles r ON ur.role_id = r.id
        GROUP BY u.id, u.username, u.email, u.email_verified, u.is_active, u.created_at, u.last_login_at
        ${orderClause}
        ${paginationClause}
      `;

      const allParams = [...queryParams, ...paginationValues];
      const result = await database.query<PublicUser>(selectQuery, allParams);

      const totalPages = Math.ceil(total / limit);

      logDatabaseOperation('SELECT', 'users', Date.now() - startTime, {
        operation: 'findMany',
        totalRecords: total,
        page,
        limit
      });

      return {
        items: result,
        meta: {
          page,
          limit,
          total,
          totalPages
        }
      };
    } catch (error) {
      logger.error('Error finding users', { error, params });
      throw error;
    }
  }

  /**
   * Soft delete user
   */
  static async softDelete(id: string): Promise<boolean> {
    const startTime = Date.now();
    
    try {
      const query = `
        UPDATE users 
        SET deleted_at = CURRENT_TIMESTAMP, 
            updated_at = CURRENT_TIMESTAMP,
            is_active = false
        WHERE id = $1 AND deleted_at IS NULL
      `;

      const result = await database.query(query, [id]);
      const success = (result as any).rowCount > 0;

      logDatabaseOperation('UPDATE', 'users', Date.now() - startTime, {
        userId: id,
        operation: 'softDelete',
        success
      });

      return success;
    } catch (error) {
      logger.error('Error soft deleting user', { error, userId: id });
      throw error;
    }
  }

  /**
   * Convert User entity to PublicUser (remove sensitive data)
   */
  static toPublicUser(user: User): PublicUser {
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
      roles: [], // Will be populated by service layer
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt
    };
  }

  /**
   * Transaction helper for complex user operations
   */
  static async withTransaction<T>(
    callback: (client: PoolClient) => Promise<T>
  ): Promise<T> {
    return await database.transaction(callback);
  }
}
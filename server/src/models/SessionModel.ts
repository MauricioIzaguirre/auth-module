import { database } from '@/config/database.js';
import { logger, logDatabaseOperation } from '@/config/logger.js';
import type { Session, QueryParams, PaginatedResult } from '@/types/auth.js';

/**
 * Session repository for managing user sessions
 * Handles session creation, validation, and cleanup
 */
export class SessionRepository {
  /**
   * Create a new session
   */
  static async createSession(sessionData: {
    userId: string;
    token: string;
    refreshToken: string;
    expiresAt: Date;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<Session> {
    const startTime = Date.now();
    
    try {
      const query = `
        INSERT INTO sessions (
          id, user_id, token, refresh_token, expires_at, ip_address, 
          user_agent, is_active, last_accessed_at, created_at, updated_at
        ) VALUES (
          gen_random_uuid(), $1, $2, $3, $4, $5, $6, true, CURRENT_TIMESTAMP, 
          CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        RETURNING *
      `;

      const values = [
        sessionData.userId,
        sessionData.token,
        sessionData.refreshToken,
        sessionData.expiresAt,
        sessionData.ipAddress ?? null,
        sessionData.userAgent ?? null
      ];

      const result = await database.query<Session>(query, values);
      const session = result[0];
      
      if (!session) {
        throw new Error('Failed to create session');
      }

      logDatabaseOperation('INSERT', 'sessions', Date.now() - startTime, {
        sessionId: session.id,
        userId: session.userId
      });

      return session;
    } catch (error) {
      logger.error('Error creating session', { error, userId: sessionData.userId });
      throw error;
    }
  }

  /**
   * Find session by token
   */
  static async findByToken(token: string): Promise<Session | null> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT 
          id, user_id, token, refresh_token, expires_at, ip_address,
          user_agent, is_active, last_accessed_at, created_at, updated_at, version
        FROM sessions 
        WHERE token = $1 
          AND is_active = true 
          AND expires_at > CURRENT_TIMESTAMP
          AND deleted_at IS NULL
      `;

      const result = await database.query<Session>(query, [token]);
      const session = result[0] || null;

      logDatabaseOperation('SELECT', 'sessions', Date.now() - startTime, {
        tokenFound: !!session,
        active: session?.isActive
      });

      return session;
    } catch (error) {
      logger.error('Error finding session by token', { error });
      throw error;
    }
  }

  /**
   * Find session by refresh token
   */
  static async findByRefreshToken(refreshToken: string): Promise<Session | null> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT 
          id, user_id, token, refresh_token, expires_at, ip_address,
          user_agent, is_active, last_accessed_at, created_at, updated_at, version
        FROM sessions 
        WHERE refresh_token = $1 
          AND is_active = true 
          AND expires_at > CURRENT_TIMESTAMP
          AND deleted_at IS NULL
      `;

      const result = await database.query<Session>(query, [refreshToken]);
      const session = result[0] || null;

      logDatabaseOperation('SELECT', 'sessions', Date.now() - startTime, {
        refreshTokenFound: !!session,
        active: session?.isActive
      });

      return session;
    } catch (error) {
      logger.error('Error finding session by refresh token', { error });
      throw error;
    }
  }

  /**
   * Find session by ID
   */
  static async findById(id: string): Promise<Session | null> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT 
          id, user_id, token, refresh_token, expires_at, ip_address,
          user_agent, is_active, last_accessed_at, created_at, updated_at, version
        FROM sessions 
        WHERE id = $1 AND deleted_at IS NULL
      `;

      const result = await database.query<Session>(query, [id]);
      const session = result[0] || null;

      logDatabaseOperation('SELECT', 'sessions', Date.now() - startTime, {
        sessionId: id,
        found: !!session
      });

      return session;
    } catch (error) {
      logger.error('Error finding session by ID', { error, sessionId: id });
      throw error;
    }
  }

  /**
   * Update session last accessed time
   */
  static async updateLastAccessed(id: string): Promise<void> {
    const startTime = Date.now();
    
    try {
      const query = `
        UPDATE sessions 
        SET last_accessed_at = CURRENT_TIMESTAMP, 
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1 AND deleted_at IS NULL
      `;

      await database.query(query, [id]);

      logDatabaseOperation('UPDATE', 'sessions', Date.now() - startTime, {
        sessionId: id,
        operation: 'updateLastAccessed'
      });
    } catch (error) {
      logger.error('Error updating session last accessed', { error, sessionId: id });
      throw error;
    }
  }

  /**
   * Update session tokens
   */
  static async updateTokens(
    id: string, 
    token: string, 
    refreshToken: string, 
    expiresAt: Date
  ): Promise<Session | null> {
    const startTime = Date.now();
    
    try {
      const query = `
        UPDATE sessions 
        SET token = $2, 
            refresh_token = $3, 
            expires_at = $4,
            last_accessed_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP,
            version = version + 1
        WHERE id = $1 AND deleted_at IS NULL
        RETURNING *
      `;

      const values = [id, token, refreshToken, expiresAt];
      const result = await database.query<Session>(query, values);
      const session = result[0] || null;

      logDatabaseOperation('UPDATE', 'sessions', Date.now() - startTime, {
        sessionId: id,
        operation: 'updateTokens',
        success: !!session
      });

      return session;
    } catch (error) {
      logger.error('Error updating session tokens', { error, sessionId: id });
      throw error;
    }
  }

  /**
   * Deactivate session (logout)
   */
  static async deactivateSession(id: string): Promise<boolean> {
    const startTime = Date.now();
    
    try {
      const query = `
        UPDATE sessions 
        SET is_active = false, 
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1 AND deleted_at IS NULL
      `;

      const result = await database.query(query, [id]);
      const success = (result as any).rowCount > 0;

      logDatabaseOperation('UPDATE', 'sessions', Date.now() - startTime, {
        sessionId: id,
        operation: 'deactivate',
        success
      });

      return success;
    } catch (error) {
      logger.error('Error deactivating session', { error, sessionId: id });
      throw error;
    }
  }

  /**
   * Deactivate all user sessions
   */
  static async deactivateUserSessions(userId: string): Promise<number> {
    const startTime = Date.now();
    
    try {
      const query = `
        UPDATE sessions 
        SET is_active = false, 
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = $1 
          AND is_active = true 
          AND deleted_at IS NULL
      `;

      const result = await database.query(query, [userId]);
      const count = (result as any).rowCount || 0;

      logDatabaseOperation('UPDATE', 'sessions', Date.now() - startTime, {
        userId,
        operation: 'deactivateUserSessions',
        count
      });

      return count;
    } catch (error) {
      logger.error('Error deactivating user sessions', { error, userId });
      throw error;
    }
  }

  /**
   * Get active sessions for a user
   */
  static async getUserActiveSessions(userId: string): Promise<Session[]> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT 
          id, user_id, token, refresh_token, expires_at, ip_address,
          user_agent, is_active, last_accessed_at, created_at, updated_at, version
        FROM sessions 
        WHERE user_id = $1 
          AND is_active = true 
          AND expires_at > CURRENT_TIMESTAMP
          AND deleted_at IS NULL
        ORDER BY last_accessed_at DESC
      `;

      const result = await database.query<Session>(query, [userId]);

      logDatabaseOperation('SELECT', 'sessions', Date.now() - startTime, {
        userId,
        activeSessionsCount: result.length
      });

      return result;
    } catch (error) {
      logger.error('Error getting user active sessions', { error, userId });
      throw error;
    }
  }

  /**
   * Clean up expired sessions
   */
  static async cleanupExpiredSessions(): Promise<number> {
    const startTime = Date.now();
    
    try {
      const query = `
        UPDATE sessions 
        SET is_active = false, 
            updated_at = CURRENT_TIMESTAMP
        WHERE expires_at <= CURRENT_TIMESTAMP 
          AND is_active = true
          AND deleted_at IS NULL
      `;

      const result = await database.query(query);
      const count = (result as any).rowCount || 0;

      logDatabaseOperation('UPDATE', 'sessions', Date.now() - startTime, {
        operation: 'cleanupExpired',
        count
      });

      return count;
    } catch (error) {
      logger.error('Error cleaning up expired sessions', { error });
      throw error;
    }
  }

  /**
   * Get sessions with pagination (for admin purposes)
   */
  static async findMany(params: QueryParams = {}): Promise<PaginatedResult<Session>> {
    const startTime = Date.now();
    
    try {
      const {
        page = 1,
        limit = 20,
        sortBy = 'last_accessed_at',
        sortOrder = 'DESC',
        status
      } = params;

      // Build base query
      let baseQuery = `
        FROM sessions s
        WHERE s.deleted_at IS NULL
      `;

      const queryParams: unknown[] = [];
      let paramIndex = 1;

      // Add status filter
      if (status) {
        if (status === 'active') {
          baseQuery += ` AND s.is_active = true AND s.expires_at > CURRENT_TIMESTAMP`;
        } else if (status === 'expired') {
          baseQuery += ` AND s.expires_at <= CURRENT_TIMESTAMP`;
        } else if (status === 'inactive') {
          baseQuery += ` AND s.is_active = false`;
        }
      }

      // Count total records
      const countQuery = `SELECT COUNT(*) as total ${baseQuery}`;
      const countResult = await database.query<{ total: string }>(countQuery, queryParams);
      const total = parseInt(countResult[0]?.total || '0');

      // Build main query with pagination
      const orderClause = `ORDER BY s.${sortBy} ${sortOrder}`;
      const paginationClause = `LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
      const paginationValues = [limit, (page - 1) * limit];

      const selectQuery = `
        SELECT 
          s.id, s.user_id, s.token, s.refresh_token, s.expires_at, s.ip_address,
          s.user_agent, s.is_active, s.last_accessed_at, s.created_at, s.updated_at, s.version
        ${baseQuery}
        ${orderClause}
        ${paginationClause}
      `;

      const allParams = [...queryParams, ...paginationValues];
      const result = await database.query<Session>(selectQuery, allParams);

      const totalPages = Math.ceil(total / limit);

      logDatabaseOperation('SELECT', 'sessions', Date.now() - startTime, {
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
      logger.error('Error finding sessions', { error, params });
      throw error;
    }
  }

  /**
   * Get session statistics
   */
  static async getSessionStats(): Promise<{
    totalSessions: number;
    activeSessions: number;
    expiredSessions: number;
    avgSessionDuration: number;
  }> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT 
          COUNT(*) as total_sessions,
          COUNT(CASE WHEN is_active = true AND expires_at > CURRENT_TIMESTAMP THEN 1 END) as active_sessions,
          COUNT(CASE WHEN expires_at <= CURRENT_TIMESTAMP THEN 1 END) as expired_sessions,
          COALESCE(AVG(EXTRACT(EPOCH FROM (last_accessed_at - created_at))), 0) as avg_duration_seconds
        FROM sessions 
        WHERE deleted_at IS NULL
      `;

      const result = await database.query<{
        total_sessions: string;
        active_sessions: string;
        expired_sessions: string;
        avg_duration_seconds: string;
      }>(query);

      const stats = result[0];

      logDatabaseOperation('SELECT', 'sessions', Date.now() - startTime, {
        operation: 'getStats'
      });

      return {
        totalSessions: parseInt(stats?.total_sessions || '0'),
        activeSessions: parseInt(stats?.active_sessions || '0'),
        expiredSessions: parseInt(stats?.expired_sessions || '0'),
        avgSessionDuration: parseFloat(stats?.avg_duration_seconds || '0')
      };
    } catch (error) {
      logger.error('Error getting session statistics', { error });
      throw error;
    }
  }

  /**
   * Delete old inactive sessions
   */
  static async deleteOldSessions(daysOld: number = 30): Promise<number> {
    const startTime = Date.now();
    
    try {
      const query = `
        DELETE FROM sessions 
        WHERE is_active = false 
          AND updated_at < CURRENT_TIMESTAMP - INTERVAL '${daysOld} days'
      `;

      const result = await database.query(query);
      const count = (result as any).rowCount || 0;

      logDatabaseOperation('DELETE', 'sessions', Date.now() - startTime, {
        operation: 'deleteOldSessions',
        daysOld,
        count
      });

      return count;
    } catch (error) {
      logger.error('Error deleting old sessions', { error, daysOld });
      throw error;
    }
  }

  /**
   * Validate session and user access
   */
  static async validateSessionWithUser(token: string): Promise<{
    session: Session;
    user: { id: string; username: string; isActive: boolean; };
  } | null> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT 
          s.id, s.user_id, s.token, s.refresh_token, s.expires_at, s.ip_address,
          s.user_agent, s.is_active, s.last_accessed_at, s.created_at, s.updated_at, s.version,
          u.username, u.is_active as user_active
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = $1 
          AND s.is_active = true 
          AND s.expires_at > CURRENT_TIMESTAMP
          AND s.deleted_at IS NULL
          AND u.deleted_at IS NULL
          AND u.is_active = true
      `;

      const result = await database.query<Session & { 
        username: string; 
        user_active: boolean; 
      }>(query, [token]);
      
      const data = result[0];
      
      if (!data) {
        logDatabaseOperation('SELECT', 'sessions', Date.now() - startTime, {
          operation: 'validateSessionWithUser',
          valid: false
        });
        return null;
      }

      const session: Session = {
        id: data.id,
        userId: data.userId,
        token: data.token,
        refreshToken: data.refreshToken,
        expiresAt: data.expiresAt,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
        isActive: data.isActive,
        lastAccessedAt: data.lastAccessedAt,
        createdAt: data.createdAt,
        updatedAt: data.updatedAt,
        version: data.version
      };

      const user = {
        id: data.userId,
        username: data.username,
        isActive: data.user_active
      };

      logDatabaseOperation('SELECT', 'sessions', Date.now() - startTime, {
        operation: 'validateSessionWithUser',
        valid: true,
        userId: user.id
      });

      return { session, user };
    } catch (error) {
      logger.error('Error validating session with user', { error });
      throw error;
    }
  }
}
// server/src/models/postgresql/User.model.ts
import bcrypt from 'bcrypt'
import { Pool, PoolClient } from 'pg'
import { db } from '../../config/database'
import { IUserModel, CreateSessionDTO, ISession, ILoginHistory, CreateAuditLogDTO, IAuditLog } from '../interfaces/User.interface'
import { IUser, IUserPublic, CreateUserDTO, UpdateUserDTO, UserFilters, PaginationOptions } from '../../types/auth.types'
import { authConfig } from '../../config/auth'
import { logger } from '../../utils/logger'
import { CryptoUtils } from '../../utils/crypto.utils'

export class UserModelPostgreSQL implements IUserModel {
  private pool: Pool | null = null

  private async getPool(): Promise<Pool> {
    if (!this.pool) {
      this.pool = await db.getPool()
    }
    return this.pool
  }

  async create(userData: CreateUserDTO): Promise<IUser> {
    const pool = await this.getPool()
    
    try {
      // Hash password
      const hashedPassword = await bcrypt.hash(userData.password, authConfig.bcrypt.saltRounds)
      
      // Generate email verification token
      const emailVerificationToken = CryptoUtils.generateSecureToken()
      const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 horas

      const query = `
        INSERT INTO users (
          username, email, password_hash, first_name, last_name,
          email_verification_token, email_verification_expires
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING 
          id, username, email, first_name, last_name, is_active, 
          email_verified, last_login, failed_login_attempts, lockout_until,
          created_at, updated_at
      `

      const values = [
        userData.username,
        userData.email,
        hashedPassword,
        userData.firstName || null,
        userData.lastName || null,
        emailVerificationToken,
        emailVerificationExpires
      ]

      const result = await pool.query(query, values)
      const user = result.rows[0]

      // Assign default roles if provided
      if (userData.roleIds && userData.roleIds.length > 0) {
        await this.assignMultipleRoles(user.id, userData.roleIds)
      }

      const userWithRoles = await this.findById(user.id)
      
      await this.createAuditLog({
        userId: user.id,
        action: 'USER_CREATED',
        resource: 'user',
        resourceId: user.id,
        success: true
      })

      return userWithRoles!
    } catch (error) {
      logger.error('Error creating user', error as Error, { userData: { username: userData.username, email: userData.email } })
      throw error
    }
  }

  async findById(id: string): Promise<IUser | null> {
    const pool = await this.getPool()
    
    try {
      const userQuery = `
        SELECT 
          u.id, u.username, u.email, u.password_hash, u.first_name, u.last_name,
          u.is_active, u.email_verified, u.last_login, u.failed_login_attempts,
          u.lockout_until, u.created_at, u.updated_at
        FROM users u
        WHERE u.id = $1
      `

      const userResult = await pool.query(userQuery, [id])
      
      if (userResult.rows.length === 0) {
        return null
      }

      const user = userResult.rows[0]

      // Get user roles
      const rolesQuery = `
        SELECT r.id, r.name, r.description
        FROM roles r
        INNER JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = $1 AND r.is_active = true
      `

      const rolesResult = await pool.query(rolesQuery, [id])

      return {
        id: user.id,
        username: user.username,
        email: user.email,
        password: user.password_hash,
        firstName: user.first_name,
        lastName: user.last_name,
        isActive: user.is_active,
        emailVerified: user.email_verified,
        lastLogin: user.last_login,
        failedLoginAttempts: user.failed_login_attempts,
        lockoutUntil: user.lockout_until,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
        roles: rolesResult.rows
      }
    } catch (error) {
      logger.error('Error finding user by ID', error as Error, { userId: id })
      throw error
    }
  }

  async findByUsername(username: string): Promise<IUser | null> {
    const pool = await this.getPool()
    
    try {
      const query = `
        SELECT 
          u.id, u.username, u.email, u.password_hash, u.first_name, u.last_name,
          u.is_active, u.email_verified, u.last_login, u.failed_login_attempts,
          u.lockout_until, u.created_at, u.updated_at
        FROM users u
        WHERE u.username = $1
      `

      const result = await pool.query(query, [username.toLowerCase()])
      
      if (result.rows.length === 0) {
        return null
      }

      const user = result.rows[0]

      // Get user roles
      const rolesQuery = `
        SELECT r.id, r.name, r.description
        FROM roles r
        INNER JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = $1 AND r.is_active = true
      `

      const rolesResult = await pool.query(rolesQuery, [user.id])

      return {
        id: user.id,
        username: user.username,
        email: user.email,
        password: user.password_hash,
        firstName: user.first_name,
        lastName: user.last_name,
        isActive: user.is_active,
        emailVerified: user.email_verified,
        lastLogin: user.last_login,
        failedLoginAttempts: user.failed_login_attempts,
        lockoutUntil: user.lockout_until,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
        roles: rolesResult.rows
      }
    } catch (error) {
      logger.error('Error finding user by username', error as Error, { username })
      throw error
    }
  }

  async findByEmail(email: string): Promise<IUser | null> {
    const pool = await this.getPool()
    
    try {
      const query = `
        SELECT 
          u.id, u.username, u.email, u.password_hash, u.first_name, u.last_name,
          u.is_active, u.email_verified, u.last_login, u.failed_login_attempts,
          u.lockout_until, u.created_at, u.updated_at
        FROM users u
        WHERE u.email = $1
      `

      const result = await pool.query(query, [email.toLowerCase()])
      
      if (result.rows.length === 0) {
        return null
      }

      const user = result.rows[0]

      // Get user roles
      const rolesQuery = `
        SELECT r.id, r.name, r.description
        FROM roles r
        INNER JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = $1 AND r.is_active = true
      `

      const rolesResult = await pool.query(rolesQuery, [user.id])

      return {
        id: user.id,
        username: user.username,
        email: user.email,
        password: user.password_hash,
        firstName: user.first_name,
        lastName: user.last_name,
        isActive: user.is_active,
        emailVerified: user.email_verified,
        lastLogin: user.last_login,
        failedLoginAttempts: user.failed_login_attempts,
        lockoutUntil: user.lockout_until,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
        roles: rolesResult.rows
      }
    } catch (error) {
      logger.error('Error finding user by email', error as Error, { email })
      throw error
    }
  }

  async update(id: string, userData: UpdateUserDTO): Promise<IUser | null> {
    const pool = await this.getPool()
    
    try {
      const fields: string[] = []
      const values: any[] = []
      let paramCount = 1

      if (userData.username !== undefined) {
        fields.push(`username = ${paramCount++}`)
        values.push(userData.username.toLowerCase())
      }

      if (userData.email !== undefined) {
        fields.push(`email = ${paramCount++}`)
        values.push(userData.email.toLowerCase())
      }

      if (userData.firstName !== undefined) {
        fields.push(`first_name = ${paramCount++}`)
        values.push(userData.firstName)
      }

      if (userData.lastName !== undefined) {
        fields.push(`last_name = ${paramCount++}`)
        values.push(userData.lastName)
      }

      if (userData.isActive !== undefined) {
        fields.push(`is_active = ${paramCount++}`)
        values.push(userData.isActive)
      }

      if (fields.length === 0) {
        return await this.findById(id)
      }

      fields.push(`updated_at = CURRENT_TIMESTAMP`)
      values.push(id)

      const query = `
        UPDATE users 
        SET ${fields.join(', ')}
        WHERE id = ${paramCount}
        RETURNING 
          id, username, email, first_name, last_name, is_active, 
          email_verified, last_login, failed_login_attempts, lockout_until,
          created_at, updated_at
      `

      const result = await pool.query(query, values)
      
      if (result.rows.length === 0) {
        return null
      }

      // Handle role updates if provided
      if (userData.roleIds !== undefined) {
        await this.removeAllRoles(id)
        if (userData.roleIds.length > 0) {
          await this.assignMultipleRoles(id, userData.roleIds)
        }
      }

      await this.createAuditLog({
        userId: id,
        action: 'USER_UPDATED',
        resource: 'user',
        resourceId: id,
        details: userData,
        success: true
      })

      return await this.findById(id)
    } catch (error) {
      logger.error('Error updating user', error as Error, { userId: id, userData })
      throw error
    }
  }

  async delete(id: string): Promise<boolean> {
    const pool = await this.getPool()
    
    try {
      const query = 'DELETE FROM users WHERE id = $1'
      const result = await pool.query(query, [id])

      await this.createAuditLog({
        userId: id,
        action: 'USER_DELETED',
        resource: 'user',
        resourceId: id,
        success: true
      })

      return result.rowCount! > 0
    } catch (error) {
      logger.error('Error deleting user', error as Error, { userId: id })
      throw error
    }
  }

  async findAll(filters?: UserFilters, pagination?: PaginationOptions): Promise<{ users: IUserPublic[], total: number }> {
    const pool = await this.getPool()
    
    try {
      let whereClause = 'WHERE 1=1'
      const values: any[] = []
      let paramCount = 1

      if (filters?.isActive !== undefined) {
        whereClause += ` AND u.is_active = ${paramCount++}`
        values.push(filters.isActive)
      }

      if (filters?.emailVerified !== undefined) {
        whereClause += ` AND u.email_verified = ${paramCount++}`
        values.push(filters.emailVerified)
      }

      if (filters?.search) {
        whereClause += ` AND (
          u.username ILIKE ${paramCount} OR 
          u.email ILIKE ${paramCount} OR 
          u.first_name ILIKE ${paramCount} OR 
          u.last_name ILIKE ${paramCount}
        )`
        values.push(`%${filters.search}%`)
        paramCount++
      }

      if (filters?.roleId) {
        whereClause += ` AND EXISTS (
          SELECT 1 FROM user_roles ur 
          WHERE ur.user_id = u.id AND ur.role_id = ${paramCount++}
        )`
        values.push(filters.roleId)
      }

      // Count total
      const countQuery = `SELECT COUNT(*) as total FROM users u ${whereClause}`
      const countResult = await pool.query(countQuery, values)
      const total = parseInt(countResult.rows[0].total)

      // Get users with pagination
      const page = pagination?.page || 1
      const limit = pagination?.limit || 10
      const offset = (page - 1) * limit
      const sortBy = pagination?.sortBy || 'created_at'
      const sortOrder = pagination?.sortOrder || 'DESC'

      const usersQuery = `
        SELECT 
          u.id, u.username, u.email, u.first_name, u.last_name,
          u.is_active, u.email_verified, u.last_login, u.created_at,
          COALESCE(
            json_agg(
              CASE 
                WHEN r.id IS NOT NULL 
                THEN json_build_object('id', r.id, 'name', r.name, 'description', r.description)
                ELSE NULL
              END
            ) FILTER (WHERE r.id IS NOT NULL), 
            '[]'::json
          ) as roles
        FROM users u
        LEFT JOIN user_roles ur ON u.id = ur.user_id
        LEFT JOIN roles r ON ur.role_id = r.id AND r.is_active = true
        ${whereClause}
        GROUP BY u.id, u.username, u.email, u.first_name, u.last_name,
                 u.is_active, u.email_verified, u.last_login, u.created_at
        ORDER BY u.${sortBy} ${sortOrder}
        LIMIT ${paramCount++} OFFSET ${paramCount++}
      `

      values.push(limit, offset)
      const usersResult = await pool.query(usersQuery, values)

      const users: IUserPublic[] = usersResult.rows.map(row => ({
        id: row.id,
        username: row.username,
        email: row.email,
        firstName: row.first_name,
        lastName: row.last_name,
        isActive: row.is_active,
        emailVerified: row.email_verified,
        lastLogin: row.last_login,
        createdAt: row.created_at,
        roles: Array.isArray(row.roles) ? row.roles : []
      }))

      return { users, total }
    } catch (error) {
      logger.error('Error finding all users', error as Error, { filters, pagination })
      throw error
    }
  }

  // Authentication specific methods
  async incrementFailedAttempts(id: string): Promise<void> {
    const pool = await this.getPool()
    
    try {
      const query = `
        UPDATE users 
        SET failed_login_attempts = failed_login_attempts + 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
      `
      await pool.query(query, [id])
    } catch (error) {
      logger.error('Error incrementing failed attempts', error as Error, { userId: id })
      throw error
    }
  }

  async resetFailedAttempts(id: string): Promise<void> {
    const pool = await this.getPool()
    
    try {
      const query = `
        UPDATE users 
        SET failed_login_attempts = 0,
            lockout_until = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
      `
      await pool.query(query, [id])
    } catch (error) {
      logger.error('Error resetting failed attempts', error as Error, { userId: id })
      throw error
    }
  }

  async setLockout(id: string, lockoutUntil: Date): Promise<void> {
    const pool = await this.getPool()
    
    try {
      const query = `
        UPDATE users 
        SET lockout_until = $2,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
      `
      await pool.query(query, [id, lockoutUntil])
    } catch (error) {
      logger.error('Error setting lockout', error as Error, { userId: id, lockoutUntil })
      throw error
    }
  }

  async updateLastLogin(id: string): Promise<void> {
    const pool = await this.getPool()
    
    try {
      const query = `
        UPDATE users 
        SET last_login = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
      `
      await pool.query(query, [id])
    } catch (error) {
      logger.error('Error updating last login', error as Error, { userId: id })
      throw error
    }
  }

  async updatePassword(id: string, hashedPassword: string): Promise<void> {
    const pool = await this.getPool()
    
    try {
      const query = `
        UPDATE users 
        SET password_hash = $2,
            password_reset_token = NULL,
            password_reset_expires = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
      `
      await pool.query(query, [id, hashedPassword])

      await this.createAuditLog({
        userId: id,
        action: 'PASSWORD_CHANGED',
        resource: 'user',
        resourceId: id,
        success: true
      })
    } catch (error) {
      logger.error('Error updating password', error as Error, { userId: id })
      throw error
    }
  }

  // Role management
  async assignRole(userId: string, roleId: string): Promise<void> {
    const pool = await this.getPool()
    
    try {
      const query = `
        INSERT INTO user_roles (user_id, role_id)
        VALUES ($1, $2)
        ON CONFLICT (user_id, role_id) DO NOTHING
      `
      await pool.query(query, [userId, roleId])

      await this.createAuditLog({
        userId,
        action: 'ROLE_ASSIGNED',
        resource: 'user_role',
        details: { roleId },
        success: true
      })
    } catch (error) {
      logger.error('Error assigning role', error as Error, { userId, roleId })
      throw error
    }
  }

  async removeRole(userId: string, roleId: string): Promise<void> {
    const pool = await this.getPool()
    
    try {
      const query = 'DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2'
      await pool.query(query, [userId, roleId])

      await this.createAuditLog({
        userId,
        action: 'ROLE_REMOVED',
        resource: 'user_role',
        details: { roleId },
        success: true
      })
    } catch (error) {
      logger.error('Error removing role', error as Error, { userId, roleId })
      throw error
    }
  }

  private async assignMultipleRoles(userId: string, roleIds: string[]): Promise<void> {
    const pool = await this.getPool()
    
    try {
      const values = roleIds.map((roleId, index) => `($1, ${index + 2})`).join(', ')
      const query = `
        INSERT INTO user_roles (user_id, role_id)
        VALUES ${values}
        ON CONFLICT (user_id, role_id) DO NOTHING
      `
      await pool.query(query, [userId, ...roleIds])
    } catch (error) {
      logger.error('Error assigning multiple roles', error as Error, { userId, roleIds })
      throw error
    }
  }

  private async removeAllRoles(userId: string): Promise<void> {
    const pool = await this.getPool()
    
    try {
      const query = 'DELETE FROM user_roles WHERE user_id = $1'
      await pool.query(query, [userId])
    } catch (error) {
      logger.error('Error removing all roles', error as Error, { userId })
      throw error
    }
  }

  async getUserRoles(userId: string): Promise<string[]> {
    const pool = await this.getPool()
    
    try {
      const query = `
        SELECT r.id
        FROM roles r
        INNER JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = $1 AND r.is_active = true
      `
      const result = await pool.query(query, [userId])
      return result.rows.map(row => row.id)
    } catch (error) {
      logger.error('Error getting user roles', error as Error, { userId })
      throw error
    }
  }

  async getUserPermissions(userId: string): Promise<string[]> {
    const pool = await this.getPool()
    
    try {
      const query = `
        SELECT DISTINCT CONCAT(p.resource, ':', p.action) as permission
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        INNER JOIN roles r ON rp.role_id = r.id
        INNER JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = $1 AND r.is_active = true
        ORDER BY permission
      `
      const result = await pool.query(query, [userId])
      return result.rows.map(row => row.permission)
    } catch (error) {
      logger.error('Error getting user permissions', error as Error, { userId })
      throw error
    }
  }

  // Verification methods
  async existsByUsername(username: string): Promise<boolean> {
    const pool = await this.getPool()
    
    try {
      const query = 'SELECT 1 FROM users WHERE username = $1'
      const result = await pool.query(query, [username.toLowerCase()])
      return result.rows.length > 0
    } catch (error) {
      logger.error('Error checking username existence', error as Error, { username })
      throw error
    }
  }

  async existsByEmail(email: string): Promise<boolean> {
    const pool = await this.getPool()
    
    try {
      const query = 'SELECT 1 FROM users WHERE email = $1'
      const result = await pool.query(query, [email.toLowerCase()])
      return result.rows.length > 0
    } catch (error) {
      logger.error('Error checking email existence', error as Error, { email })
      throw error
    }
  }

  async isUserLocked(id: string): Promise<boolean> {
    const pool = await this.getPool()
    
    try {
      const query = `
        SELECT lockout_until 
        FROM users 
        WHERE id = $1 AND lockout_until IS NOT NULL AND lockout_until > CURRENT_TIMESTAMP
      `
      const result = await pool.query(query, [id])
      return result.rows.length > 0
    } catch (error) {
      logger.error('Error checking user lock status', error as Error, { userId: id })
      throw error
    }
  }

  // Session management
  async createSession(userId: string, sessionData: CreateSessionDTO): Promise<ISession> {
    const pool = await this.getPool()
    
    try {
      const query = `
        INSERT INTO user_sessions (user_id, token_hash, ip_address, user_agent, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, user_id, token_hash, ip_address, user_agent, created_at, last_activity, expires_at, is_valid
      `
      
      const values = [
        userId,
        sessionData.tokenHash,
        sessionData.ipAddress,
        sessionData.userAgent,
        sessionData.expiresAt
      ]

      const result = await pool.query(query, values)
      return {
        id: result.rows[0].id,
        userId: result.rows[0].user_id,
        tokenHash: result.rows[0].token_hash,
        ipAddress: result.rows[0].ip_address,
        userAgent: result.rows[0].user_agent,
        createdAt: result.rows[0].created_at,
        lastActivity: result.rows[0].last_activity,
        expiresAt: result.rows[0].expires_at,
        isValid: result.rows[0].is_valid
      }
    } catch (error) {
      logger.error('Error creating session', error as Error, { userId, sessionData })
      throw error
    }
  }

  async invalidateSession(sessionId: string): Promise<void> {
    const pool = await this.getPool()
    
    try {
      const query = 'UPDATE user_sessions SET is_valid = false WHERE id = $1'
      await pool.query(query, [sessionId])
    } catch (error) {
      logger.error('Error invalidating session', error as Error, { sessionId })
      throw error
    }
  }

  async invalidateUserSessions(userId: string): Promise<void> {
    const pool = await this.getPool()
    
    try {
      const query = 'UPDATE user_sessions SET is_valid = false WHERE user_id = $1'
      await pool.query(query, [userId])
    } catch (error) {
      logger.error('Error invalidating user sessions', error as Error, { userId })
      throw error
    }
  }

  async getUserActiveSessions(userId: string): Promise<ISession[]> {
    const pool = await this.getPool()
    
    try {
      const query = `
        SELECT id, user_id, token_hash, ip_address, user_agent, 
               created_at, last_activity, expires_at, is_valid
        FROM user_sessions
        WHERE user_id = $1 AND is_valid = true AND expires_at > CURRENT_TIMESTAMP
        ORDER BY last_activity DESC
      `
      
      const result = await pool.query(query, [userId])
      return result.rows.map(row => ({
        id: row.id,
        userId: row.user_id,
        tokenHash: row.token_hash,
        ipAddress: row.ip_address,
        userAgent: row.user_agent,
        createdAt: row.created_at,
        lastActivity: row.last_activity,
        expiresAt: row.expires_at,
        isValid: row.is_valid
      }))
    } catch (error) {
      logger.error('Error getting user active sessions', error as Error, { userId })
      throw error
    }
  }

  // Audit and history
  async getLoginHistory(userId: string, limit?: number): Promise<ILoginHistory[]> {
    const pool = await this.getPool()
    
    try {
      const query = `
        SELECT id, user_id, username, ip_address, user_agent, success, failure_reason, attempted_at
        FROM login_history
        WHERE user_id = $1
        ORDER BY attempted_at DESC
        LIMIT $2
      `
      
      const result = await pool.query(query, [userId, limit || 10])
      return result.rows.map(row => ({
        id: row.id,
        userId: row.user_id,
        ipAddress: row.ip_address,
        userAgent: row.user_agent,
        success: row.success,
        timestamp: row.attempted_at,
        failureReason: row.failure_reason
      }))
    } catch (error) {
      logger.error('Error getting login history', error as Error, { userId, limit })
      throw error
    }
  }

  async createAuditLog(auditData: CreateAuditLogDTO): Promise<void> {
    const pool = await this.getPool()
    
    try {
      const query = `
        INSERT INTO audit_logs (user_id, action, resource, resource_id, details, ip_address, user_agent, success)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `
      
      const values = [
        auditData.userId || null,
        auditData.action,
        auditData.resource,
        auditData.resourceId || null,
        auditData.details ? JSON.stringify(auditData.details) : null,
        auditData.ipAddress || null,
        auditData.userAgent || null,
        auditData.success
      ]

      await pool.query(query, values)
    } catch (error) {
      logger.error('Error creating audit log', error as Error, { auditData })
      // Don't throw here to avoid cascading failures
    }
  }

  // Password reset methods
  async setPasswordResetToken(email: string, token: string, expiresAt: Date): Promise<boolean> {
    const pool = await this.getPool()
    
    try {
      const query = `
        UPDATE users 
        SET password_reset_token = $2,
            password_reset_expires = $3,
            updated_at = CURRENT_TIMESTAMP
        WHERE email = $1
      `
      const result = await pool.query(query, [email.toLowerCase(), token, expiresAt])
      return result.rowCount! > 0
    } catch (error) {
      logger.error('Error setting password reset token', error as Error, { email })
      throw error
    }
  }

  async findByPasswordResetToken(token: string): Promise<IUser | null> {
    const pool = await this.getPool()
    
    try {
      const query = `
        SELECT 
          u.id, u.username, u.email, u.password_hash, u.first_name, u.last_name,
          u.is_active, u.email_verified, u.last_login, u.failed_login_attempts,
          u.lockout_until, u.created_at, u.updated_at
        FROM users u
        WHERE u.password_reset_token = $1 
        AND u.password_reset_expires > CURRENT_TIMESTAMP
      `

      const result = await pool.query(query, [token])
      
      if (result.rows.length === 0) {
        return null
      }

      const user = result.rows[0]

      // Get user roles
      const rolesQuery = `
        SELECT r.id, r.name, r.description
        FROM roles r
        INNER JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = $1 AND r.is_active = true
      `

      const rolesResult = await pool.query(rolesQuery, [user.id])

      return {
        id: user.id,
        username: user.username,
        email: user.email,
        password: user.password_hash,
        firstName: user.first_name,
        lastName: user.last_name,
        isActive: user.is_active,
        emailVerified: user.email_verified,
        lastLogin: user.last_login,
        failedLoginAttempts: user.failed_login_attempts,
        lockoutUntil: user.lockout_until,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
        roles: rolesResult.rows
      }
    } catch (error) {
      logger.error('Error finding user by password reset token', error as Error, { token })
      throw error
    }
  }

  // Email verification methods
  async setEmailVerificationToken(email: string, token: string, expiresAt: Date): Promise<boolean> {
    const pool = await this.getPool()
    
    try {
      const query = `
        UPDATE users 
        SET email_verification_token = $2,
            email_verification_expires = $3,
            updated_at = CURRENT_TIMESTAMP
        WHERE email = $1
      `
      const result = await pool.query(query, [email.toLowerCase(), token, expiresAt])
      return result.rowCount! > 0
    } catch (error) {
      logger.error('Error setting email verification token', error as Error, { email })
      throw error
    }
  }

  async verifyEmail(token: string): Promise<boolean> {
    const pool = await this.getPool()
    
    try {
      const query = `
        UPDATE users 
        SET email_verified = true,
            email_verification_token = NULL,
            email_verification_expires = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE email_verification_token = $1 
        AND email_verification_expires > CURRENT_TIMESTAMP
      `
      const result = await pool.query(query, [token])

      if (result.rowCount! > 0) {
        await this.createAuditLog({
          action: 'EMAIL_VERIFIED',
          resource: 'user',
          success: true
        })
        return true
      }

      return false
    } catch (error) {
      logger.error('Error verifying email', error as Error, { token })
      throw error
    }
  }
}
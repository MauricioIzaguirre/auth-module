import { UserRepository } from '@/models/UserModel';
import { RoleRepository } from '@/models/RoleModel.js';
import { logger, logDatabaseOperation } from '@/config/logger';
import { CryptoUtils } from '@/utils/crypto';
import {
  Errors,
  UserNotFoundError,
  UserAlreadyExistsError,
  ValidationError
} from '@/utils/errors.js';
import type {
  User,
  PublicUser,
  UpdateProfileRequest,
  QueryParams,
  PaginatedResult
} from '@/types/auth.js';

/**
 * User Service
 * Handles user management business logic
 */
export class UserService {
  /**
   * Get user by ID (public data only)
   */
  static async getUserById(id: string): Promise<PublicUser> {
    try {
      const user = await UserRepository.findById(id);
      if (!user) {
        throw new UserNotFoundError(id);
      }

      const roles = await RoleRepository.getUserRoles(user.id);
      
      return {
        ...UserRepository.toPublicUser(user),
        roles: roles.map(role => role.name)
      };

    } catch (error) {
      if (error instanceof UserNotFoundError) {
        throw error;
      }
      
      logger.error('Get user by ID error', { error, userId: id });
      throw new Errors.InternalServer('Failed to get user');
    }
  }

  /**
   * Get user by username (public data only)
   */
  static async getUserByUsername(username: string): Promise<PublicUser> {
    try {
      const user = await UserRepository.findByUsername(username);
      if (!user) {
        throw new UserNotFoundError(username);
      }

      const roles = await RoleRepository.getUserRoles(user.id);
      
      return {
        ...UserRepository.toPublicUser(user),
        roles: roles.map(role => role.name)
      };

    } catch (error) {
      if (error instanceof UserNotFoundError) {
        throw error;
      }
      
      logger.error('Get user by username error', { error, username });
      throw new Errors.InternalServer('Failed to get user');
    }
  }

  /**
   * Get paginated list of users (admin only)
   */
  static async getUsers(params: QueryParams = {}): Promise<PaginatedResult<PublicUser>> {
    try {
      return await UserRepository.findMany(params);
    } catch (error) {
      logger.error('Get users error', { error, params });
      throw new Errors.InternalServer('Failed to get users');
    }
  }

  /**
   * Update user profile
   */
  static async updateProfile(userId: string, updates: UpdateProfileRequest): Promise<PublicUser> {
    const startTime = Date.now();
    
    try {
      const user = await UserRepository.findById(userId);
      if (!user) {
        throw new UserNotFoundError(userId);
      }

      // For now, we'll just update basic user info
      // Profile-specific fields would need a separate UserProfile table
      const updateData: Partial<User> = {};
      
      // Map profile updates to user fields if needed
      // This is simplified - in a real app you'd have a separate profile table
      
      const updatedUser = await UserRepository.update(userId, updateData);
      if (!updatedUser) {
        throw new Errors.InternalServer('Failed to update profile');
      }

      const roles = await RoleRepository.getUserRoles(userId);
      
      logDatabaseOperation('UPDATE', 'users', Date.now() - startTime, {
        userId,
        operation: 'updateProfile'
      });

      return {
        ...UserRepository.toPublicUser(updatedUser),
        roles: roles.map(role => role.name)
      };

    } catch (error) {
      if (error instanceof UserNotFoundError) {
        throw error;
      }
      
      logger.error('Update profile error', { error, userId, updates });
      throw new Errors.InternalServer('Failed to update profile');
    }
  }

  /**
   * Update user email
   */
  static async updateEmail(userId: string, newEmail: string): Promise<void> {
    try {
      const user = await UserRepository.findById(userId);
      if (!user) {
        throw new UserNotFoundError(userId);
      }

      // Check if email is already taken
      const existingUser = await UserRepository.findByEmail(newEmail);
      if (existingUser && existingUser.id !== userId) {
        throw new UserAlreadyExistsError('email', newEmail);
      }

      // Generate new verification token
      const emailVerificationToken = CryptoUtils.general.generateSecureRandomString(64);

      await UserRepository.update(userId, {
        email: newEmail,
        emailVerified: false,
        emailVerificationToken
      });

      // TODO: Send email verification
      // await EmailService.sendEmailVerification(newEmail, emailVerificationToken);

      logger.info('User email updated', { userId, newEmail });

    } catch (error) {
      if (error instanceof UserNotFoundError || error instanceof UserAlreadyExistsError) {
        throw error;
      }
      
      logger.error('Update email error', { error, userId });
      throw new Errors.InternalServer('Failed to update email');
    }
  }

  /**
   * Update username
   */
  static async updateUsername(userId: string, newUsername: string): Promise<void> {
    try {
      const user = await UserRepository.findById(userId);
      if (!user) {
        throw new UserNotFoundError(userId);
      }

      // Check if username is already taken
      const existingUser = await UserRepository.findByUsername(newUsername);
      if (existingUser && existingUser.id !== userId) {
        throw new UserAlreadyExistsError('username', newUsername);
      }

      await UserRepository.update(userId, { username: newUsername });

      logger.info('User username updated', { userId, newUsername });

    } catch (error) {
      if (error instanceof UserNotFoundError || error instanceof UserAlreadyExistsError) {
        throw error;
      }
      
      logger.error('Update username error', { error, userId });
      throw new Errors.InternalServer('Failed to update username');
    }
  }

  /**
   * Deactivate user account
   */
  static async deactivateUser(userId: string, adminId: string): Promise<void> {
    try {
      const user = await UserRepository.findById(userId);
      if (!user) {
        throw new UserNotFoundError(userId);
      }

      await UserRepository.update(userId, { isActive: false });

      // TODO: Deactivate all user sessions
      // await SessionRepository.deactivateUserSessions(userId);

      logger.info('User account deactivated', { 
        userId, 
        adminId,
        username: user.username 
      });

    } catch (error) {
      if (error instanceof UserNotFoundError) {
        throw error;
      }
      
      logger.error('Deactivate user error', { error, userId });
      throw new Errors.InternalServer('Failed to deactivate user');
    }
  }

  /**
   * Reactivate user account
   */
  static async reactivateUser(userId: string, adminId: string): Promise<void> {
    try {
      const user = await UserRepository.findById(userId);
      if (!user) {
        throw new UserNotFoundError(userId);
      }

      await UserRepository.update(userId, { 
        isActive: true,
        loginAttempts: 0,
        lockUntil: null
      });

      logger.info('User account reactivated', { 
        userId, 
        adminId,
        username: user.username 
      });

    } catch (error) {
      if (error instanceof UserNotFoundError) {
        throw error;
      }
      
      logger.error('Reactivate user error', { error, userId });
      throw new Errors.InternalServer('Failed to reactivate user');
    }
  }

  /**
   * Delete user account (soft delete)
   */
  static async deleteUser(userId: string, adminId: string): Promise<void> {
    try {
      const user = await UserRepository.findById(userId);
      if (!user) {
        throw new UserNotFoundError(userId);
      }

      const success = await UserRepository.softDelete(userId);
      if (!success) {
        throw new Errors.InternalServer('Failed to delete user');
      }

      // TODO: Clean up user data
      // await SessionRepository.deactivateUserSessions(userId);
      // await UserRoleRepository.removeAllUserRoles(userId);

      logger.info('User account deleted', { 
        userId, 
        adminId,
        username: user.username 
      });

    } catch (error) {
      if (error instanceof UserNotFoundError) {
        throw error;
      }
      
      logger.error('Delete user error', { error, userId });
      throw new Errors.InternalServer('Failed to delete user');
    }
  }

  /**
   * Get user roles
   */
  static async getUserRoles(userId: string): Promise<string[]> {
    try {
      const user = await UserRepository.findById(userId);
      if (!user) {
        throw new UserNotFoundError(userId);
      }

      const roles = await RoleRepository.getUserRoles(userId);
      return roles.map(role => role.name);

    } catch (error) {
      if (error instanceof UserNotFoundError) {
        throw error;
      }
      
      logger.error('Get user roles error', { error, userId });
      throw new Errors.InternalServer('Failed to get user roles');
    }
  }

  /**
   * Get user permissions
   */
  static async getUserPermissions(userId: string): Promise<string[]> {
    try {
      const user = await UserRepository.findById(userId);
      if (!user) {
        throw new UserNotFoundError(userId);
      }

      const permissions = await RoleRepository.getUserPermissions(userId);
      return permissions.map(p => `${p.resource}:${p.action}`);

    } catch (error) {
      if (error instanceof UserNotFoundError) {
        throw error;
      }
      
      logger.error('Get user permissions error', { error, userId });
      throw new Errors.InternalServer('Failed to get user permissions');
    }
  }

  /**
   * Check if user has specific permission
   */
  static async hasPermission(userId: string, resource: string, action: string): Promise<boolean> {
    try {
      const user = await UserRepository.findById(userId);
      if (!user || !user.isActive) {
        return false;
      }

      return await RoleRepository.userHasPermission(userId, resource, action);

    } catch (error) {
      logger.error('Check permission error', { error, userId, resource, action });
      return false;
    }
  }

  /**
   * Assign role to user
   */
  static async assignRole(userId: string, roleId: string, assignedBy: string, expiresAt?: Date): Promise<void> {
    try {
      const user = await UserRepository.findById(userId);
      if (!user) {
        throw new UserNotFoundError(userId);
      }

      const role = await RoleRepository.findRoleById(roleId);
      if (!role) {
        throw new Errors.RoleNotFound(roleId);
      }

      await RoleRepository.assignRoleToUser(userId, roleId, assignedBy, expiresAt);

      logger.info('Role assigned to user', { 
        userId, 
        roleId, 
        roleName: role.name,
        assignedBy 
      });

    } catch (error) {
      if (error instanceof UserNotFoundError || error instanceof Errors.RoleNotFound) {
        throw error;
      }
      
      logger.error('Assign role error', { error, userId, roleId });
      throw new Errors.InternalServer('Failed to assign role');
    }
  }

  /**
   * Remove role from user
   */
  static async removeRole(userId: string, roleId: string, removedBy: string): Promise<void> {
    try {
      const user = await UserRepository.findById(userId);
      if (!user) {
        throw new UserNotFoundError(userId);
      }

      const role = await RoleRepository.findRoleById(roleId);
      if (!role) {
        throw new Errors.RoleNotFound(roleId);
      }

      const success = await RoleRepository.removeRoleFromUser(userId, roleId);
      if (!success) {
        throw new Errors.NotFound('Role assignment');
      }

      logger.info('Role removed from user', { 
        userId, 
        roleId, 
        roleName: role.name,
        removedBy 
      });

    } catch (error) {
      if (error instanceof UserNotFoundError || 
          error instanceof Errors.RoleNotFound || 
          error instanceof Errors.NotFound) {
        throw error;
      }
      
      logger.error('Remove role error', { error, userId, roleId });
      throw new Errors.InternalServer('Failed to remove role');
    }
  }

  /**
   * Search users by criteria
   */
  static async searchUsers(query: string, params: QueryParams = {}): Promise<PaginatedResult<PublicUser>> {
    try {
      const searchParams = {
        ...params,
        search: query
      };

      return await UserRepository.findMany(searchParams);

    } catch (error) {
      logger.error('Search users error', { error, query, params });
      throw new Errors.InternalServer('Failed to search users');
    }
  }

  /**
   * Get user statistics
   */
  static async getUserStats(): Promise<{
    totalUsers: number;
    activeUsers: number;
    inactiveUsers: number;
    verifiedUsers: number;
    unverifiedUsers: number;
  }> {
    try {
      const allUsers = await UserRepository.findMany({ limit: 999999 });
      
      const stats = {
        totalUsers: allUsers.meta.total,
        activeUsers: 0,
        inactiveUsers: 0,
        verifiedUsers: 0,
        unverifiedUsers: 0
      };

      // This is not efficient for large datasets
      // In production, you'd want to do this with SQL aggregation
      for (const user of allUsers.items) {
        if (user.isActive) {
          stats.activeUsers++;
        } else {
          stats.inactiveUsers++;
        }

        if (user.emailVerified) {
          stats.verifiedUsers++;
        } else {
          stats.unverifiedUsers++;
        }
      }

      return stats;

    } catch (error) {
      logger.error('Get user stats error', { error });
      throw new Errors.InternalServer('Failed to get user statistics');
    }
  }

  /**
   * Validate user exists and is active
   */
  static async validateUser(userId: string): Promise<User> {
    const user = await UserRepository.findById(userId);
    
    if (!user) {
      throw new UserNotFoundError(userId);
    }

    if (!user.isActive) {
      throw new Errors.AccountDeactivated();
    }

    return user;
  }

  /**
   * Reset user login attempts and unlock account
   */
  static async resetLoginAttempts(userId: string, adminId: string): Promise<void> {
    try {
      const user = await UserRepository.findById(userId);
      if (!user) {
        throw new UserNotFoundError(userId);
      }

      await UserRepository.update(userId, {
        loginAttempts: 0,
        lockUntil: null
      });

      logger.info('User login attempts reset', { 
        userId, 
        adminId,
        username: user.username 
      });

    } catch (error) {
      if (error instanceof UserNotFoundError) {
        throw error;
      }
      
      logger.error('Reset login attempts error', { error, userId });
      throw new Errors.InternalServer('Failed to reset login attempts');
    }
  }
}
import { Request } from 'express'

// Interfaces base para el usuario
export interface IUser {
  id: string
  username: string
  email: string
  password: string
  firstName?: string
  lastName?: string
  isActive: boolean
  emailVerified: boolean
  lastLogin?: Date
  failedLoginAttempts: number
  lockoutUntil?: Date
  createdAt: Date
  updatedAt: Date
  roles: IRole[]
}

export interface IUserPublic {
  id: string
  username: string
  email: string
  firstName?: string
  lastName?: string
  isActive: boolean
  emailVerified: boolean
  lastLogin?: Date
  createdAt: Date
  roles: IRolePublic[]
}

export interface IRole {
  id: string
  name: string
  description?: string
  isActive: boolean
  createdAt: Date
  updatedAt: Date
  permissions: IPermission[]
}

export interface IRolePublic {
  id: string
  name: string
  description?: string
}

export interface IPermission {
  id: string
  resource: string
  action: string
  description?: string
  createdAt: Date
}

// DTOs para crear/actualizar
export interface CreateUserDTO {
  username: string
  email: string
  password: string
  firstName?: string
  lastName?: string
  roleIds?: string[]
}

export interface UpdateUserDTO {
  username?: string
  email?: string
  firstName?: string
  lastName?: string
  isActive?: boolean
  roleIds?: string[]
}

export interface CreateRoleDTO {
  name: string
  description?: string
  permissionIds?: string[]
}

export interface UpdateRoleDTO {
  name?: string
  description?: string
  isActive?: boolean
  permissionIds?: string[]
}

export interface CreatePermissionDTO {
  resource: string
  action: string
  description?: string
}

// Autenticación y autorización
export interface LoginDTO {
  username: string
  password: string
  rememberMe?: boolean
}

export interface RegisterDTO {
  username: string
  email: string
  password: string
  confirmPassword: string
  firstName?: string
  lastName?: string
}

export interface AuthTokens {
  accessToken: string
  refreshToken: string
  tokenType: 'Bearer'
  expiresIn: number
}

export interface JWTPayload {
  sub: string // user id
  username: string
  email: string
  roles: string[]
  permissions: string[]
  iat: number
  exp: number
  iss: string
  aud: string
}

export interface RefreshTokenPayload {
  sub: string
  username: string
  tokenVersion: number
  iat: number
  exp: number
  iss: string
  aud: string
}

// Request extendido con información de autenticación
export interface AuthenticatedRequest extends Request {
  user?: IUserPublic
  permissions?: string[]
  tokenPayload?: JWTPayload
}

// Respuestas de la API
export interface AuthResponse {
  success: boolean
  message: string
  data?: {
    user?: IUserPublic
    tokens?: AuthTokens
  }
  errors?: string[]
}

export interface APIResponse<T = any> {
  success: boolean
  message: string
  data?: T
  pagination?: {
    page: number
    limit: number
    total: number
    totalPages: number
  }
  errors?: string[]
}

// Filtros y paginación
export interface PaginationOptions {
  page?: number
  limit?: number
  sortBy?: string
  sortOrder?: 'ASC' | 'DESC'
}

export interface UserFilters {
  isActive?: boolean
  emailVerified?: boolean
  roleId?: string
  search?: string
}

export interface RoleFilters {
  isActive?: boolean
  search?: string
}

// Configuración RBAC
export interface RBACConfig {
  defaultRoles: string[]
  superAdminRole: string
  guestRole: string
  autoAssignDefaultRole: boolean
  inheritanceEnabled: boolean
}

// Eventos de auditoría
export interface AuditEvent {
  id: string
  userId?: string
  action: string
  resource: string
  details?: Record<string, any>
  ipAddress?: string
  userAgent?: string
  timestamp: Date
  success: boolean
}

// Tipos de acciones para auditoría
export enum AuditAction {
  LOGIN = 'LOGIN',
  LOGOUT = 'LOGOUT',
  REGISTER = 'REGISTER',
  PASSWORD_CHANGE = 'PASSWORD_CHANGE',
  PASSWORD_RESET = 'PASSWORD_RESET',
  USER_CREATE = 'USER_CREATE',
  USER_UPDATE = 'USER_UPDATE',
  USER_DELETE = 'USER_DELETE',
  ROLE_ASSIGN = 'ROLE_ASSIGN',
  ROLE_REVOKE = 'ROLE_REVOKE',
  PERMISSION_CHECK = 'PERMISSION_CHECK',
  ACCESS_DENIED = 'ACCESS_DENIED'
}

// Rate limiting
export interface RateLimitInfo {
  totalRequests: number
  remainingRequests: number
  resetTime: Date
  blocked: boolean
}

// Sesiones activas
export interface ActiveSession {
  id: string
  userId: string
  tokenHash: string
  ipAddress: string
  userAgent: string
  createdAt: Date
  lastActivity: Date
  isValid: boolean
}
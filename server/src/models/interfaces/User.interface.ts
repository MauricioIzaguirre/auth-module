import { IUser, IUserPublic, CreateUserDTO, UpdateUserDTO, UserFilters, PaginationOptions, APIResponse } from '../../types/auth.types'

// Interface para el modelo de usuario (abstracción para diferentes bases de datos)
export interface IUserModel {
  // Operaciones CRUD básicas
  create(userData: CreateUserDTO): Promise<IUser>
  findById(id: string): Promise<IUser | null>
  findByUsername(username: string): Promise<IUser | null>
  findByEmail(email: string): Promise<IUser | null>
  update(id: string, userData: UpdateUserDTO): Promise<IUser | null>
  delete(id: string): Promise<boolean>
  
  // Operaciones de listado y búsqueda
  findAll(filters?: UserFilters, pagination?: PaginationOptions): Promise<{
    users: IUserPublic[]
    total: number
  }>
  
  // Operaciones específicas de autenticación
  incrementFailedAttempts(id: string): Promise<void>
  resetFailedAttempts(id: string): Promise<void>
  setLockout(id: string, lockoutUntil: Date): Promise<void>
  updateLastLogin(id: string): Promise<void>
  updatePassword(id: string, hashedPassword: string): Promise<void>
  
  // Operaciones de roles
  assignRole(userId: string, roleId: string): Promise<void>
  removeRole(userId: string, roleId: string): Promise<void>
  getUserRoles(userId: string): Promise<string[]>
  getUserPermissions(userId: string): Promise<string[]>
  
  // Verificaciones
  existsByUsername(username: string): Promise<boolean>
  existsByEmail(email: string): Promise<boolean>
  isUserLocked(id: string): Promise<boolean>
  
  // Operaciones de sesión
  createSession(userId: string, sessionData: CreateSessionDTO): Promise<ISession>
  invalidateSession(sessionId: string): Promise<void>
  invalidateUserSessions(userId: string): Promise<void>
  getUserActiveSessions(userId: string): Promise<ISession[]>
  
  // Auditoría
  getLoginHistory(userId: string, limit?: number): Promise<ILoginHistory[]>
  createAuditLog(auditData: CreateAuditLogDTO): Promise<void>
}

// DTOs adicionales para user
export interface CreateSessionDTO {
  tokenHash: string
  ipAddress: string
  userAgent: string
  expiresAt: Date
}

export interface ISession {
  id: string
  userId: string
  tokenHash: string
  ipAddress: string
  userAgent: string
  createdAt: Date
  lastActivity: Date
  expiresAt: Date
  isValid: boolean
}

export interface ILoginHistory {
  id: string
  userId: string
  ipAddress: string
  userAgent: string
  success: boolean
  timestamp: Date
  failureReason?: string
}

export interface CreateAuditLogDTO {
  userId?: string
  action: string
  resource: string
  resourceId?: string
  details?: Record<string, any>
  ipAddress?: string
  userAgent?: string
  success: boolean
}

export interface IAuditLog {
  id: string
  userId?: string
  action: string
  resource: string
  resourceId?: string
  details?: Record<string, any>
  ipAddress?: string
  userAgent?: string
  success: boolean
  timestamp: Date
}

// Tipos para validaciones específicas del usuario
export interface UserValidationRules {
  username: {
    minLength: number
    maxLength: number
    allowedChars: RegExp
    reservedNames: string[]
  }
  email: {
    maxLength: number
    domainWhitelist?: string[]
    domainBlacklist?: string[]
  }
  password: {
    minLength: number
    maxLength: number
    requireUppercase: boolean
    requireLowercase: boolean
    requireNumbers: boolean
    requireSpecialChars: boolean
    forbiddenPatterns: RegExp[]
  }
}

// Respuestas específicas para operaciones de usuario
export interface UserCreationResponse extends APIResponse {
  data?: {
    user: IUserPublic
    temporaryPassword?: string
  }
}

export interface UserListResponse extends APIResponse {
  data?: {
    users: IUserPublic[]
    pagination: {
      page: number
      limit: number
      total: number
      totalPages: number
    }
  }
}
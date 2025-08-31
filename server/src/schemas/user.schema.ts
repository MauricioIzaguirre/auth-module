import { z } from 'zod'
import { ValidationUtils } from '../utils/validation.utils'

// Schema base para usuario
const baseUserSchema = z.object({
  username: z.string()
    .min(3, 'El nombre de usuario debe tener al menos 3 caracteres')
    .max(30, 'El nombre de usuario no puede tener más de 30 caracteres')
    .regex(/^[a-zA-Z0-9_.-]+$/, 'El nombre de usuario solo puede contener letras, números, guiones, puntos y guiones bajos')
    .refine(
      val => !val.match(/^[._-]|[._-]$/),
      'El nombre de usuario no puede empezar o terminar con caracteres especiales'
    )
    .refine(
      val => !['admin', 'administrator', 'root', 'system', 'api', 'www', 'ftp', 'mail', 'email', 'user', 'test', 'demo', 'guest', 'null', 'undefined'].includes(val.toLowerCase()),
      'Nombre de usuario reservado'
    ),

  email: z.string()
    .email('Formato de email inválido')
    .max(254, 'El email es demasiado largo')
    .toLowerCase()
    .refine(
      val => {
        const domain = val.split('@')[1]
        const suspiciousDomains = ['10minutemail.com', 'guerrillamail.com', 'tempmail.org']
        return !suspiciousDomains.includes(domain)
      },
      'Dominio de email no permitido'
    ),

  password: z.string()
    .min(8, 'La contraseña debe tener al menos 8 caracteres')
    .max(128, 'La contraseña no puede tener más de 128 caracteres')
    .refine(
      val => ValidationUtils.validatePassword(val).isValid,
      val => ValidationUtils.validatePassword(val).errors.join(', ')
    ),

  firstName: z.string()
    .min(1, 'El nombre es requerido')
    .max(50, 'El nombre no puede tener más de 50 caracteres')
    .regex(/^[a-zA-ZÀ-ÿ\u0100-\u017F\s'-]+$/, 'El nombre solo puede contener letras, espacios, guiones y apostrofes')
    .transform(val => val.trim().toLowerCase().split(' ').map(word => 
      word.charAt(0).toUpperCase() + word.slice(1)).join(' ')
    )
    .optional(),

  lastName: z.string()
    .min(1, 'El apellido es requerido')
    .max(50, 'El apellido no puede tener más de 50 caracteres')
    .regex(/^[a-zA-ZÀ-ÿ\u0100-\u017F\s'-]+$/, 'El apellido solo puede contener letras, espacios, guiones y apostrofes')
    .transform(val => val.trim().toLowerCase().split(' ').map(word => 
      word.charAt(0).toUpperCase() + word.slice(1)).join(' ')
    )
    .optional(),

  isActive: z.boolean().default(true),
  emailVerified: z.boolean().default(false),
  roleIds: z.array(z.string().uuid('ID de rol debe ser un UUID válido')).optional()
})

// Schema para crear usuario
export const createUserSchema = baseUserSchema.extend({
  confirmPassword: z.string()
}).refine(
  data => data.password === data.confirmPassword,
  {
    message: 'Las contraseñas no coinciden',
    path: ['confirmPassword']
  }
)

// Schema para actualizar usuario (todos los campos opcionales excepto validaciones)
export const updateUserSchema = baseUserSchema.partial().extend({
  id: z.string().uuid('ID de usuario debe ser un UUID válido')
}).omit({ password: true }) // El password se actualiza por separado

// Schema para cambio de contraseña
export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Contraseña actual es requerida'),
  newPassword: z.string()
    .min(8, 'La nueva contraseña debe tener al menos 8 caracteres')
    .max(128, 'La nueva contraseña no puede tener más de 128 caracteres')
    .refine(
      val => ValidationUtils.validatePassword(val).isValid,
      val => ValidationUtils.validatePassword(val).errors.join(', ')
    ),
  confirmNewPassword: z.string()
}).refine(
  data => data.newPassword === data.confirmNewPassword,
  {
    message: 'Las nuevas contraseñas no coinciden',
    path: ['confirmNewPassword']
  }
).refine(
  data => data.currentPassword !== data.newPassword,
  {
    message: 'La nueva contraseña debe ser diferente a la actual',
    path: ['newPassword']
  }
)

// Schema para reset de contraseña
export const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Token de reset es requerido'),
  newPassword: z.string()
    .min(8, 'La contraseña debe tener al menos 8 caracteres')
    .max(128, 'La contraseña no puede tener más de 128 caracteres')
    .refine(
      val => ValidationUtils.validatePassword(val).isValid,
      val => ValidationUtils.validatePassword(val).errors.join(', ')
    ),
  confirmNewPassword: z.string()
}).refine(
  data => data.newPassword === data.confirmNewPassword,
  {
    message: 'Las contraseñas no coinciden',
    path: ['confirmNewPassword']
  }
)

// Schema para solicitud de reset de contraseña
export const requestPasswordResetSchema = z.object({
  email: z.string()
    .email('Formato de email inválido')
    .toLowerCase()
})

// Schema para asignación de roles
export const assignRoleSchema = z.object({
  userId: z.string().uuid('ID de usuario debe ser un UUID válido'),
  roleId: z.string().uuid('ID de rol debe ser un UUID válido')
})

// Schema para asignación múltiple de roles
export const assignMultipleRolesSchema = z.object({
  userId: z.string().uuid('ID de usuario debe ser un UUID válido'),
  roleIds: z.array(z.string().uuid('ID de rol debe ser un UUID válido'))
    .min(1, 'Debe proporcionar al menos un rol')
    .max(10, 'No puede asignar más de 10 roles a la vez')
})

// Schema para filtros de usuario
export const userFiltersSchema = z.object({
  isActive: z.boolean().optional(),
  emailVerified: z.boolean().optional(),
  roleId: z.string().uuid().optional(),
  search: z.string().max(100).optional(),
  createdAfter: z.string().datetime().optional(),
  createdBefore: z.string().datetime().optional()
})

// Schema para paginación
export const paginationSchema = z.object({
  page: z.number().int().min(1).default(1).or(z.string().transform(val => parseInt(val)).pipe(z.number().int().min(1))),
  limit: z.number().int().min(1).max(100).default(10).or(z.string().transform(val => parseInt(val)).pipe(z.number().int().min(1).max(100))),
  sortBy: z.string().max(50).optional(),
  sortOrder: z.enum(['ASC', 'DESC']).default('ASC')
})

// Schema para parámetros de ID
export const idParamSchema = z.object({
  id: z.string().uuid('ID debe ser un UUID válido')
})

// Schema para búsqueda de usuarios
export const userSearchSchema = z.object({
  query: z.string()
    .min(2, 'La búsqueda debe tener al menos 2 caracteres')
    .max(100, 'La búsqueda no puede tener más de 100 caracteres')
    .transform(val => ValidationUtils.sanitizeInput(val)),
  fields: z.array(z.enum(['username', 'email', 'firstName', 'lastName'])).optional(),
  exact: z.boolean().default(false)
})

// Schema para cambio de estado de usuario
export const userStatusSchema = z.object({
  isActive: z.boolean(),
  reason: z.string().max(500).optional()
})

// Schema para verificación de email
export const emailVerificationSchema = z.object({
  token: z.string().min(1, 'Token de verificación es requerido'),
  email: z.string().email('Formato de email inválido').toLowerCase()
})

// Funciones de validación exportadas
export const validateCreateUser = (data: unknown) => {
  return createUserSchema.safeParse(data)
}

export const validateUpdateUser = (data: unknown) => {
  return updateUserSchema.safeParse(data)
}

export const validateChangePassword = (data: unknown) => {
  return changePasswordSchema.safeParse(data)
}

export const validateResetPassword = (data: unknown) => {
  return resetPasswordSchema.safeParse(data)
}

export const validateRequestPasswordReset = (data: unknown) => {
  return requestPasswordResetSchema.safeParse(data)
}

export const validateAssignRole = (data: unknown) => {
  return assignRoleSchema.safeParse(data)
}

export const validateAssignMultipleRoles = (data: unknown) => {
  return assignMultipleRolesSchema.safeParse(data)
}

export const validateUserFilters = (data: unknown) => {
  return userFiltersSchema.safeParse(data)
}

export const validatePagination = (data: unknown) => {
  return paginationSchema.safeParse(data)
}

export const validateIdParam = (data: unknown) => {
  return idParamSchema.safeParse(data)
}

export const validateUserSearch = (data: unknown) => {
  return userSearchSchema.safeParse(data)
}

export const validateUserStatus = (data: unknown) => {
  return userStatusSchema.safeParse(data)
}

export const validateEmailVerification = (data: unknown) => {
  return emailVerificationSchema.safeParse(data)
}
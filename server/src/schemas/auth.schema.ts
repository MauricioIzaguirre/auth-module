// server/src/schemas/auth.schema.ts
import { z } from 'zod'
import { ValidationUtils } from '../utils/validation.utils'

// Schema para login
export const loginSchema = z.object({
  username: z.string()
    .min(1, 'Nombre de usuario o email requerido')
    .max(254, 'Nombre de usuario o email demasiado largo')
    .transform(val => val.trim().toLowerCase()),
  
  password: z.string()
    .min(1, 'Contraseña requerida')
    .max(128, 'Contraseña demasiado larga'),
    
  rememberMe: z.boolean().optional().default(false)
})

// Schema para registro
export const registerSchema = z.object({
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
    )
    .transform(val => val.trim().toLowerCase()),

  email: z.string()
    .email('Formato de email inválido')
    .max(254, 'El email es demasiado largo')
    .toLowerCase()
    .refine(
      val => {
        const domain = val.split('@')[1]
        if (!domain) return false
        const suspiciousDomains = ['10minutemail.com', 'guerrillamail.com', 'tempmail.org']
        return !suspiciousDomains.includes(domain)
      },
      'Dominio de email no permitido'
    ),

  password: z.string()
    .min(8, 'La contraseña debe tener al menos 8 caracteres')
    .max(128, 'La contraseña no puede tener más de 128 caracteres')
    .refine(
      (val: string) => ValidationUtils.validatePassword(val).isValid,
      (val: string) => ({
        message: ValidationUtils.validatePassword(val).errors.join(', ')
      })
    ),

  confirmPassword: z.string(),

  firstName: z.string()
    .min(1, 'El nombre es requerido')
    .max(50, 'El nombre no puede tener más de 50 caracteres')
    .regex(/^[a-zA-ZÀ-ÿ\u0100-\u017F\s'-]+$/, 'El nombre solo puede contener letras, espacios, guiones y apostrofes')
    .transform(val => ValidationUtils.sanitizeInput(val).trim())
    .optional(),

  lastName: z.string()
    .min(1, 'El apellido es requerido')
    .max(50, 'El apellido no puede tener más de 50 caracteres')
    .regex(/^[a-zA-ZÀ-ÿ\u0100-\u017F\s'-]+$/, 'El apellido solo puede contener letras, espacios, guiones y apostrofes')
    .transform(val => ValidationUtils.sanitizeInput(val).trim())
    .optional()
}).refine(
  data => data.password === data.confirmPassword,
  {
    message: 'Las contraseñas no coinciden',
    path: ['confirmPassword']
  }
)

// Schema para cambio de contraseña
export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Contraseña actual requerida'),
  newPassword: z.string()
    .min(8, 'La nueva contraseña debe tener al menos 8 caracteres')
    .max(128, 'La nueva contraseña no puede tener más de 128 caracteres')
    .refine(
      (val: string) => ValidationUtils.validatePassword(val).isValid,
      (val: string) => ({
        message: ValidationUtils.validatePassword(val).errors.join(', ')
      })
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

// Schema para solicitud de reset de contraseña
export const requestPasswordResetSchema = z.object({
  email: z.string()
    .email('Formato de email inválido')
    .max(254, 'El email es demasiado largo')
    .toLowerCase()
})

// Schema para reset de contraseña
export const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Token de reset requerido'),
  newPassword: z.string()
    .min(8, 'La contraseña debe tener al menos 8 caracteres')
    .max(128, 'La contraseña no puede tener más de 128 caracteres')
    .refine(
      (val: string) => ValidationUtils.validatePassword(val).isValid,
      (val: string) => ({
        message: ValidationUtils.validatePassword(val).errors.join(', ')
      })
    ),
  confirmNewPassword: z.string()
}).refine(
  data => data.newPassword === data.confirmNewPassword,
  {
    message: 'Las contraseñas no coinciden',
    path: ['confirmNewPassword']
  }
)

// Schema para verificación de email
export const verifyEmailSchema = z.object({
  token: z.string().min(1, 'Token de verificación requerido'),
  email: z.string()
    .email('Formato de email inválido')
    .toLowerCase()
    .optional()
})

// Schema para reenvío de verificación de email
export const resendVerificationSchema = z.object({
  email: z.string()
    .email('Formato de email inválido')
    .max(254, 'El email es demasiado largo')
    .toLowerCase()
})

// Schema para refresh token
export const refreshTokenSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token requerido')
})

// Schema para logout
export const logoutSchema = z.object({
  refreshToken: z.string().optional(),
  logoutAll: z.boolean().default(false)
})

// Schema para validar token JWT
export const jwtTokenSchema = z.object({
  token: z.string().min(1, 'Token JWT requerido')
})

// Funciones de validación exportadas
export const validateLogin = (data: unknown) => {
  return loginSchema.safeParse(data)
}

export const validateRegister = (data: unknown) => {
  return registerSchema.safeParse(data)
}

export const validateChangePassword = (data: unknown) => {
  return changePasswordSchema.safeParse(data)
}

export const validateRequestPasswordReset = (data: unknown) => {
  return requestPasswordResetSchema.safeParse(data)
}

export const validateResetPassword = (data: unknown) => {
  return resetPasswordSchema.safeParse(data)
}

export const validateVerifyEmail = (data: unknown) => {
  return verifyEmailSchema.safeParse(data)
}

export const validateResendVerification = (data: unknown) => {
  return resendVerificationSchema.safeParse(data)
}

export const validateRefreshToken = (data: unknown) => {
  return refreshTokenSchema.safeParse(data)
}

export const validateLogout = (data: unknown) => {
  return logoutSchema.safeParse(data)
}

export const validateJWTToken = (data: unknown) => {
  return jwtTokenSchema.safeParse(data)
}
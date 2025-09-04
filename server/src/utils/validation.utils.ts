import { authConfig } from '../config/auth'

export class ValidationUtils {
  /**
   * Valida si una contraseña cumple con las políticas de seguridad
   */
  static validatePassword(password: string): {
    isValid: boolean
    errors: string[]
    strength: 'weak' | 'medium' | 'strong' | 'very_strong'
  } {
    const errors: string[] = []
    const policy = authConfig.security.passwordPolicy

    // Longitud mínima
    if (password.length < policy.minLength) {
      errors.push(`La contraseña debe tener al menos ${policy.minLength} caracteres`)
    }

    // Mayúsculas
    if (policy.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('La contraseña debe contener al menos una letra mayúscula')
    }

    // Minúsculas
    if (policy.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('La contraseña debe contener al menos una letra minúscula')
    }

    // Números
    if (policy.requireNumbers && !/\d/.test(password)) {
      errors.push('La contraseña debe contener al menos un número')
    }

    // Caracteres especiales
    if (policy.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('La contraseña debe contener al menos un carácter especial')
    }

    // Patrones comunes débiles
    const weakPatterns = [
      /(.)\1{2,}/, // Caracteres repetidos
      /123456|abcdef|qwerty|password|admin/i, // Secuencias comunes
      /^(.{1,3})\1+$/ // Patrones repetitivos
    ]

    for (const pattern of weakPatterns) {
      if (pattern.test(password)) {
        errors.push('La contraseña contiene patrones comunes inseguros')
        break
      }
    }

    // Calcular fortaleza
    const strength = this.calculatePasswordStrength(password)

    return {
      isValid: errors.length === 0,
      errors,
      strength
    }
  }

  /**
   * Calcula la fortaleza de una contraseña
   */
  private static calculatePasswordStrength(password: string): 'weak' | 'medium' | 'strong' | 'very_strong' {
    let score = 0

    // Longitud
    if (password.length >= 8) score += 1
    if (password.length >= 12) score += 1
    if (password.length >= 16) score += 1

    // Variedad de caracteres
    if (/[a-z]/.test(password)) score += 1
    if (/[A-Z]/.test(password)) score += 1
    if (/\d/.test(password)) score += 1
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score += 1

    // Complejidad adicional
    if (/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])/.test(password)) score += 1

    if (score <= 3) return 'weak'
    if (score <= 5) return 'medium'
    if (score <= 7) return 'strong'
    return 'very_strong'
  }

  /**
   * Valida formato de email
   */
  static validateEmail(email: string): {
    isValid: boolean
    errors: string[]
  } {
    const errors: string[] = []

    // Regex más estricto para email
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/

    if (!emailRegex.test(email)) {
      errors.push('Formato de email inválido')
    }

    if (email.length > 254) {
      errors.push('El email es demasiado largo')
    }

    // Verificar dominios sospechosos
    const suspiciousDomains = ['10minutemail.com', 'guerrillamail.com', 'tempmail.org']
    const domain = email.split('@')[1]?.toLowerCase()
    
    if (domain && suspiciousDomains.includes(domain)) {
      errors.push('Dominio de email no permitido')
    }

    return {
      isValid: errors.length === 0,
      errors
    }
  }

  /**
   * Valida formato de username
   */
  static validateUsername(username: string): {
    isValid: boolean
    errors: string[]
  } {
    const errors: string[] = []

    // Longitud
    if (username.length < 3) {
      errors.push('El nombre de usuario debe tener al menos 3 caracteres')
    }

    if (username.length > 30) {
      errors.push('El nombre de usuario no puede tener más de 30 caracteres')
    }

    // Formato
    if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
      errors.push('El nombre de usuario solo puede contener letras, números, guiones, puntos y guiones bajos')
    }

    // No puede empezar o terminar con caracteres especiales
    if (/^[._-]|[._-]$/.test(username)) {
      errors.push('El nombre de usuario no puede empezar o terminar con caracteres especiales')
    }

    // Nombres reservados
    const reservedNames = [
      'admin', 'administrator', 'root', 'system', 'api', 'www', 'ftp', 'mail',
      'email', 'user', 'test', 'demo', 'guest', 'null', 'undefined'
    ]

    if (reservedNames.includes(username.toLowerCase())) {
      errors.push('Nombre de usuario reservado')
    }

    return {
      isValid: errors.length === 0,
      errors
    }
  }

  /**
   * Sanitiza entrada de usuario para prevenir XSS
   */
  static sanitizeInput(input: string): string {
    return input
      .replace(/[<>\"'&]/g, match => {
        const escapeMap: Record<string, string> = {
          '<': '&lt;',
          '>': '&gt;',
          '"': '&quot;',
          "'": '&#x27;',
          '&': '&amp;'
        }
        return escapeMap[match] || match
      })
      .trim()
  }

  /**
   * Valida y sanitiza SQL input para prevenir inyecciones
   */
  static validateSQLInput(input: string): {
    isValid: boolean
    sanitized: string
    errors: string[]
  } {
    const errors: string[] = []
    let sanitized = input.trim()

    // Patrones sospechosos de SQL injection
    const sqlInjectionPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)/i,
      /(--|\|\||&&|\/\*|\*\/)/,
      /(\bOR\b|\bAND\b).*?[=<>]/i,
      /[';\\x00\\x1a"]/
    ]

    for (const pattern of sqlInjectionPatterns) {
      if (pattern.test(input)) {
        errors.push('Entrada contiene caracteres o patrones no permitidos')
        break
      }
    }

    // Sanitizar caracteres peligrosos
    sanitized = sanitized
      .replace(/['"\\;]/g, '')
      .replace(/--.*$/gm, '')
      .replace(/\/\*.*?\*\//gs, '')

    return {
      isValid: errors.length === 0,
      sanitized,
      errors
    }
  }

  /**
   * Valida dirección IP
   */
  static validateIPAddress(ip: string): boolean {
    const ipv4Regex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/
    const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/

    return ipv4Regex.test(ip) || ipv6Regex.test(ip)
  }

  /**
   * Valida UUID
   */
  static validateUUID(uuid: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    return uuidRegex.test(uuid)
  }

  /**
   * Normaliza y valida número de teléfono
   */
  static validatePhoneNumber(phone: string): {
    isValid: boolean
    normalized: string
    errors: string[]
  } {
    const errors: string[] = []
    let normalized = phone.replace(/\D/g, '') // Remover caracteres no numéricos

    // Validar longitud básica
    if (normalized.length < 7 || normalized.length > 15) {
      errors.push('Número de teléfono debe tener entre 7 y 15 dígitos')
    }

    // Formatear para almacenamiento internacional
    if (normalized.length === 10 && !normalized.startsWith('1')) {
      normalized = '1' + normalized // Asumir código de país US
    }

    return {
      isValid: errors.length === 0,
      normalized: '+' + normalized,
      errors
    }
  }

  /**
   * Valida y extrae información de User Agent
   */
  static parseUserAgent(userAgent: string): {
    browser: string
    version: string
    os: string
    device: string
    isMobile: boolean
    isBot: boolean
  } {
    const botPatterns = [
      /bot|crawler|spider|scraper/i,
      /google|bing|yahoo|duckduck/i,
      /facebook|twitter|linkedin/i
    ]

    const isBot = botPatterns.some(pattern => pattern.test(userAgent))

    // Detección básica de browser
    let browser = 'Unknown'
    let version = 'Unknown'

    if (userAgent.includes('Chrome/')) {
      browser = 'Chrome'
      version = userAgent.match(/Chrome\/([^\s]+)/)?.[1] || 'Unknown'
    } else if (userAgent.includes('Firefox/')) {
      browser = 'Firefox'
      version = userAgent.match(/Firefox\/([^\s]+)/)?.[1] || 'Unknown'
    } else if (userAgent.includes('Safari/') && !userAgent.includes('Chrome')) {
      browser = 'Safari'
      version = userAgent.match(/Version\/([^\s]+)/)?.[1] || 'Unknown'
    } else if (userAgent.includes('Edge/')) {
      browser = 'Edge'
      version = userAgent.match(/Edge\/([^\s]+)/)?.[1] || 'Unknown'
    }

    // Detección de OS
    let os = 'Unknown'
    if (userAgent.includes('Windows')) os = 'Windows'
    else if (userAgent.includes('Mac OS')) os = 'macOS'
    else if (userAgent.includes('Linux')) os = 'Linux'
    else if (userAgent.includes('Android')) os = 'Android'
    else if (userAgent.includes('iOS')) os = 'iOS'

    // Detección de dispositivo
    const isMobile = /Mobile|Android|iPhone|iPad/.test(userAgent)
    let device = 'Desktop'
    if (userAgent.includes('iPhone')) device = 'iPhone'
    else if (userAgent.includes('iPad')) device = 'iPad'
    else if (userAgent.includes('Android')) device = 'Android'
    else if (isMobile) device = 'Mobile'

    return {
      browser,
      version,
      os,
      device,
      isMobile,
      isBot
    }
  }

  /**
   * Valida fecha de nacimiento
   */
  static validateBirthDate(birthDate: string | Date): {
    isValid: boolean
    age: number
    errors: string[]
  } {
    const errors: string[] = []
    const date = new Date(birthDate)
    const now = new Date()

    if (isNaN(date.getTime())) {
      errors.push('Fecha de nacimiento inválida')
      return { isValid: false, age: 0, errors }
    }

    // No puede ser fecha futura
    if (date > now) {
      errors.push('La fecha de nacimiento no puede ser en el futuro')
    }

    // Calcular edad
    const age = Math.floor((now.getTime() - date.getTime()) / (365.25 * 24 * 60 * 60 * 1000))

    // Edad mínima (13 años por COPPA)
    if (age < 13) {
      errors.push('Debe ser mayor de 13 años para registrarse')
    }

    // Edad máxima razonable
    if (age > 120) {
      errors.push('Edad no válida')
    }

    return {
      isValid: errors.length === 0,
      age,
      errors
    }
  }

  /**
   * Valida formato de nombre (firstName, lastName)
   */
  static validateName(name: string): {
    isValid: boolean
    sanitized: string
    errors: string[]
  } {
    const errors: string[] = []
    let sanitized = name.trim()

    // Longitud
    if (sanitized.length < 1) {
      errors.push('El nombre no puede estar vacío')
    }

    if (sanitized.length > 50) {
      errors.push('El nombre no puede tener más de 50 caracteres')
    }

    // Solo letras, espacios, guiones y apostrofes
    if (!/^[a-zA-ZÀ-ÿ\u0100-\u017F\s'-]+$/.test(sanitized)) {
      errors.push('El nombre solo puede contener letras, espacios, guiones y apostrofes')
    }

    // No puede empezar o terminar con espacios o caracteres especiales
    if (/^[\s'-]|[\s'-]$/.test(sanitized)) {
      errors.push('El nombre no puede empezar o terminar con espacios o caracteres especiales')
    }

    // Capitalizar correctamente
    sanitized = sanitized
      .toLowerCase()
      .split(' ')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ')

    return {
      isValid: errors.length === 0,
      sanitized,
      errors
    }
  }

  /**
   * Valida ID de recurso (UUID)
   */
  static validateResourceId(id: string, resourceName: string = 'recurso'): {
    isValid: boolean
    errors: string[]
  } {
    const errors: string[] = []

    if (!id || typeof id !== 'string') {
      errors.push(`ID de ${resourceName} es requerido`)
      return { isValid: false, errors }
    }

    if (!this.validateUUID(id)) {
      errors.push(`ID de ${resourceName} debe ser un UUID válido`)
    }

    return {
      isValid: errors.length === 0,
      errors
    }
  }


  /**
   * Valida parámetros de paginación
   */
  static validatePagination(page?: number, limit?: number): {
    isValid: boolean
    page: number
    limit: number
    errors: string[]
  } {
    const errors: string[] = []
    let validatedPage = page || 1
    let validatedLimit = limit || 10

    // Página mínima
    if (validatedPage < 1) {
      validatedPage = 1
      errors.push('La página debe ser mayor a 0')
    }

    // Límite mínimo y máximo
    if (validatedLimit < 1) {
      validatedLimit = 10
      errors.push('El límite debe ser mayor a 0')
    }

    if (validatedLimit > 100) {
      validatedLimit = 100
      errors.push('El límite no puede ser mayor a 100')
    }

    return {
      isValid: errors.length === 0,
      page: validatedPage,
      limit: validatedLimit,
      errors
    }
  }

  /**
   * Valida formato de permiso (resource:action)
   */
  static validatePermissionFormat(permission: string): {
    isValid: boolean
    resource: string
    action: string
    errors: string[]
  } {
    const errors: string[] = []
    const parts = permission.split(':')

    if (parts.length !== 2) {
      errors.push('El permiso debe tener el formato "recurso:acción"')
      return { isValid: false, resource: '', action: '', errors }
    }

    const resource = parts[0]?.trim()
    const action = parts[1]?.trim()

    if (!resource || resource.length === 0) {
      errors.push('El recurso no puede estar vacío')
    }

    if (!action || action.length === 0) {
      errors.push('La acción no puede estar vacía')
    }

    // Validar formato de caracteres solo si resource y action están definidos
    if (resource && !/^[a-z_]+$/.test(resource)) {
      errors.push('El recurso solo puede contener letras minúsculas y guiones bajos')
    }

    if (action && !/^[a-z_]+$/.test(action)) {
      errors.push('La acción solo puede contener letras minúsculas y guiones bajos')
    }

    return {
      isValid: errors.length === 0,
      resource: resource || '',
      action: action || '',
      errors
    }
  }
}
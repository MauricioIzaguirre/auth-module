// server/src/services/email.service.ts
import nodemailer, { Transporter } from 'nodemailer'
import { logger } from '../utils/logger'
import { appConfig } from '../config'

interface EmailConfig {
  smtp: {
    host: string
    port: number
    secure: boolean
    auth: {
      user: string
      pass: string
    }
  }
  from: {
    name: string
    email: string
  }
  templates: {
    baseUrl: string
  }
}

export class EmailService {
  private transporter: Transporter
  private config: EmailConfig

  constructor() {
    this.config = this.getEmailConfig()
    this.transporter = this.createTransporter()
  }

  private getEmailConfig(): EmailConfig {
    return {
      smtp: {
        host: process.env.SMTP_HOST || 'localhost',
        port: parseInt(process.env.SMTP_PORT || '587'),
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER || '',
          pass: process.env.SMTP_PASS || ''
        }
      },
      from: {
        name: process.env.EMAIL_FROM_NAME || 'Clínica Oftalmológica',
        email: process.env.EMAIL_FROM_ADDRESS || 'noreply@clinica.com'
      },
      templates: {
        baseUrl: process.env.FRONTEND_URL || 'http://localhost:3000'
      }
    }
  }

  private createTransporter(): Transporter {
    if (appConfig.nodeEnv === 'development' || appConfig.nodeEnv === 'test') {
      // Use ethereal for development/testing
      return nodemailer.createTransporter({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: {
          user: 'ethereal.user@ethereal.email',
          pass: 'ethereal.pass'
        }
      })
    }

    return nodemailer.createTransporter({
      host: this.config.smtp.host,
      port: this.config.smtp.port,
      secure: this.config.smtp.secure,
      auth: {
        user: this.config.smtp.auth.user,
        pass: this.config.smtp.auth.pass
      }
    })
  }

  async sendEmailVerification(email: string, token: string, name?: string): Promise<void> {
    try {
      const verificationUrl = `${this.config.templates.baseUrl}/auth/verify-email?token=${token}`
      
      const html = this.generateEmailVerificationTemplate(verificationUrl, name || 'Usuario')
      
      await this.transporter.sendMail({
        from: `"${this.config.from.name}" <${this.config.from.email}>`,
        to: email,
        subject: 'Verifica tu cuenta - Clínica Oftalmológica',
        html
      })

      logger.info('Email verification sent', { email, tokenPrefix: token.substring(0, 8) })

    } catch (error) {
      logger.error('Failed to send email verification', error as Error, { email })
      throw new Error('Error enviando email de verificación')
    }
  }

  async sendPasswordReset(email: string, token: string): Promise<void> {
    try {
      const resetUrl = `${this.config.templates.baseUrl}/auth/reset-password?token=${token}`
      
      const html = this.generatePasswordResetTemplate(resetUrl)
      
      await this.transporter.sendMail({
        from: `"${this.config.from.name}" <${this.config.from.email}>`,
        to: email,
        subject: 'Restablecer contraseña - Clínica Oftalmológica',
        html
      })

      logger.info('Password reset email sent', { email, tokenPrefix: token.substring(0, 8) })

    } catch (error) {
      logger.error('Failed to send password reset email', error as Error, { email })
      throw new Error('Error enviando email de restablecimiento')
    }
  }

  async sendWelcomeEmail(email: string, name: string): Promise<void> {
    try {
      const html = this.generateWelcomeTemplate(name)
      
      await this.transporter.sendMail({
        from: `"${this.config.from.name}" <${this.config.from.email}>`,
        to: email,
        subject: '¡Bienvenido a nuestra Clínica Oftalmológica!',
        html
      })

      logger.info('Welcome email sent', { email, name })

    } catch (error) {
      logger.error('Failed to send welcome email', error as Error, { email })
      // Don't throw error for welcome email failures
    }
  }

  async sendPasswordChangeNotification(email: string, name: string, ipAddress?: string): Promise<void> {
    try {
      const html = this.generatePasswordChangeTemplate(name, ipAddress)
      
      await this.transporter.sendMail({
        from: `"${this.config.from.name}" <${this.config.from.email}>`,
        to: email,
        subject: 'Contraseña cambiada - Clínica Oftalmológica',
        html
      })

      logger.info('Password change notification sent', { email, name })

    } catch (error) {
      logger.error('Failed to send password change notification', error as Error, { email })
      // Don't throw error for notification failures
    }
  }

  async sendSecurityAlert(email: string, name: string, event: string, ipAddress?: string, userAgent?: string): Promise<void> {
    try {
      const html = this.generateSecurityAlertTemplate(name, event, ipAddress, userAgent)
      
      await this.transporter.sendMail({
        from: `"${this.config.from.name}" <${this.config.from.email}>`,
        to: email,
        subject: '🚨 Alerta de seguridad - Clínica Oftalmológica',
        html
      })

      logger.info('Security alert sent', { email, event, ipAddress })

    } catch (error) {
      logger.error('Failed to send security alert', error as Error, { email, event })
      // Don't throw error for notification failures
    }
  }

  async sendAccountLockoutNotification(email: string, name: string, unlockTime: Date): Promise<void> {
    try {
      const html = this.generateAccountLockoutTemplate(name, unlockTime)
      
      await this.transporter.sendMail({
        from: `"${this.config.from.name}" <${this.config.from.email}>`,
        to: email,
        subject: '🔒 Cuenta bloqueada - Clínica Oftalmológica',
        html
      })

      logger.info('Account lockout notification sent', { email, unlockTime })

    } catch (error) {
      logger.error('Failed to send account lockout notification', error as Error, { email })
      // Don't throw error for notification failures
    }
  }

  // Template generators
  private generateEmailVerificationTemplate(verificationUrl: string, name: string): string {
    return `
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verifica tu cuenta</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }
            .container {
                max-width: 600px;
                margin: 0 auto;
                background: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 2rem;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 1.8rem;
            }
            .content {
                padding: 2rem;
            }
            .button {
                display: inline-block;
                background: #667eea;
                color: white;
                padding: 12px 30px;
                text-decoration: none;
                border-radius: 5px;
                font-weight: bold;
                margin: 1rem 0;
            }
            .button:hover {
                background: #5a6fd8;
            }
            .footer {
                background: #f8f9fa;
                padding: 1rem 2rem;
                text-align: center;
                color: #666;
                font-size: 0.9rem;
            }
            .security-notice {
                background: #fff3cd;
                border: 1px solid #ffeaa7;
                padding: 1rem;
                border-radius: 4px;
                margin: 1rem 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏥 Clínica Oftalmológica</h1>
            </div>
            <div class="content">
                <h2>¡Hola ${name}!</h2>
                <p>Gracias por registrarte en nuestra clínica. Para completar el proceso de registro, necesitas verificar tu dirección de correo electrónico.</p>
                
                <p style="text-align: center;">
                    <a href="${verificationUrl}" class="button">Verificar mi cuenta</a>
                </p>
                
                <div class="security-notice">
                    <strong>⚠️ Nota de seguridad:</strong>
                    <p>Este enlace expirará en 24 horas por razones de seguridad. Si no solicitaste esta cuenta, puedes ignorar este correo.</p>
                </div>
                
                <p>Si el botón no funciona, copia y pega este enlace en tu navegador:</p>
                <p style="word-break: break-all; color: #667eea;">${verificationUrl}</p>
            </div>
            <div class="footer">
                <p>Este correo fue enviado automáticamente, por favor no respondas.</p>
                <p>&copy; 2024 Clínica Oftalmológica. Todos los derechos reservados.</p>
            </div>
        </div>
    </body>
    </html>
    `
  }

  private generatePasswordResetTemplate(resetUrl: string): string {
    return `
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Restablecer contraseña</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }
            .container {
                max-width: 600px;
                margin: 0 auto;
                background: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            .header {
                background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                color: white;
                padding: 2rem;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 1.8rem;
            }
            .content {
                padding: 2rem;
            }
            .button {
                display: inline-block;
                background: #e74c3c;
                color: white;
                padding: 12px 30px;
                text-decoration: none;
                border-radius: 5px;
                font-weight: bold;
                margin: 1rem 0;
            }
            .button:hover {
                background: #c0392b;
            }
            .footer {
                background: #f8f9fa;
                padding: 1rem 2rem;
                text-align: center;
                color: #666;
                font-size: 0.9rem;
            }
            .security-notice {
                background: #ffebee;
                border: 1px solid #ffcdd2;
                padding: 1rem;
                border-radius: 4px;
                margin: 1rem 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 Restablecer Contraseña</h1>
            </div>
            <div class="content">
                <h2>Solicitud de restablecimiento</h2>
                <p>Has solicitado restablecer tu contraseña. Haz clic en el botón de abajo para crear una nueva contraseña.</p>
                
                <p style="text-align: center;">
                    <a href="${resetUrl}" class="button">Restablecer contraseña</a>
                </p>
                
                <div class="security-notice">
                    <strong>🛡️ Importante:</strong>
                    <ul>
                        <li>Este enlace expirará en 1 hora</li>
                        <li>Solo puede ser usado una vez</li>
                        <li>Si no solicitaste este cambio, ignora este correo</li>
                        <li>Tu contraseña actual seguirá siendo válida hasta que la cambies</li>
                    </ul>
                </div>
                
                <p>Si el botón no funciona, copia y pega este enlace en tu navegador:</p>
                <p style="word-break: break-all; color: #e74c3c;">${resetUrl}</p>
            </div>
            <div class="footer">
                <p>Este correo fue enviado automáticamente, por favor no respondas.</p>
                <p>&copy; 2024 Clínica Oftalmológica. Todos los derechos reservados.</p>
            </div>
        </div>
    </body>
    </html>
    `
  }

  private generateWelcomeTemplate(name: string): string {
    return `
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>¡Bienvenido!</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }
            .container {
                max-width: 600px;
                margin: 0 auto;
                background: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            .header {
                background: linear-gradient(135deg, #27ae60 0%, #2ecc71 100%);
                color: white;
                padding: 2rem;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 1.8rem;
            }
            .content {
                padding: 2rem;
            }
            .features {
                background: #f8f9fa;
                padding: 1rem;
                border-radius: 4px;
                margin: 1rem 0;
            }
            .features h3 {
                color: #27ae60;
                margin-top: 0;
            }
            .footer {
                background: #f8f9fa;
                padding: 1rem 2rem;
                text-align: center;
                color: #666;
                font-size: 0.9rem;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎉 ¡Bienvenido!</h1>
            </div>
            <div class="content">
                <h2>¡Hola ${name}!</h2>
                <p>¡Bienvenido a nuestra Clínica Oftalmológica! Tu cuenta ha sido verificada exitosamente y ya puedes comenzar a usar nuestros servicios.</p>
                
                <div class="features">
                    <h3>¿Qué puedes hacer ahora?</h3>
                    <ul>
                        <li>📅 Programar citas online</li>
                        <li>📋 Acceder a tu historial médico</li>
                        <li>💊 Revisar tus recetas y tratamientos</li>
                        <li>📞 Contactar con nuestro equipo médico</li>
                        <li>📊 Seguir el progreso de tus tratamientos</li>
                    </ul>
                </div>
                
                <p>Si tienes alguna pregunta o necesitas ayuda, no dudes en contactarnos. Nuestro equipo está aquí para cuidar de tu salud visual.</p>
                
                <p><strong>Horarios de atención:</strong><br>
                Lunes a Viernes: 8:00 AM - 6:00 PM<br>
                Sábados: 9:00 AM - 2:00 PM</p>
            </div>
            <div class="footer">
                <p>📧 contacto@clinica.com | 📞 (555) 123-4567</p>
                <p>&copy; 2024 Clínica Oftalmológica. Todos los derechos reservados.</p>
            </div>
        </div>
    </body>
    </html>
    `
  }

  private generatePasswordChangeTemplate(name: string, ipAddress?: string): string {
    const locationInfo = ipAddress ? `desde la dirección IP: ${ipAddress}` : 'desde una ubicación desconocida'
    
    return `
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Contraseña cambiada</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }
            .container {
                max-width: 600px;
                margin: 0 auto;
                background: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            .header {
                background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);
                color: white;
                padding: 2rem;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 1.8rem;
            }
            .content {
                padding: 2rem;
            }
            .footer {
                background: #f8f9fa;
                padding: 1rem 2rem;
                text-align: center;
                color: #666;
                font-size: 0.9rem;
            }
            .security-info {
                background: #e8f5e8;
                border: 1px solid #c3e6c3;
                padding: 1rem;
                border-radius: 4px;
                margin: 1rem 0;
            }
            .warning {
                background: #fff3cd;
                border: 1px solid #ffeaa7;
                padding: 1rem;
                border-radius: 4px;
                margin: 1rem 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔑 Contraseña Cambiada</h1>
            </div>
            <div class="content">
                <h2>Hola ${name},</h2>
                <p>Te confirmamos que tu contraseña ha sido cambiada exitosamente.</p>
                
                <div class="security-info">
                    <strong>✅ Detalles del cambio:</strong>
                    <ul>
                        <li><strong>Fecha:</strong> ${new Date().toLocaleDateString('es-ES', { 
                          year: 'numeric', 
                          month: 'long', 
                          day: 'numeric', 
                          hour: '2-digit', 
                          minute: '2-digit' 
                        })}</li>
                        <li><strong>Ubicación:</strong> ${locationInfo}</li>
                    </ul>
                </div>
                
                <div class="warning">
                    <strong>⚠️ ¿No fuiste tú?</strong>
                    <p>Si no realizaste este cambio, tu cuenta podría estar comprometida. Contacta inmediatamente con nuestro equipo de soporte.</p>
                </div>
                
                <p><strong>Recomendaciones de seguridad:</strong></p>
                <ul>
                    <li>Mantén tu contraseña segura y no la compartas</li>
                    <li>Utiliza contraseñas únicas para cada servicio</li>
                    <li>Habilita la autenticación de dos factores si está disponible</li>
                    <li>Revisa regularmente la actividad de tu cuenta</li>
                </ul>
            </div>
            <div class="footer">
                <p>Si tienes dudas, contacta con soporte: soporte@clinica.com</p>
                <p>&copy; 2024 Clínica Oftalmológica. Todos los derechos reservados.</p>
            </div>
        </div>
    </body>
    </html>
    `
  }

  private generateSecurityAlertTemplate(name: string, event: string, ipAddress?: string, userAgent?: string): string {
    return `
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Alerta de seguridad</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }
            .container {
                max-width: 600px;
                margin: 0 auto;
                background: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            .header {
                background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                color: white;
                padding: 2rem;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 1.8rem;
            }
            .content {
                padding: 2rem;
            }
            .footer {
                background: #f8f9fa;
                padding: 1rem 2rem;
                text-align: center;
                color: #666;
                font-size: 0.9rem;
            }
            .alert {
                background: #ffebee;
                border: 1px solid #ffcdd2;
                padding: 1rem;
                border-radius: 4px;
                margin: 1rem 0;
            }
            .button {
                display: inline-block;
                background: #e74c3c;
                color: white;
                padding: 12px 30px;
                text-decoration: none;
                border-radius: 5px;
                font-weight: bold;
                margin: 1rem 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🚨 Alerta de Seguridad</h1>
            </div>
            <div class="content">
                <h2>Hola ${name},</h2>
                <p>Hemos detectado actividad sospechosa en tu cuenta:</p>
                
                <div class="alert">
                    <strong>📋 Detalles del evento:</strong>
                    <ul>
                        <li><strong>Evento:</strong> ${event}</li>
                        <li><strong>Fecha:</strong> ${new Date().toLocaleDateString('es-ES', { 
                          year: 'numeric', 
                          month: 'long', 
                          day: 'numeric', 
                          hour: '2-digit', 
                          minute: '2-digit' 
                        })}</li>
                        ${ipAddress ? `<li><strong>Dirección IP:</strong> ${ipAddress}</li>` : ''}
                        ${userAgent ? `<li><strong>Navegador:</strong> ${userAgent}</li>` : ''}
                    </ul>
                </div>
                
                <p><strong>🔐 Acciones recomendadas:</strong></p>
                <ul>
                    <li>Si reconoces esta actividad, puedes ignorar este mensaje</li>
                    <li>Si no reconoces esta actividad, cambia tu contraseña inmediatamente</li>
                    <li>Revisa los accesos recientes a tu cuenta</li>
                    <li>Contacta con soporte si necesitas ayuda</li>
                </ul>
                
                <p style="text-align: center;">
                    <a href="${this.config.templates.baseUrl}/auth/change-password" class="button">Cambiar contraseña</a>
                </p>
            </div>
            <div class="footer">
                <p>Si tienes dudas, contacta con soporte: soporte@clinica.com</p>
                <p>&copy; 2024 Clínica Oftalmológica. Todos los derechos reservados.</p>
            </div>
        </div>
    </body>
    </html>
    `
  }

  private generateAccountLockoutTemplate(name: string, unlockTime: Date): string {
    return `
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cuenta bloqueada</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }
            .container {
                max-width: 600px;
                margin: 0 auto;
                background: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            .header {
                background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                color: white;
                padding: 2rem;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 1.8rem;
            }
            .content {
                padding: 2rem;
            }
            .footer {
                background: #f8f9fa;
                padding: 1rem 2rem;
                text-align: center;
                color: #666;
                font-size: 0.9rem;
            }
            .lockout-info {
                background: #ffebee;
                border: 1px solid #ffcdd2;
                padding: 1rem;
                border-radius: 4px;
                margin: 1rem 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 Cuenta Bloqueada</h1>
            </div>
            <div class="content">
                <h2>Hola ${name},</h2>
                <p>Tu cuenta ha sido bloqueada temporalmente debido a múltiples intentos de inicio de sesión fallidos.</p>
                
                <div class="lockout-info">
                    <strong>⏰ Información del bloqueo:</strong>
                    <ul>
                        <li><strong>Fecha de bloqueo:</strong> ${new Date().toLocaleDateString('es-ES', { 
                          year: 'numeric', 
                          month: 'long', 
                          day: 'numeric', 
                          hour: '2-digit', 
                          minute: '2-digit' 
                        })}</li>
                        <li><strong>Desbloqueada automáticamente:</strong> ${unlockTime.toLocaleDateString('es-ES', { 
                          year: 'numeric', 
                          month: 'long', 
                          day: 'numeric', 
                          hour: '2-digit', 
                          minute: '2-digit' 
                        })}</li>
                    </ul>
                </div>
                
                <p><strong>🛡️ ¿Por qué pasó esto?</strong></p>
                <p>Para proteger tu cuenta, la bloqueamos automáticamente después de varios intentos fallidos de inicio de sesión. Esto ayuda a prevenir accesos no autorizados.</p>
                
                <p><strong>📋 ¿Qué puedes hacer?</strong></p>
                <ul>
                    <li>Esperar hasta la hora de desbloqueo automático</li>
                    <li>Si olvidaste tu contraseña, puedes restablecerla</li>
                    <li>Contactar con soporte si crees que es un error</li>
                </ul>
                
                <p><strong>🔐 Consejos de seguridad:</strong></p>
                <ul>
                    <li>Utiliza contraseñas seguras y únicas</li>
                    <li>No compartas tus credenciales con nadie</li>
                    <li>Mantén actualizada tu información de contacto</li>
                </ul>
            </div>
            <div class="footer">
                <p>Si necesitas ayuda inmediata: soporte@clinica.com | (555) 123-4567</p>
                <p>&copy; 2024 Clínica Oftalmológica. Todos los derechos reservados.</p>
            </div>
        </div>
    </body>
    </html>
    `
  }

  // Test email connection
  async testConnection(): Promise<boolean> {
    try {
      await this.transporter.verify()
      logger.info('Email service connection verified successfully')
      return true
    } catch (error) {
      logger.error('Email service connection failed', error as Error)
      return false
    }
  }

  // Send test email
  async sendTestEmail(to: string): Promise<void> {
    try {
      await this.transporter.sendMail({
        from: `"${this.config.from.name}" <${this.config.from.email}>`,
        to,
        subject: 'Test Email - Clínica Oftalmológica',
        html: `
          <h2>✅ Email Service Test</h2>
          <p>If you received this email, the email service is working correctly!</p>
          <p><strong>Timestamp:</strong> ${new Date().toISOString()}</p>
        `
      })
      
      logger.info('Test email sent successfully', { to })
    } catch (error) {
      logger.error('Failed to send test email', error as Error, { to })
      throw error
    }
  }
}
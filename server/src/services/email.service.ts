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

  private generatePasswordChangeTemplate(name: string,
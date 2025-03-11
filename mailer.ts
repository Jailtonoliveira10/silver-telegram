import { MailService } from '@sendgrid/mail';
import { logger } from '../utils/logger';

if (!process.env.SENDGRID_API_KEY) {
  logger.error('SENDGRID_API_KEY não está definido no arquivo .env', { source: 'mailer' });
  throw new Error("SENDGRID_API_KEY environment variable must be set");
}

const mailService = new MailService();
mailService.setApiKey(process.env.SENDGRID_API_KEY);

const FROM_EMAIL = 'noreply@esn.app';

export async function sendPasswordResetEmail(
  to: string,
  resetToken: string
): Promise<boolean> {
  try {
    const resetLink = `${process.env.APP_URL || 'http://localhost:5000'}/reset-password?token=${resetToken}`;
    
    await mailService.send({
      to,
      from: FROM_EMAIL,
      subject: 'Recuperação de Senha - Elite Scouting Network',
      text: `Para redefinir sua senha, acesse o link: ${resetLink}`,
      html: `
        <div>
          <h2>Recuperação de Senha - Elite Scouting Network</h2>
          <p>Você solicitou a redefinição de sua senha.</p>
          <p>Clique no link abaixo para criar uma nova senha:</p>
          <a href="${resetLink}">${resetLink}</a>
          <p>Este link é válido por 1 hora.</p>
          <p>Se você não solicitou esta redefinição, ignore este email.</p>
        </div>
      `
    });

    logger.info('Email de recuperação de senha enviado com sucesso', {
      source: 'mailer',
      data: { to }
    });

    return true;
  } catch (error) {
    logger.error('Erro ao enviar email de recuperação de senha', error as Error, {
      source: 'mailer',
      data: { to }
    });
    return false;
  }
}

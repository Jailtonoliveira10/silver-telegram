import { logger } from '../utils/logger';

const FROM_EMAIL = 'noreply@esn.app';

type TwoFAEmailType = 'enable' | 'disable' | 'backup_codes';

export async function sendPasswordResetEmail(
  to: string,
  resetToken: string
): Promise<boolean> {
  try {
    const resetLink = `${process.env.APP_URL || 'http://localhost:5000'}/reset-password?token=${resetToken}`;

    // Simula o envio do email (apenas log)
    logger.info('Simulando envio de email de recuperação de senha', {
      source: 'email',
      data: {
        to,
        resetLink,
        subject: 'Recuperação de Senha - Elite Scouting Network'
      }
    });

    // Em um ambiente de produção, aqui utilizaríamos o SendGrid
    // const mailService = new MailService();
    // mailService.setApiKey(process.env.SENDGRID_API_KEY);
    // await mailService.send({...});

    logger.info('Email de recuperação de senha simulado com sucesso', {
      source: 'email',
      data: { to }
    });

    return true;
  } catch (error) {
    logger.error('Erro ao simular envio de email de recuperação de senha', error as Error, {
      source: 'email',
      data: { to }
    });
    return false;
  }
}

export async function send2FAConfirmationEmail(
  to: string,
  confirmToken: string,
  type: TwoFAEmailType
): Promise<boolean> {
  try {
    const confirmLink = `${process.env.APP_URL || 'http://localhost:5000'}/settings/2fa/confirm?token=${confirmToken}&type=${type}`;

    const subjects = {
      enable: 'Confirmar Ativação do 2FA',
      disable: 'Confirmar Desativação do 2FA',
      backup_codes: 'Confirmar Geração de Códigos de Backup 2FA'
    };

    const messages = {
      enable: 'confirmar a ativação da autenticação de dois fatores',
      disable: 'confirmar a desativação da autenticação de dois fatores',
      backup_codes: 'gerar novos códigos de backup para autenticação de dois fatores'
    };

    // Simula o envio do email (apenas log)
    logger.info('Simulando envio de email de confirmação 2FA', {
      source: 'email',
      data: {
        to,
        confirmLink,
        subject: subjects[type],
        type
      }
    });

    // Em um ambiente de produção, aqui utilizaríamos o SendGrid
    // const mailService = new MailService();
    // mailService.setApiKey(process.env.SENDGRID_API_KEY);
    // await mailService.send({
    //   to,
    //   from: FROM_EMAIL,
    //   subject: subjects[type],
    //   html: `<p>Clique no link abaixo para ${messages[type]}:</p><a href="${confirmLink}">${confirmLink}</a>`
    // });

    logger.info('Email de confirmação 2FA simulado com sucesso', {
      source: 'email',
      data: { to, type }
    });

    return true;
  } catch (error) {
    logger.error('Erro ao simular envio de email de confirmação 2FA', error as Error, {
      source: 'email',
      data: { to, type }
    });
    return false;
  }
}
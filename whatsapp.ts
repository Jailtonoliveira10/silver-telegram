import twilio from 'twilio';

interface WhatsAppMessage {
  to: string;
  message: string;
}

// Simplified version - will be enhanced later
export async function sendWhatsAppMessage({ to, message }: WhatsAppMessage): Promise<boolean> {
  console.log('[WhatsApp] Mensagem seria enviada para:', to);
  console.log('[WhatsApp] Conteúdo:', message);
  return true; // Always return success for now
}

export function formatWhatsAppNumber(number: string): string {
  const cleaned = number.replace(/\D/g, '');
  return cleaned.startsWith('55') ? cleaned : `55${cleaned}`;
}
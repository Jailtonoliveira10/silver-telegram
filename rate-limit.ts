import rateLimit from 'express-rate-limit';
import { logger } from '../utils/logger';

// Define limites baseados no ambiente
const isTestEnv = process.env.DISABLE_RATE_LIMIT_FOR_TESTS === 'true';
const authMax = isTestEnv ? Infinity : 1000; // aumentado para 1000 durante testes
const generalMax = isTestEnv ? Infinity : 2000; // aumentado para 2000 durante testes

logger.info('Configurando rate limiting', { 
  source: 'rate-limit',
  data: {
    isTestEnv,
    authMax,
    generalMax
  }
});

// Configuração do rate limit para autenticação
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: isTestEnv ? Infinity : authMax,
  message: { error: 'Muitas tentativas de login. Por favor, tente novamente mais tarde.' },
  handler: (req, res, next) => {
    if (isTestEnv) {
      // Skip rate limiting durante testes
      return next();
    }

    logger.warn('Rate limit excedido na autenticação', {
      data: {
        ip: req.ip,
        method: req.method,
        path: req.path,
        timestamp: new Date().toISOString()
      }
    });
    res.status(429).json({ error: 'Muitas tentativas de login. Por favor, tente novamente mais tarde.' });
  },
  skip: () => isTestEnv, // Skip rate limiting durante testes
  standardHeaders: true,
  legacyHeaders: false,
  skipFailedRequests: isTestEnv, // Ignora requisições com falha durante testes
  skipSuccessfulRequests: isTestEnv // Ignora requisições bem-sucedidas durante testes
});

// Configuração do rate limit para rotas gerais
export const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: isTestEnv ? Infinity : generalMax,
  message: { error: 'Limite de requisições excedido. Por favor, tente novamente mais tarde.' },
  handler: (req, res, next) => {
    if (isTestEnv) {
      // Skip rate limiting durante testes
      return next();
    }

    logger.warn('Rate limit excedido em rota geral', {
      data: {
        ip: req.ip,
        method: req.method,
        path: req.path,
        timestamp: new Date().toISOString()
      }
    });
    res.status(429).json({ error: 'Limite de requisições excedido. Por favor, tente novamente mais tarde.' });
  },
  skip: () => isTestEnv, // Skip rate limiting durante testes
  standardHeaders: true,
  legacyHeaders: false,
  skipFailedRequests: isTestEnv, // Ignora requisições com falha durante testes
  skipSuccessfulRequests: isTestEnv // Ignora requisições bem-sucedidas durante testes
});
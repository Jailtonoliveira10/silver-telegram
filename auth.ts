import { User, users, blacklistedTokens } from "@shared/schema";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { logger } from '../utils/logger';
import { db } from '../db';
import { eq } from 'drizzle-orm';

// Funções utilitárias para hash e verificação de senha
export async function hashPassword(password: string): Promise<string> {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
}

export async function verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
  return bcrypt.compare(password, hashedPassword);
}

// Extrair o token da string do cabeçalho Authorization
export function extractTokenFromHeader(authHeader: string): string | null {
  const [scheme, token] = authHeader.split(' ');
  if (!token || scheme !== 'Bearer') {
    return null;
  }
  return token;
}

// Funções para geração e verificação de tokens JWT
export function generateToken(user: User): string {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET environment variable must be set");
  }
  return jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
}

// Blacklist um token
export async function blacklistToken(token: string): Promise<void> {
  try {
    const decoded = jwt.decode(token) as { exp?: number } | null;
    if (!decoded?.exp) {
      throw new Error("Token inválido");
    }

    await db.insert(blacklistedTokens).values({
      token,
      expiresAt: new Date(decoded.exp * 1000),
    });

    logger.info('Token adicionado à lista negra com sucesso');
  } catch (error) {
    logger.error('Erro ao adicionar token à lista negra');
    throw error;
  }
}

// Verificar se um token está na lista negra
export async function isTokenBlacklisted(token: string): Promise<boolean> {
  try {
    const blacklistedToken = await db.query.blacklistedTokens.findFirst({
      where: eq(blacklistedTokens.token, token)
    });
    return !!blacklistedToken;
  } catch (error) {
    logger.error('Erro ao verificar token na lista negra');
    throw error;
  }
}

export async function verifyToken(token: string): Promise<{ id: number; username: string } | null> {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET environment variable must be set");
  }

  try {
    // Primeiro verifica se o token está na lista negra
    const isBlacklisted = await isTokenBlacklisted(token);
    if (isBlacklisted) {
      return null;
    }

    // Se não estiver na lista negra, verifica a validade do token
    return jwt.verify(token, process.env.JWT_SECRET) as { id: number; username: string };
  } catch (error) {
    return null;
  }
}

// Enhanced middleware de autenticação
export async function authMiddleware(req: any, res: any, next: any) {
  const authHeader = req.headers.authorization;

  // Check if Authorization header exists
  if (!authHeader) {
    logger.warn('Token não fornecido', {
      data: { path: req.path }
    });
    return res.status(401).json({ 
      error: 'Acesso negado',
      message: 'Token não fornecido' 
    });
  }

  const token = extractTokenFromHeader(authHeader);
  if (!token) {
    logger.warn('Formato de token inválido', {
      data: { path: req.path }
    });
    return res.status(401).json({ 
      error: 'Acesso negado',
      message: 'Formato de token inválido' 
    });
  }

  try {
    // Verify and decode token
    const decoded = await verifyToken(token);
    if (!decoded) {
      logger.warn('Token inválido, expirado ou revogado', {
        data: { path: req.path }
      });
      return res.status(401).json({ 
        error: 'Acesso negado',
        message: 'Token inválido, expirado ou revogado' 
      });
    }

    // Add user info to request
    req.user = decoded;
    logger.info('Token verificado com sucesso', {
      data: { 
        userId: decoded.id,
        username: decoded.username,
        path: req.path 
      }
    });
    next();
  } catch (error) {
    logger.error('Erro ao verificar token');
    return res.status(500).json({ 
      error: 'Erro interno',
      message: 'Erro ao verificar token' 
    });
  }
}
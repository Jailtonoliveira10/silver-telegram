import { jest, describe, expect, it, beforeAll } from '@jest/globals';
import { eq } from 'drizzle-orm';
import request from 'supertest';
import express, { Express } from 'express';
import { authRouter } from '../routes/auth';
import { db } from '../db';
import { users, blacklistedTokens, User } from '@shared/schema';

describe('Authentication Endpoints', () => {
  let app: Express;
  let authToken: string;

  beforeAll(() => {
    app = express();
    app.use(express.json());
    app.use('/api/auth', authRouter);
  });

  describe('POST /api/auth/register', () => {
    it('should register a new user successfully', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          password: 'test123',
          email: 'test@example.com'
        });

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('token');
      expect(res.body.message).toBe('Usuário registrado com sucesso');
    });

    it('should return 400 if required fields are missing', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser'
        });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error');
    });
  });

  describe('POST /api/auth/login', () => {
    it('should login successfully with correct credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'test123'
        });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('token');
      expect(res.body.message).toBe('Login realizado com sucesso');
    });

    it('should return 401 with incorrect credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'wrongpassword'
        });

      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('error');
    });
  });

  describe('POST /api/auth/forgot-password', () => {
    it('should send reset password email successfully', async () => {
      const res = await request(app)
        .post('/api/auth/forgot-password')
        .send({
          email: 'test@example.com'
        });

      expect(res.status).toBe(200);
      expect(res.body.message).toBe('Email de recuperação enviado com sucesso');
    });

    it('should return 404 for non-existent email', async () => {
      const res = await request(app)
        .post('/api/auth/forgot-password')
        .send({
          email: 'nonexistent@example.com'
        });

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Email não encontrado');
    });
  });

  describe('POST /api/auth/reset-password', () => {
    let resetToken: string;

    beforeAll(async () => {
      // Clear any existing users
      await db.delete(users);

      // Create a test user
      const [user] = await db.insert(users).values({
        username: 'testuser',
        password: 'oldpassword',
        email: 'test@example.com',
        alertPreferences: {
          positions: [],
          minMarketValue: 0,
          maxMarketValue: 100000000,
          ageRange: [16, 40],
          notificationEnabled: true,
          whatsappNumber: "",
          whatsappEnabled: false,
          alertTypes: {
            marketValue: true,
            performance: true,
            injury: true,
            transfer: true
          }
        }
      }).returning();

      // Request password reset to get a valid token
      const response = await request(app)
        .post('/api/auth/forgot-password')
        .send({
          email: 'test@example.com'
        });

      // Get the token from the database
      const updatedUser = await db.query.users.findFirst({
        where: eq(users.email, 'test@example.com')
      });
      resetToken = updatedUser?.resetToken || '';
    });

    it('should reset password successfully with valid token', async () => {
      const res = await request(app)
        .post('/api/auth/reset-password')
        .send({
          token: resetToken,
          password: 'newpassword123'
        });

      expect(res.status).toBe(200);
      expect(res.body.message).toBe('Senha redefinida com sucesso');
    });

    it('should return 400 for invalid token', async () => {
      const res = await request(app)
        .post('/api/auth/reset-password')
        .send({
          token: 'invalid-token',
          password: 'newpassword123'
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Token inválido ou expirado');
    });
  });

  describe('POST /api/auth/logout', () => {
    beforeAll(async () => {
      // Clear any existing users and blacklisted tokens
      await db.delete(users);
      await db.delete(blacklistedTokens);

      // Register a user and get token
      const registerResponse = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          password: 'test123',
          email: 'test@example.com'
        });

      authToken = registerResponse.body.token;
    });

    it('should logout successfully and invalidate token', async () => {
      // First logout
      const logoutRes = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${authToken}`);

      expect(logoutRes.status).toBe(200);
      expect(logoutRes.body.message).toBe('Logout realizado com sucesso');

      // Try to access protected route with blacklisted token
      const protectedRes = await request(app)
        .get('/api/auth/protected-test')
        .set('Authorization', `Bearer ${authToken}`);

      expect(protectedRes.status).toBe(401);
      expect(protectedRes.body.message).toBe('Token inválido, expirado ou revogado');
    });

    it('should return 401 when trying to logout without token', async () => {
      const res = await request(app)
        .post('/api/auth/logout');

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Token não fornecido');
    });

    it('should return 401 when trying to logout with invalid token format', async () => {
      const res = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', 'InvalidToken');

      expect(res.status).toBe(401);
      expect(res.body.message).toBe('Formato de token inválido');
    });
  });
});
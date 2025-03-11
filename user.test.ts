import { jest, describe, expect, it, beforeAll } from '@jest/globals';
import request from 'supertest';
import express, { Express } from 'express';
import { userRouter } from '../routes/user';
import { db } from '../db';
import { users } from '@shared/schema';
import path from 'path';
import fs from 'fs';

describe('User Profile Endpoints', () => {
  let app: Express;
  let authToken: string;

  beforeAll(async () => {
    app = express();
    app.use(express.json());
    app.use('/api/user', userRouter);

    // Ensure test uploads directory exists
    const uploadsDir = path.join(process.cwd(), 'uploads');
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }

    // Register a test user and get token
    const registerResponse = await request(app)
      .post('/api/auth/register')
      .send({
        username: 'testuser',
        password: 'test123',
        email: 'test@example.com'
      });

    authToken = registerResponse.body.token;
  });

  describe('POST /api/user/profile/image', () => {
    it('should upload profile image successfully', async () => {
      const testImagePath = path.join(__dirname, 'fixtures', 'test-image.jpg');
      
      const res = await request(app)
        .post('/api/user/profile/image')
        .set('Authorization', `Bearer ${authToken}`)
        .attach('image', testImagePath);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('message', 'Foto de perfil atualizada com sucesso');
      expect(res.body.user).toHaveProperty('profileImage');
      expect(typeof res.body.user.profileImage).toBe('string');
    });

    it('should return 400 if no image is provided', async () => {
      const res = await request(app)
        .post('/api/user/profile/image')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Nenhuma imagem fornecida');
    });

    it('should return 401 without authentication', async () => {
      const testImagePath = path.join(__dirname, 'fixtures', 'test-image.jpg');
      
      const res = await request(app)
        .post('/api/user/profile/image')
        .attach('image', testImagePath);

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Usuário não autenticado');
    });

    it('should return 400 for invalid file type', async () => {
      const testFilePath = path.join(__dirname, 'fixtures', 'test.txt');
      
      const res = await request(app)
        .post('/api/user/profile/image')
        .set('Authorization', `Bearer ${authToken}`)
        .attach('image', testFilePath);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Formato de arquivo inválido. Use JPEG, PNG ou GIF');
    });
  });

  // Cleanup after tests
  afterAll(async () => {
    // Clean up test uploads
    const uploadsDir = path.join(process.cwd(), 'uploads');
    const files = fs.readdirSync(uploadsDir);
    for (const file of files) {
      fs.unlinkSync(path.join(uploadsDir, file));
    }
    
    // Clean up test users
    await db.delete(users);
  });
});

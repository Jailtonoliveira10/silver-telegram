// Configure environment variables for testing
process.env.JWT_SECRET = 'test-secret';
process.env.NODE_ENV = 'test';

// Import types from jest
import { jest } from '@jest/globals';

// Mock the email service
jest.mock('../services/email', () => ({
  sendPasswordResetEmail: jest.fn().mockImplementation(() => Promise.resolve(true))
}));
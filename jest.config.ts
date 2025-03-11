import type { Config } from '@jest/types';

const config: Config.InitialOptions = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/server'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  transform: {
    '^.+\\.tsx?$': 'ts-jest'
  },
  moduleNameMapper: {
    '@shared/(.*)': '<rootDir>/shared/$1'
  },
  setupFiles: ['<rootDir>/server/__tests__/setup.ts']
};

export default config;

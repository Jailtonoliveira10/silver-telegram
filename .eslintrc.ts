import { Linter } from 'eslint';

const config: Linter.Config = {
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:@typescript-eslint/recommended-type-checked',
    'plugin:dotenv/recommended'
  ],
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint', 'dotenv'],
  parserOptions: {
    project: './tsconfig.json',
  },
  settings: {
    react: {
      version: 'detect'
    }
  },
  root: true,
  rules: {
    // Configurações de estilo e formatação
    'indent': ['error', 2],
    'quotes': ['error', 'single'],
    'semi': ['error', 'always'],
    'max-lines': ['warn', { max: 200 }],
    'prefer-const': 'error',

    // Configurações de segurança e boas práticas
    'no-console': 'warn',
    'no-process-env': 'off',
    'no-restricted-globals': ['error', 'event'],
    'no-unsafe-optional-chaining': 'error',
    'import/no-extraneous-dependencies': ['error', { devDependencies: true }],

    // Regras do TypeScript
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/strict-boolean-expressions': 'error',
    '@typescript-eslint/no-non-null-assertion': 'warn',
    '@typescript-eslint/no-var-requires': 'error',
    '@typescript-eslint/no-unsafe-assignment': 'error',
    '@typescript-eslint/no-unsafe-member-access': 'error',

    // Gerenciamento de variáveis
    'no-unused-vars': ['error', { 
      vars: 'all', 
      args: 'after-used',
      ignoreRestSiblings: true 
    }],

    // Configurações de imports
    'import/extensions': ['error', 'ignorePackages'],
    'import/no-unresolved': 'error',
    'import/named': 'error',

    // Verificação de variáveis de ambiente
    'dotenv/no-missing-vars': 'error'
  },
  ignorePatterns: [
    'dist/', 
    'node_modules/'
  ],
};

export default config;

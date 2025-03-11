import autocannon, { Result } from 'autocannon';
import { promisify } from 'util';
import { logger } from '../utils/logger';
import { db } from '../db';
import { users } from '@shared/schema';
import { hashPassword } from '../services/auth';

const run = promisify(autocannon);

// Função para aguardar um tempo específico
const wait = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

async function createTestUser() {
  try {
    // Verifica se o usuário já existe
    const existingUser = await db.query.users.findFirst({
      where: (users, { eq }) => eq(users.username, 'admin6')
    });

    if (!existingUser) {
      // Cria o usuário de teste se não existir
      const hashedPassword = await hashPassword('novasenha123');
      await db.insert(users).values({
        username: 'admin6',
        password: hashedPassword,
        email: 'admin6@test.com',
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
      });
      logger.info('Usuário de teste criado com sucesso', { source: 'loadtest' });
    } else {
      logger.info('Usuário de teste já existe', { source: 'loadtest' });
    }
  } catch (error) {
    logger.error('Erro ao criar usuário de teste', error as Error, { source: 'loadtest' });
    throw error;
  }
}

async function runLoadTest() {
  try {
    logger.info('Iniciando teste de carga na API', {
      source: 'loadtest'
    });

    // Garante que o usuário de teste existe
    await createTestUser();

    // Teste de endpoints públicos
    const publicResult = await run({
      url: 'http://localhost:5000',
      connections: 10,
      duration: 10,
      title: 'Teste de Endpoints Públicos',
      requests: [
        {
          method: 'GET',
          path: '/api/health'
        },
        {
          method: 'GET',
          path: '/'
        }
      ]
    }) as Result;

    logger.info('Resultados do teste em endpoints públicos', {
      source: 'loadtest',
      data: {
        avgLatency: publicResult.latency.average,
        reqPerSec: publicResult.requests.average,
        successRate: publicResult.non2xx === undefined ? 100 : 
          ((publicResult.requests.total - publicResult.non2xx) / publicResult.requests.total) * 100,
        totalRequests: publicResult.requests.total,
        errors: publicResult.errors ? Object.keys(publicResult.errors).length : 0,
        statusCodes: publicResult.statusCodeStats || {}
      }
    });

    // Aguarda 5 segundos antes do próximo teste
    await wait(5000);

    // Teste do endpoint de login
    const loginResult = await run({
      url: 'http://localhost:5000/api/auth/login',
      connections: 5,
      duration: 10,
      method: 'POST',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        username: 'admin6',
        password: 'novasenha123'
      })
    }) as Result;

    logger.info('Resultados do teste no endpoint de login', {
      source: 'loadtest',
      data: {
        avgLatency: loginResult.latency.average,
        reqPerSec: loginResult.requests.average,
        successRate: loginResult.non2xx === undefined ? 100 : 
          ((loginResult.requests.total - loginResult.non2xx) / loginResult.requests.total) * 100,
        totalRequests: loginResult.requests.total,
        errors: loginResult.errors ? Object.keys(loginResult.errors).length : 0,
        statusCodes: loginResult.statusCodeStats || {}
      }
    });

    // Aguarda 5 segundos antes de tentar obter o token
    await wait(5000);

    // Faz uma única requisição de login para obter o token
    try {
      logger.info('Tentando obter token de autenticação...', { source: 'loadtest' });

      const loginResponse = await fetch('http://localhost:5000/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Forwarded-For': '127.0.0.2' // IP diferente para evitar rate limit
        },
        body: JSON.stringify({
          username: 'admin6',
          password: 'novasenha123'
        })
      });

      const responseText = await loginResponse.text();
      logger.info('Resposta do login', {
        source: 'loadtest',
        data: {
          status: loginResponse.status,
          headers: Object.fromEntries(loginResponse.headers.entries()),
          body: responseText
        }
      });

      if (!loginResponse.ok) {
        throw new Error(`Login falhou com status ${loginResponse.status}: ${responseText}`);
      }

      const data = JSON.parse(responseText);
      const token = data.token;

      if (!token) {
        throw new Error(`Token não encontrado na resposta: ${responseText}`);
      }

      logger.info('Token obtido com sucesso', { source: 'loadtest' });

      // Aguarda 5 segundos antes do teste de endpoints autenticados
      await wait(5000);

      // Teste de endpoints autenticados
      const authResult = await run({
        url: 'http://localhost:5000',
        connections: 5,
        duration: 10,
        title: 'Teste de Endpoints Autenticados',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        requests: [
          {
            method: 'GET',
            path: '/api/user/profile'
          },
          {
            method: 'GET',
            path: '/api/auth/me'
          }
        ]
      }) as Result;

      logger.info('Resultados do teste em endpoints autenticados', {
        source: 'loadtest',
        data: {
          avgLatency: authResult.latency.average,
          reqPerSec: authResult.requests.average,
          successRate: authResult.non2xx === undefined ? 100 :
            ((authResult.requests.total - authResult.non2xx) / authResult.requests.total) * 100,
          totalRequests: authResult.requests.total,
          errors: authResult.errors ? Object.keys(authResult.errors).length : 0,
          statusCodes: authResult.statusCodeStats || {}
        }
      });
    } catch (error) {
      logger.error('Erro ao obter token de autenticação', error as Error, {
        source: 'loadtest'
      });
    }

  } catch (error) {
    logger.error('Erro ao executar teste de carga', error as Error, {
      source: 'loadtest'
    });
    process.exit(1);
  }
}

runLoadTest().catch(console.error);
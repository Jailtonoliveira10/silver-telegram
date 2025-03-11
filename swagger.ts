import swaggerJSDoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'Elite Scouting Network API',
    version: '1.0.0',
    description: 'API para plataforma de scouting e inteligência de mercado no futebol',
    license: {
      name: 'MIT',
      url: 'https://opensource.org/licenses/MIT',
    },
    contact: {
      name: 'Suporte ESN',
      url: 'https://esn.com.br',
      email: 'suporte@esn.com.br',
    },
  },
  servers: [
    {
      url: 'http://localhost:5000',
      description: 'Servidor de Desenvolvimento',
    },
  ],
  components: {
    securitySchemes: {
      BearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
    },
  },
};

const options = {
  swaggerDefinition,
  apis: ['./server/routes/*.ts'], // Caminhos para os arquivos com anotações JSDoc
};

const swaggerSpec = swaggerJSDoc(options);

export const swaggerDocs = swaggerSpec;
export const swaggerUiServe = swaggerUi.serve;
export const swaggerUiSetup = swaggerUi.setup(swaggerSpec);

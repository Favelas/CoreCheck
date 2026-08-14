'use strict';

const express = require('express');
const { healthRouter } = require('./routes/health.routes');
const { reportsRouter } = require('./routes/reports.routes');
const { notFoundHandler } = require('./middlewares/notFound');
const { errorHandler } = require('./middlewares/errorHandler');

/**
 * Factory de la app Express (sin listen).
 * Permite tests HTTP sin abrir puerto (supertest / Fase C).
 */
function createApp() {
  const app = express();

  // Límite de body alineado a presupuesto de evidencia CoreCheck (evitar OOM en CI)
  app.use(express.json({ limit: '1mb' }));

  app.use('/', healthRouter);
  app.use('/api/reports', reportsRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}

module.exports = { createApp };

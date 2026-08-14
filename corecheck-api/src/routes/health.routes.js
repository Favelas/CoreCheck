'use strict';

const { Router } = require('express');
const { getHealth } = require('../controllers/health.controller');
const { asyncHandler } = require('../middlewares/asyncHandler');

const healthRouter = Router();

healthRouter.get('/', asyncHandler(getHealth));

module.exports = { healthRouter };

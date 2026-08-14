'use strict';

const { Router } = require('express');
const {
  createReport,
  listReports,
  getReportById
} = require('../controllers/reports.controller');
const { validateReportBody } = require('../middlewares/validateReportBody');
const { asyncHandler } = require('../middlewares/asyncHandler');

const reportsRouter = Router();

reportsRouter.get('/', asyncHandler(listReports));
reportsRouter.post('/', validateReportBody, asyncHandler(createReport));
reportsRouter.get('/:id', asyncHandler(getReportById));

module.exports = { reportsRouter };

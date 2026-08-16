import { Router } from 'express';
import {
  createReport,
  getDiff,
  getReportById,
  getTrends,
  listReports,
  verifyReport
} from '../controllers/reports.controller';
import { asyncHandler } from '../middlewares/asyncHandler';
import { validateReportBody } from '../middlewares/validateReportBody';

export const reportsRouter = Router();

reportsRouter.get('/', asyncHandler(listReports));
reportsRouter.post('/', validateReportBody, asyncHandler(createReport));

// Insights antes de /:id (Slice 3)
reportsRouter.get('/insights/trends', asyncHandler(getTrends));
reportsRouter.get('/insights/diff', asyncHandler(getDiff));

reportsRouter.post('/:id/verify', asyncHandler(verifyReport));
reportsRouter.get('/:id', asyncHandler(getReportById));

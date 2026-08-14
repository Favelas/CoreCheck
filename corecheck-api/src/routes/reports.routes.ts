import { Router } from 'express';
import {
  createReport,
  getReportById,
  listReports,
  verifyReport
} from '../controllers/reports.controller';
import { asyncHandler } from '../middlewares/asyncHandler';
import { validateReportBody } from '../middlewares/validateReportBody';

export const reportsRouter = Router();

reportsRouter.get('/', asyncHandler(listReports));
reportsRouter.post('/', validateReportBody, asyncHandler(createReport));
// Ruta específica antes de GET /:id
reportsRouter.post('/:id/verify', asyncHandler(verifyReport));
reportsRouter.get('/:id', asyncHandler(getReportById));

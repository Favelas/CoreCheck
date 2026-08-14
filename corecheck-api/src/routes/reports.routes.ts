import { Router } from 'express';
import {
  createReport,
  getReportById,
  listReports
} from '../controllers/reports.controller';
import { asyncHandler } from '../middlewares/asyncHandler';
import { validateReportBody } from '../middlewares/validateReportBody';

export const reportsRouter = Router();

reportsRouter.get('/', asyncHandler(listReports));
reportsRouter.post('/', validateReportBody, asyncHandler(createReport));
reportsRouter.get('/:id', asyncHandler(getReportById));

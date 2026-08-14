import { Router } from 'express';
import { getHealth } from '../controllers/health.controller';
import { asyncHandler } from '../middlewares/asyncHandler';

export const healthRouter = Router();

healthRouter.get('/', asyncHandler(getHealth));

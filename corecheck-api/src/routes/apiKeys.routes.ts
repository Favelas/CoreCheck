import { Router } from 'express';
import {
  createApiKey,
  listApiKeys,
  revokeApiKey
} from '../controllers/apiKeys.controller';
import { asyncHandler } from '../middlewares/asyncHandler';
import type { TenantRequest } from '../types/express';

export const apiKeysRouter = Router();

apiKeysRouter.get(
  '/',
  asyncHandler((req, res) => listApiKeys(req as TenantRequest, res))
);
apiKeysRouter.post(
  '/',
  asyncHandler((req, res) => createApiKey(req as TenantRequest, res))
);
apiKeysRouter.delete(
  '/:id',
  asyncHandler((req, res) => revokeApiKey(req as TenantRequest, res))
);

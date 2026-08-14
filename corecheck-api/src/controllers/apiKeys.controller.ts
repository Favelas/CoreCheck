import type { Response } from 'express';
import { AppError } from '../errors/AppError';
import { getApiKeyRepository } from '../store/apiKey.context';
import type { TenantRequest } from '../types/express';

/**
 * POST /api/admin/api-keys
 * Crea una key para el tenant autenticado. El secreto plaintext solo en esta respuesta.
 */
export async function createApiKey(
  req: TenantRequest,
  res: Response
): Promise<void> {
  const body = (req.body ?? {}) as { label?: unknown };
  const label =
    typeof body.label === 'string' && body.label.trim() !== ''
      ? body.label.trim()
      : undefined;

  const created = await getApiKeyRepository().create({
    accountId: req.accountId,
    ...(label !== undefined ? { label } : {})
  });

  res.status(201).json({
    id: created.record.id,
    accountId: created.record.accountId,
    keyPrefix: created.record.keyPrefix,
    label: created.record.label,
    createdAt: created.record.createdAt,
    apiKey: created.apiKey,
    message:
      'Guarda apiKey ahora — no se volverá a mostrar (solo se persiste el hash).'
  });
}

/** GET /api/admin/api-keys — lista keys del tenant (sin secretos). */
export async function listApiKeys(
  req: TenantRequest,
  res: Response
): Promise<void> {
  const data = await getApiKeyRepository().listByAccount(req.accountId);
  res.status(200).json({ total: data.length, data });
}

/** DELETE /api/admin/api-keys/:id — revoca (404 cross-tenant / inexistente). */
export async function revokeApiKey(
  req: TenantRequest,
  res: Response
): Promise<void> {
  const rawId = req.params['id'];
  const id = Array.isArray(rawId) ? rawId[0] : rawId;
  if (!id) {
    throw new AppError('BAD_REQUEST', 'id de API key requerido.', 400);
  }

  const ok = await getApiKeyRepository().revoke(id, req.accountId);
  if (!ok) {
    throw new AppError('NOT_FOUND', `API key no encontrada: ${id}`, 404);
  }

  const listed = await getApiKeyRepository().listByAccount(req.accountId);
  const record = listed.find((k) => k.id === id);
  res.status(200).json({
    revoked: true,
    key: record ?? { id, accountId: req.accountId }
  });
}
